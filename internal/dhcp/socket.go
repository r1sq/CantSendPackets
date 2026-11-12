package dhcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/r1sq/CantSendPackets/internal/sockopt"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// SocketConfig configures a plain UDP transport. Ports and target are
// overridable so tests can run without privileged ports.
type SocketConfig struct {
	BindIP     netip.Addr
	ClientPort int
	Target     *net.UDPAddr
}

// SocketTransport is the no-driver fallback. It needs SO_REUSEADDR to coexist
// with the Windows DHCP Client service, and it can't see the sender's MAC.
type SocketTransport struct {
	send    net.PacketConn
	conns   []net.PacketConn
	target  *net.UDPAddr
	replies chan ServerReply
	done    chan struct{}
}

// NewSocketTransport binds to the adapter's own address, which is what selects
// the outgoing interface on a multi-homed machine, plus a best-effort wildcard
// listener in case the stack delivers broadcasts only there.
func NewSocketTransport(cfg SocketConfig) (*SocketTransport, error) {
	if cfg.ClientPort == 0 {
		cfg.ClientPort = ClientPort
	}
	if cfg.Target == nil {
		cfg.Target = &net.UDPAddr{IP: net.IPv4bcast, Port: ServerPort}
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var optErr error
		if err := c.Control(func(fd uintptr) { optErr = sockopt.ReuseAndBroadcast(fd) }); err != nil {
			return err
		}
		return optErr
	}}

	primary, err := lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(cfg.BindIP, uint16(cfg.ClientPort)).String())
	if err != nil {
		return nil, verdict.Err("err.dhcp.bind", "port", cfg.ClientPort, "ip", cfg.BindIP, "detail", err.Error())
	}
	t := &SocketTransport{
		send:    primary,
		conns:   []net.PacketConn{primary},
		target:  cfg.Target,
		replies: make(chan ServerReply, 64),
		done:    make(chan struct{}),
	}
	wildcard := fmt.Sprintf("0.0.0.0:%d", cfg.ClientPort)
	if extra, err := lc.ListenPacket(context.Background(), "udp4", wildcard); err == nil {
		t.conns = append(t.conns, extra)
	}
	for _, c := range t.conns {
		go t.readLoop(c)
	}
	return t, nil
}

func (t *SocketTransport) readLoop(c net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Windows reports WSAECONNRESET after a send that drew an ICMP error. The
			// socket still works, and giving up would lose every later offer.
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var src netip.Addr
		if u, ok := from.(*net.UDPAddr); ok {
			src, _ = netip.AddrFromSlice(u.IP.To4())
		}
		r := ServerReply{SrcIP: src, Payload: append([]byte(nil), buf[:n]...)}
		select {
		case t.replies <- r:
		case <-t.done:
			return
		default: // reader is behind: dropping beats blocking on a flood
		}
	}
}

// Send implements Transport.
func (t *SocketTransport) Send(payload []byte) error {
	_, err := t.send.WriteTo(payload, t.target)
	return err
}

// Recv implements Transport.
func (t *SocketTransport) Recv(timeout time.Duration) (ServerReply, error) {
	select {
	case r := <-t.replies:
		return r, nil
	case <-time.After(timeout):
		return ServerReply{}, ErrTimeout
	}
}

// Close implements Transport.
func (t *SocketTransport) Close() error {
	close(t.done)
	var errs []error
	for _, c := range t.conns {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
