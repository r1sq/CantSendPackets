// Package rawcap captures and sends Ethernet frames on Linux through AF_PACKET
// sockets: what Npcap does on Windows, without a driver. It needs root or the
// CAP_NET_RAW capability.
package rawcap

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	snapLen     = 65536
	readTimeout = 100 * time.Millisecond
)

// ErrNoPermission means raw sockets need root or CAP_NET_RAW.
var ErrNoPermission = errors.New("raw sockets need root or CAP_NET_RAW")

// Options configure a capture.
type Options struct {
	// Filter runs in the kernel; frames it rejects are never copied out.
	Filter []bpf.Instruction
	// InboundOnly skips frames this machine sent, which AF_PACKET otherwise
	// reports too (as Npcap does).
	InboundOnly bool
}

// Handle is an open capture on one interface.
type Handle struct {
	fd      int
	ifindex int
	inbound bool
	buf     []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Available reports whether this process may open raw sockets.
func Available() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// Open starts a capture on the named interface. Promiscuous mode isn't needed:
// everything looked at here is addressed to broadcast, multicast or this host.
func Open(name string, opts Options) (*Handle, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return nil, ErrNoPermission
	}
	if err != nil {
		return nil, fmt.Errorf("opening raw socket: %w", err)
	}
	h := &Handle{fd: fd, ifindex: ifc.Index, inbound: opts.InboundOnly, buf: make([]byte, snapLen)}
	// The filter goes on before bind, so nothing unfiltered is ever queued.
	if len(opts.Filter) > 0 {
		raw, err := bpf.Assemble(opts.Filter)
		if err != nil {
			h.Close()
			return nil, err
		}
		prog := make([]unix.SockFilter, len(raw))
		for i, ins := range raw {
			prog[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
			h.Close()
			return nil, fmt.Errorf("attaching filter: %w", err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		h.Close()
		return nil, fmt.Errorf("binding to %s: %w", name, err)
	}
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// Send transmits one complete Ethernet frame.
func (h *Handle) Send(frame []byte) error {
	if len(frame) < 14 {
		return errors.New("frame too short")
	}
	var addr [8]byte
	copy(addr[:], frame[:6])
	to := &unix.SockaddrLinklayer{Ifindex: h.ifindex, Halen: 6, Addr: addr}
	if err := unix.Sendto(h.fd, frame, 0, to); err != nil {
		return fmt.Errorf("sending frame: %w", err)
	}
	return nil
}

// Next returns one captured frame, copied, or a nil frame if the read timed out.
func (h *Handle) Next() ([]byte, time.Time, error) {
	for {
		n, from, err := unix.Recvfrom(h.fd, h.buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return nil, time.Time{}, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && h.inbound && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return append([]byte(nil), h.buf[:n]...), time.Now(), nil
	}
}

// Close releases the socket.
func (h *Handle) Close() {
	if h.fd >= 0 {
		unix.Close(h.fd)
		h.fd = -1
	}
}

// Broadcast and multicast frames only: what the loop check looks at.
var NonUnicast = []bpf.Instruction{
	bpf.LoadAbsolute{Off: 0, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1, SkipFalse: 1},
	bpf.RetConstant{Val: snapLen},
	bpf.RetConstant{Val: 0},
}

// DHCPServerReplies matches IPv4 UDP from port 67 to port 68, unfragmented.
var DHCPServerReplies = []bpf.Instruction{
	bpf.LoadAbsolute{Off: 12, Size: 2},                         // EtherType
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 9}, // IPv4
	bpf.LoadAbsolute{Off: 23, Size: 1},                         // protocol
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 7},     // UDP
	bpf.LoadAbsolute{Off: 20, Size: 2},                         // flags and fragment offset
	bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5},
	bpf.LoadMemShift{Off: 14},          // X = IP header length
	bpf.LoadIndirect{Off: 14, Size: 2}, // source port
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipFalse: 2},
	bpf.LoadIndirect{Off: 16, Size: 2}, // destination port
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 68, SkipTrue: 1},
	bpf.RetConstant{Val: 0},
	bpf.RetConstant{Val: snapLen},
}
