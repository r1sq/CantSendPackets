package peer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/r1sq/CantSendPackets/internal/sockopt"
)

// Announce is how often a hello goes out.
const Announce = 5 * time.Second

// Local is one address of this PC to announce from.
type Local struct {
	IP netip.Addr
	// Targets are where hellos go from this address: normally its subnet's directed
	// broadcast and the limited broadcast.
	Targets []netip.Addr
}

// Config configures a Service.
type Config struct {
	Name      string
	SpeedPort int
	// Port is the UDP port. Zero means DefaultPort.
	Port int
	// Locals lists current addresses. It's called on every announcement, so
	// adapters coming and going are picked up.
	Locals func() []Local
	// Allow filters senders by address. nil allows all.
	Allow func(netip.Addr) bool
	// OnChange is called with the new list when it changes.
	OnChange func([]Peer)
	// NoWildcard skips the catch-all listener, for tests running several instances
	// on one machine.
	NoWildcard bool
	Interval   time.Duration
}

// Service announces this instance and tracks others.
type Service struct {
	cfg Config
	id  string

	mu    sync.Mutex
	table *Table
	conns map[netip.Addr]net.PacketConn
	any   net.PacketConn
	wg    sync.WaitGroup
}

// NewID makes an instance ID, unique per run.
func NewID() string {
	b := make([]byte, idLen/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Start begins announcing until ctx ends. Wait blocks until it has fully stopped.
func Start(ctx context.Context, cfg Config) *Service {
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Interval == 0 {
		cfg.Interval = Announce
	}
	id := NewID()
	s := &Service{cfg: cfg, id: id, table: NewTable(id), conns: map[netip.Addr]net.PacketConn{}}
	s.wg.Add(1)
	go s.run(ctx)
	return s
}

// ID returns this instance's ID.
func (s *Service) ID() string { return s.id }

// Wait blocks until the service has stopped.
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) listen(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var optErr error
		if err := c.Control(func(fd uintptr) { optErr = sockopt.ReuseAndBroadcast(fd) }); err != nil {
			return err
		}
		return optErr
	}}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

func (s *Service) run(ctx context.Context) {
	defer s.wg.Done()
	if !s.cfg.NoWildcard {
		if c, err := s.listen("0.0.0.0:" + strconv.Itoa(s.cfg.Port)); err == nil {
			s.any = c
			s.wg.Add(1)
			go s.read(c)
		}
	}
	tick := time.NewTicker(s.cfg.Interval)
	defer tick.Stop()
	defer s.closeAll()
	s.announce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.announce()
			s.mu.Lock()
			changed := s.table.Expire(time.Now())
			list := s.table.List()
			s.mu.Unlock()
			if changed {
				s.notify(list)
			}
		}
	}
}

func (s *Service) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = map[netip.Addr]net.PacketConn{}
	if s.any != nil {
		s.any.Close()
	}
}

// announce sends a hello from every current address, opening sockets for new ones
// and closing those that have gone. Sockets are bound per address because that's
// what chooses the outgoing adapter on a multi-homed PC.
func (s *Service) announce() {
	if s.cfg.Locals == nil {
		return
	}
	locals := s.cfg.Locals()
	hello := Encode(s.hello(false))

	s.mu.Lock()
	seen := map[netip.Addr]bool{}
	for _, l := range locals {
		seen[l.IP] = true
		if s.conns[l.IP] != nil {
			continue
		}
		c, err := s.listen(netip.AddrPortFrom(l.IP, uint16(s.cfg.Port)).String())
		if err != nil {
			continue
		}
		s.conns[l.IP] = c
		s.wg.Add(1)
		go s.read(c)
	}
	for ip, c := range s.conns {
		if !seen[ip] {
			c.Close()
			delete(s.conns, ip)
		}
	}
	own := make([]netip.Addr, 0, len(locals))
	for _, l := range locals {
		own = append(own, l.IP)
	}
	var changedList []Peer
	if s.table.SetOwn(own) {
		changedList = s.table.List()
	}
	conns := make(map[netip.Addr]net.PacketConn, len(s.conns))
	for ip, c := range s.conns {
		conns[ip] = c
	}
	s.mu.Unlock()
	if changedList != nil {
		s.notify(changedList)
	}

	for _, l := range locals {
		c := conns[l.IP]
		if c == nil {
			continue
		}
		for _, target := range l.Targets {
			c.WriteTo(hello, net.UDPAddrFromAddrPort(netip.AddrPortFrom(target, uint16(s.cfg.Port))))
		}
	}
}

func (s *Service) hello(reply bool) Hello {
	return Hello{ID: s.id, Name: s.cfg.Name, Port: s.cfg.SpeedPort, Proto: ProtocolVersion, Reply: reply}
}

func (s *Service) read(c net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, maxPacket+1)
	for {
		n, from, err := c.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Windows reports WSAECONNRESET here after a packet we sent reached a host
			// with nothing listening, such as a mistyped address. The socket is fine,
			// and giving up would end discovery. The pause stops any error that
			// does repeat from spinning.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		u, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(u.IP.To4())
		if !ip.IsValid() || (s.cfg.Allow != nil && !s.cfg.Allow(ip)) {
			continue
		}
		h, ok := Decode(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		changed, reply := s.table.Observe(h, ip, time.Now())
		list := s.table.List()
		s.mu.Unlock()
		if reply {
			c.WriteTo(Encode(s.hello(true)), u)
		}
		if changed {
			s.notify(list)
		}
	}
}

func (s *Service) notify(list []Peer) {
	if s.cfg.OnChange != nil {
		s.cfg.OnChange(list)
	}
}

// Peers returns the current list.
func (s *Service) Peers() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.table.List()
}

// Find returns a peer by ID.
func (s *Service) Find(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.table.Find(id)
}

// Probe sends a hello straight to an address, for networks where broadcasts don't
// reach, such as another VLAN. If an instance is there, its reply adds it to the
// list as usual.
func (s *Service) Probe(ip netip.Addr) bool {
	s.mu.Lock()
	c := s.any
	if c == nil {
		for _, open := range s.conns {
			c = open
			break
		}
	}
	s.mu.Unlock()
	if c == nil {
		return false
	}
	_, err := c.WriteTo(Encode(s.hello(false)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(s.cfg.Port))))
	return err == nil
}
