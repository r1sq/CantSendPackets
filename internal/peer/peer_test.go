package peer

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	idA = strings.Repeat("a", idLen)
	idB = strings.Repeat("b", idLen)
	ipA = netip.MustParseAddr("192.168.1.10")
	t0  = time.Unix(1000, 0)
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Hello{ID: idA, Name: "PC-1", Port: 47116, Proto: 1, Reply: true}
	got, ok := Decode(Encode(in))
	if !ok || got != in {
		t.Errorf("%+v %v", got, ok)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := Hello{ID: idA, Name: "x", Port: 1, Proto: 1}
	cases := map[string][]byte{
		"empty":     {},
		"no magic":  []byte(`{"id":"x"}`),
		"not json":  append([]byte("CSPK1"), []byte("{oops")...),
		"short id":  Encode(Hello{ID: "abc", Port: 1}),
		"odd id":    Encode(Hello{ID: strings.Repeat("Z", idLen), Port: 1}),
		"port 0":    Encode(Hello{ID: idA, Port: 0}),
		"high port": Encode(Hello{ID: idA, Port: 70000}),
		"huge":      append(Encode(good), make([]byte, maxPacket)...),
	}
	for name, b := range cases {
		if _, ok := Decode(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDecodeSanitisesTheName(t *testing.T) {
	h, ok := Decode(Encode(Hello{ID: idA, Port: 1, Name: "PC\x07<b>" + strings.Repeat("y", 200) + "ü"}))
	if !ok {
		t.Fatal("rejected")
	}
	if strings.Contains(h.Name, "\x07") || len(h.Name) != maxName {
		t.Errorf("%q", h.Name)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(Encode(Hello{ID: idA, Port: 1}))
	f.Fuzz(func(t *testing.T, b []byte) { Decode(b) })
}

func TestTableIgnoresItself(t *testing.T) {
	tb := NewTable(idA)
	if changed, reply := tb.Observe(Hello{ID: idA, Port: 1}, ipA, t0); changed || reply || len(tb.List()) != 0 {
		t.Error("own hello must not appear")
	}
}

func TestTableIgnoresOtherInstancesOnThisPC(t *testing.T) {
	tb := NewTable(idA)
	now := time.Now()
	if changed, _ := tb.Observe(Hello{ID: idB, Name: "PC-1", Proto: 1}, ipA, now); !changed {
		t.Fatal("a peer heard before its address was known as ours should be listed")
	}
	if !tb.SetOwn([]netip.Addr{ipA}) || len(tb.List()) != 0 {
		t.Fatal("learning the address is ours should drop the instance on it")
	}
	if changed, reply := tb.Observe(Hello{ID: idB, Name: "PC-1", Proto: 1}, ipA, now); changed || reply {
		t.Error("a second window on this PC isn't a peer, and needs no reply")
	}
	if changed, _ := tb.Observe(Hello{ID: idB, Name: "PC-2", Proto: 1}, netip.MustParseAddr("192.168.1.11"), now); !changed {
		t.Error("other PCs must still be listed")
	}
}

func TestTableTracksChanges(t *testing.T) {
	tb := NewTable(idA)
	h := Hello{ID: idB, Name: "B", Port: 1, Proto: ProtocolVersion}
	if changed, _ := tb.Observe(h, ipA, t0); !changed {
		t.Error("new peer")
	}
	if changed, _ := tb.Observe(h, ipA, t0.Add(time.Second)); changed {
		t.Error("nothing changed")
	}
	h.Port = 2
	if changed, _ := tb.Observe(h, ipA, t0.Add(2*time.Second)); !changed {
		t.Error("port changed")
	}
	if p, _ := tb.Find(idB); !p.Compatible || p.Port != 2 {
		t.Errorf("%+v", p)
	}
}

func TestPeerAddressComesFromThePacketNotTheClaim(t *testing.T) {
	tb := NewTable(idA)
	tb.Observe(Hello{ID: idB, Port: 1}, ipA, t0)
	if p, _ := tb.Find(idB); p.IP != ipA {
		t.Errorf("%v", p.IP)
	}
}

func TestIncompatibleVersionIsMarked(t *testing.T) {
	tb := NewTable(idA)
	tb.Observe(Hello{ID: idB, Port: 1, Proto: ProtocolVersion + 1}, ipA, t0)
	if p, _ := tb.Find(idB); p.Compatible {
		t.Error("should be incompatible")
	}
}

func TestReplies(t *testing.T) {
	tb := NewTable(idA)
	h := Hello{ID: idB, Port: 1}
	if _, reply := tb.Observe(h, ipA, t0); !reply {
		t.Error("should answer a new peer")
	}
	if _, reply := tb.Observe(h, ipA, t0.Add(time.Second)); reply {
		t.Error("a flood of hellos must not produce a flood of replies")
	}
	if _, reply := tb.Observe(h, ipA, t0.Add(replyInterval+time.Second)); !reply {
		t.Error("should answer again later")
	}
	h.Reply = true
	if _, reply := tb.Observe(h, ipA, t0.Add(replyInterval*10)); reply {
		t.Error("answering a reply would loop forever")
	}
}

func TestExpiry(t *testing.T) {
	tb := NewTable(idA)
	tb.Observe(Hello{ID: idB, Port: 1}, ipA, t0)
	if tb.Expire(t0.Add(Expiry - time.Second)) {
		t.Error("too early")
	}
	if !tb.Expire(t0.Add(Expiry+time.Second)) || len(tb.List()) != 0 {
		t.Error("should be gone")
	}
}

func fakeID(i int) string {
	const hex = "0123456789abcdef"
	b := []byte(strings.Repeat("0", idLen))
	b[0], b[1], b[2] = hex[i>>8&15], hex[i>>4&15], hex[i&15]
	return string(b)
}

func TestTableSizeIsBounded(t *testing.T) {
	tb := NewTable(idA)
	for i := 0; i < maxPeers*3; i++ {
		tb.Observe(Hello{ID: fakeID(i), Port: 1}, ipA, t0)
	}
	if n := len(tb.List()); n != maxPeers {
		t.Errorf("forged hellos grew the list to %d", n)
	}
	// Once they've expired, a real peer can get in again.
	if changed, _ := tb.Observe(Hello{ID: idB, Port: 1}, ipA, t0.Add(Expiry*2)); !changed {
		t.Error("list stayed full of expired entries")
	}
}

func TestAllowedSource(t *testing.T) {
	onLink := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	cases := map[string]bool{
		"192.168.1.5":  true,
		"10.1.2.3":     true,
		"172.16.0.9":   true,
		"169.254.1.1":  true,
		"100.64.1.1":   true,
		"127.0.0.1":    true,
		"8.8.8.8":      false,
		"203.0.113.9":  true, // public, but this PC's own subnet
		"198.51.100.1": false,
		"2001:db8::1":  false,
	}
	for ip, want := range cases {
		if got := AllowedSource(netip.MustParseAddr(ip), onLink); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
}

// startPair runs two real services over real UDP sockets, on two loopback
// addresses sharing a port, as two PCs on a subnet would.
func startPair(t *testing.T, ctx context.Context, aHears, bHears bool) (*Service, *Service, *recorder, *recorder) {
	t.Helper()
	const port = 47399
	a := netip.MustParseAddr("127.0.0.2")
	b := netip.MustParseAddr("127.0.0.3")
	mk := func(name string, self, other netip.Addr, speed int, rec *recorder, send bool) *Service {
		var targets []netip.Addr
		if send {
			targets = []netip.Addr{other}
		}
		return Start(ctx, Config{
			Name: name, SpeedPort: speed, Port: port, NoWildcard: true, Interval: 40 * time.Millisecond,
			Locals:   func() []Local { return []Local{{IP: self, Targets: targets}} },
			OnChange: rec.set,
		})
	}
	ra, rb := &recorder{}, &recorder{}
	sa := mk("A", a, b, 1111, ra, aHears)
	sb := mk("B", b, a, 2222, rb, bHears)
	return sa, sb, ra, rb
}

type recorder struct {
	mu   sync.Mutex
	last []Peer
}

func (r *recorder) set(p []Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = p
}

func (r *recorder) get() []Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestTwoInstancesFindEachOther(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sa, sb, ra, _ := startPair(t, ctx, true, true)
	defer func() {
		cancel()
		sa.Wait()
		sb.Wait()
	}()
	eventually(t, "A sees B", func() bool { return len(sa.Peers()) == 1 })
	eventually(t, "B sees A", func() bool { return len(sb.Peers()) == 1 })
	got := sa.Peers()[0]
	if got.Name != "B" || got.Port != 2222 || got.IP.String() != "127.0.0.3" || !got.Compatible {
		t.Errorf("%+v", got)
	}
	if got.ID != sb.ID() {
		t.Errorf("ID: %s", got.ID)
	}
	eventually(t, "change callback", func() bool { return len(ra.get()) == 1 })
}

// B's firewall drops nothing, but B never announces. A must still end up seeing it,
// and B must see A, purely through A's hello and B's reply.
func TestOneWayBroadcastStillConnectsBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sa, sb, _, _ := startPair(t, ctx, true, false)
	defer func() {
		cancel()
		sa.Wait()
		sb.Wait()
	}()
	eventually(t, "A sees B from its reply", func() bool { return len(sa.Peers()) == 1 })
	eventually(t, "B sees A from its hello", func() bool { return len(sb.Peers()) == 1 })
}

func TestManualProbeFindsAPeerWithoutBroadcasts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sa, sb, _, _ := startPair(t, ctx, false, false)
	defer func() {
		cancel()
		sa.Wait()
		sb.Wait()
	}()
	time.Sleep(100 * time.Millisecond)
	if len(sa.Peers()) != 0 {
		t.Fatal("nothing should have been found yet")
	}
	if !sa.Probe(netip.MustParseAddr("127.0.0.3")) {
		t.Fatal("probe failed to send")
	}
	eventually(t, "A sees B after probing", func() bool { return len(sa.Peers()) == 1 })
}

func TestStoppingClosesSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sa, sb, _, _ := startPair(t, ctx, true, true)
	cancel()
	done := make(chan struct{})
	go func() {
		sa.Wait()
		sb.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("services didn't stop")
	}
}
