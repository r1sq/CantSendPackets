package dhcp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

var testMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}

const testXID = 0xdeadbeef

// offerBytes builds a server's reply the way a real server would.
func offerBytes(xid uint32, mac net.HardwareAddr, server, yiaddr string, extra ...byte) []byte {
	p := make([]byte, headerLen)
	p[0] = opReply
	p[1], p[2] = 1, 6
	binary.BigEndian.PutUint32(p[4:], xid)
	y := netip.MustParseAddr(yiaddr).As4()
	copy(p[16:20], y[:])
	copy(p[28:44], mac)
	p = binary.BigEndian.AppendUint32(p, magicCookie)
	p = append(p, optMsgType, 1, msgOffer)
	if server != "" {
		s := netip.MustParseAddr(server).As4()
		p = append(p, optServerID, 4, s[0], s[1], s[2], s[3])
	}
	p = append(p, extra...)
	return append(p, optEnd)
}

func TestBuildDiscoverIsWellFormed(t *testing.T) {
	p := BuildDiscover(testXID, testMAC)
	if len(p) < minBootpLen {
		t.Fatalf("len = %d, BOOTP relays expect at least %d", len(p), minBootpLen)
	}
	if binary.BigEndian.Uint16(p[10:])&flagBroadcast == 0 {
		t.Error("broadcast flag not set: unicast offers would miss our socket")
	}
	if !strings.EqualFold(net.HardwareAddr(p[28:34]).String(), testMAC.String()) {
		t.Errorf("chaddr = %x", p[28:34])
	}
	if binary.BigEndian.Uint32(p[headerLen:]) != magicCookie {
		t.Error("missing magic cookie")
	}
	if p[headerLen+4] != optMsgType || p[headerLen+6] != msgDiscover {
		t.Error("first option should mark this a DISCOVER")
	}
}

func TestParseOfferReadsOptions(t *testing.T) {
	extra := []byte{
		optSubnetMask, 4, 255, 255, 255, 0,
		optRouter, 8, 10, 0, 0, 1, 10, 0, 0, 2,
		optDNS, 4, 9, 9, 9, 9,
		optLeaseTime, 4, 0, 0, 0x0e, 0x10,
		optDomainName, 8, 'l', 'a', 'n', '<', 0x07, 'x', '>', 0xff,
	}
	o, err := ParseOffer(offerBytes(testXID, testMAC, "10.0.0.1", "10.0.0.50", extra...), testXID, testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if o.ServerID.String() != "10.0.0.1" || o.YourIP.String() != "10.0.0.50" || o.Mask.String() != "255.255.255.0" {
		t.Errorf("parsed %+v", o)
	}
	if len(o.Routers) != 2 || o.Routers[1].String() != "10.0.0.2" || o.DNS[0].String() != "9.9.9.9" {
		t.Errorf("lists %+v %+v", o.Routers, o.DNS)
	}
	if o.Lease != 3600 {
		t.Errorf("lease = %d", o.Lease)
	}
	if o.Domain != "lan<x>" {
		t.Errorf("domain not stripped of control bytes: %q", o.Domain)
	}
}

func TestParseOfferRejects(t *testing.T) {
	good := offerBytes(testXID, testMAC, "10.0.0.1", "10.0.0.50")
	ack := append([]byte(nil), good...)
	ack[headerLen+6] = 5 // DHCPACK
	req := append([]byte(nil), good...)
	req[0] = opRequest
	cases := map[string][]byte{
		"wrong xid":   offerBytes(1, testMAC, "10.0.0.1", "10.0.0.50"),
		"wrong mac":   offerBytes(testXID, net.HardwareAddr{1, 2, 3, 4, 5, 6}, "10.0.0.1", "10.0.0.50"),
		"ack":         ack,
		"client's op": req,
		"short":       good[:100],
		"empty":       {},
	}
	for name, p := range cases {
		if _, err := ParseOffer(p, testXID, testMAC); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseOfferSurvivesTruncatedOptions(t *testing.T) {
	good := offerBytes(testXID, testMAC, "10.0.0.1", "10.0.0.50", optDNS, 200, 1, 2)
	if _, err := ParseOffer(good, testXID, testMAC); err != nil {
		t.Fatalf("offer with a truncated trailing option should still parse: %v", err)
	}
	for n := range good {
		ParseOffer(good[:n], testXID, testMAC) // must not panic
	}
}

func FuzzParseOffer(f *testing.F) {
	f.Add(offerBytes(testXID, testMAC, "10.0.0.1", "10.0.0.50"))
	f.Fuzz(func(t *testing.T, b []byte) { ParseOffer(b, testXID, nil) })
}

func FuzzDecodeServerFrame(f *testing.F) {
	f.Add(serverFrame("02:00:00:00:00:01", "10.0.0.1", []byte("x")))
	f.Fuzz(func(t *testing.T, b []byte) { DecodeServerFrame(b) })
}

// serverFrame wraps a payload the way a server's reply looks on the wire.
func serverFrame(srcMAC, srcIP string, payload []byte) []byte {
	mac, _ := net.ParseMAC(srcMAC)
	f := make([]byte, 14+20+8+len(payload))
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:], etherIPv4)
	ip := f[14:34]
	ip[0] = 0x45
	ip[9] = protoUDP
	s := netip.MustParseAddr(srcIP).As4()
	copy(ip[12:16], s[:])
	udp := f[34:]
	binary.BigEndian.PutUint16(udp[0:], ServerPort)
	binary.BigEndian.PutUint16(udp[2:], ClientPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return f
}

func TestDiscoverFrameChecksums(t *testing.T) {
	f := EncodeDiscoverFrame(testMAC, BuildDiscover(testXID, testMAC))
	ip := f[14:34]
	if got := checksum(ip); got != 0 {
		t.Errorf("IP header checksum does not verify: %#x", got)
	}
	udp := f[34:]
	if got := udpChecksumVerify(ip[12:16], ip[16:20], udp); got != 0 {
		t.Errorf("UDP checksum does not verify: %#x", got)
	}
	if !strings.EqualFold(net.HardwareAddr(f[6:12]).String(), testMAC.String()) {
		t.Error("source MAC wrong")
	}
	if binary.BigEndian.Uint16(udp[0:]) != ClientPort || binary.BigEndian.Uint16(udp[2:]) != ServerPort {
		t.Error("ports wrong")
	}
}

func udpChecksumVerify(src, dst, udp []byte) uint16 {
	pseudo := append(append(append([]byte{}, src...), dst...), 0, protoUDP, byte(len(udp)>>8), byte(len(udp)))
	return checksum(append(pseudo, udp...))
}

func TestDecodeServerFrame(t *testing.T) {
	r, ok := DecodeServerFrame(serverFrame("02:00:00:00:00:01", "10.0.0.1", []byte("hello")))
	if !ok || r.SrcIP.String() != "10.0.0.1" || r.SrcMAC != "02:00:00:00:00:01" || string(r.Payload) != "hello" {
		t.Fatalf("%+v ok=%v", r, ok)
	}
	plain := serverFrame("02:00:00:00:00:01", "10.0.0.1", []byte("vlan"))
	tagged := append(append(append([]byte{}, plain[:12]...), 0x81, 0x00, 0x00, 0x05), plain[12:]...)
	if r, ok := DecodeServerFrame(tagged); !ok || string(r.Payload) != "vlan" {
		t.Errorf("VLAN tagged frame: %+v ok=%v", r, ok)
	}
	if _, ok := DecodeServerFrame(EncodeDiscoverFrame(testMAC, []byte("x"))); ok {
		t.Error("our own client->server frame must not count as a server reply")
	}
}

// fakeNet answers each Send with a scripted set of replies, as a segment would.
type fakeNet struct {
	replies []ServerReply
	inbox   []ServerReply
	sends   int
	sendErr error
}

func (f *fakeNet) Send([]byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sends++
	f.inbox = append(f.inbox, f.replies...)
	return nil
}
func (f *fakeNet) Recv(time.Duration) (ServerReply, error) {
	if len(f.inbox) == 0 {
		return ServerReply{}, ErrTimeout
	}
	r := f.inbox[0]
	f.inbox = f.inbox[1:]
	return r, nil
}
func (f *fakeNet) Close() error { return nil }

var fastProbe = Options{Sends: 3, Interval: 5 * time.Millisecond, Wait: 30 * time.Millisecond}

func TestProbeCollapsesRetriesAndFindsRogue(t *testing.T) {
	net := &fakeNet{replies: []ServerReply{
		{SrcMAC: "02:00:00:00:00:01", SrcIP: netip.MustParseAddr("10.0.0.1"), Payload: offerBytes(testXID, testMAC, "10.0.0.1", "10.0.0.50")},
		{SrcMAC: "02:00:00:00:00:66", SrcIP: netip.MustParseAddr("10.0.0.66"), Payload: offerBytes(testXID, testMAC, "10.0.0.66", "192.168.8.2")},
		{SrcMAC: "02:00:00:00:00:77", SrcIP: netip.MustParseAddr("10.0.0.77"), Payload: []byte("garbage")},
		{SrcMAC: "02:00:00:00:00:88", SrcIP: netip.MustParseAddr("10.0.0.88"), Payload: offerBytes(1, testMAC, "10.0.0.88", "10.0.0.9")},
	}}
	servers, sent, err := Probe(context.Background(), net, testMAC, testXID, fastProbe)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 3 {
		t.Errorf("sent = %d", sent)
	}
	if len(servers) != 2 {
		t.Fatalf("want the 2 real servers, got %+v", servers)
	}
	if servers[0].Offers != 3 {
		t.Errorf("retries should collapse into one server, offers = %d", servers[0].Offers)
	}
	rep := Evaluate(servers, sent, MethodCapture, netip.MustParseAddr("10.0.0.1"), nil)
	if rep.Verdict != verdict.Problem {
		t.Errorf("verdict = %s", rep.Verdict)
	}
	if !rep.Servers[0].IsLeaseServer || rep.Servers[1].IsLeaseServer {
		t.Errorf("lease server marking wrong: %+v", rep.Servers)
	}
}

func TestProbeBoundsForgedServers(t *testing.T) {
	f := &fakeNet{}
	for i := 0; i < 200; i++ {
		a := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		f.replies = append(f.replies, ServerReply{SrcIP: a, Payload: offerBytes(testXID, testMAC, a.String(), "10.0.0.5")})
	}
	servers, _, _ := Probe(context.Background(), f, testMAC, testXID, Options{Sends: 1, Wait: 20 * time.Millisecond})
	if len(servers) > 32 {
		t.Errorf("forged offers grew report to %d", len(servers))
	}
}

func TestProbeReportsSendFailure(t *testing.T) {
	_, _, err := Probe(context.Background(), &fakeNet{sendErr: errors.New("no route")}, testMAC, testXID, fastProbe)
	if err == nil {
		t.Fatal("a failed first send must be an error, not an empty result")
	}
}

func TestEvaluate(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	srvA := Server{ServerID: a, SourceIP: a, SourceMAC: "m1"}
	srvB := Server{ServerID: b, SourceIP: b, SourceMAC: "m2"}
	srvAOther := Server{ServerID: a, SourceIP: a, SourceMAC: "m3"}
	noLease := netip.Addr{}
	cases := []struct {
		name    string
		servers []Server
		method  Method
		lease   netip.Addr
		err     error
		want    verdict.Level
	}{
		{"one server, is lease server", []Server{srvA}, MethodCapture, a, nil, verdict.OK},
		{"one server, static adapter", []Server{srvA}, MethodSocket, noLease, nil, verdict.OK},
		{"two servers", []Server{srvA, srvB}, MethodSocket, a, nil, verdict.Problem},
		{"one server but not ours", []Server{srvB}, MethodCapture, a, nil, verdict.Warn},
		{"same id two macs", []Server{srvA, srvAOther}, MethodCapture, a, nil, verdict.Warn},
		{"silence over socket proves nothing", nil, MethodSocket, a, nil, verdict.Unknown},
		{"silence on the wire, had lease", nil, MethodCapture, a, nil, verdict.Warn},
		{"silence on the wire, no lease", nil, MethodCapture, noLease, nil, verdict.Warn},
		{"probe failed", nil, MethodSocket, a, errors.New("boom"), verdict.Unknown},
	}
	for _, c := range cases {
		if got := Evaluate(c.servers, 3, c.method, c.lease, c.err); got.Verdict != c.want {
			t.Errorf("%s: verdict = %s (%s), want %s", c.name, got.Verdict, got.Headline, c.want)
		}
	}
}

// The socket transport is exercised for real over loopback against a tiny
// server, covering everything except what only Windows can show.
func TestSocketTransportEndToEnd(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	probe, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	clientPort := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			xid := binary.BigEndian.Uint32(buf[4:n])
			srv.WriteToUDP(offerBytes(xid, testMAC, "127.0.0.1", "10.9.9.9"), from)
		}
	}()

	tr, err := NewSocketTransport(SocketConfig{BindIP: lo, ClientPort: clientPort, Target: srv.LocalAddr().(*net.UDPAddr)})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	servers, sent, err := Probe(context.Background(), tr, testMAC, testXID, Options{Sends: 2, Interval: 20 * time.Millisecond, Wait: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if sent != 2 || len(servers) != 1 || servers[0].OfferedIP.String() != "10.9.9.9" || servers[0].SourceIP != lo {
		t.Fatalf("sent=%d servers=%+v", sent, servers)
	}
}
