package probe

import (
	"net/netip"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func TestPingLoopback(t *testing.T) {
	rtt, err := Ping(netip.Addr{}, loopback, time.Second)
	if err != nil {
		t.Fatalf("the reply struct or the call is wrong: %v", err)
	}
	if rtt < 0 || rtt > time.Second {
		t.Errorf("implausible RTT %v", rtt)
	}
}

func TestPingWithSourceAddress(t *testing.T) {
	if _, err := Ping(loopback, loopback, time.Second); err != nil {
		t.Errorf("%v", err)
	}
}

func TestPingUnreachableIsTranslated(t *testing.T) {
	// TEST-NET-1: reserved, never answers.
	_, err := Ping(netip.Addr{}, netip.MustParseAddr("192.0.2.1"), 500*time.Millisecond)
	if err == nil {
		t.Fatal("got a reply from a reserved address")
	}
	if m := verdict.AsMsg(err); m.Key == "err.raw" {
		t.Errorf("failure wasn't mapped to a message: %v", err)
	}
}

func TestPingIPv6IsDeclined(t *testing.T) {
	if _, err := Ping(netip.Addr{}, netip.MustParseAddr("::1"), time.Second); err == nil {
		t.Error("expected an error")
	}
}

func TestCountersAndARPOnRealAdapters(t *testing.T) {
	list, err := adapter.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Skip("no adapters")
	}
	for _, a := range list {
		nu1, oct1, err := Counters(a.Index)
		if err != nil {
			t.Errorf("%s: %v", a.Name, err)
			continue
		}
		t.Logf("%s: non-unicast packets %d, broadcast bytes %d", a.Name, nu1, oct1)
		// Counters only ever grow, so garbage from a misread struct shows up here.
		time.Sleep(200 * time.Millisecond)
		nu2, oct2, err := Counters(a.Index)
		if err != nil || nu2 < nu1 || oct2 < oct1 {
			t.Errorf("%s: counters went backwards: %d->%d %d->%d, err %v", a.Name, nu1, nu2, oct1, oct2, err)
		}
		if gw := a.GatewayV4(); gw.IsValid() {
			mac, rtt, err := ARP(a.PrimaryIPv4(), gw)
			t.Logf("%s: gateway %s has MAC %v after %v, err %v", a.Name, gw, mac, rtt, err)
			if err == nil && len(mac) != 6 {
				t.Errorf("%s: implausible MAC %v", a.Name, mac)
			}
			prtt, perr := Ping(a.PrimaryIPv4(), gw, time.Second)
			t.Logf("%s: ping gateway from this adapter: %v, err %v", a.Name, prtt, perr)
		}
	}
}
