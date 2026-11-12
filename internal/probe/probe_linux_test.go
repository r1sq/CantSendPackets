package probe

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseARPTableTakesCompleteEntriesOnly(t *testing.T) {
	const table = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
`
	read := func(ip string) bool {
		_, ok := parseARPTable(bufio.NewScanner(strings.NewReader(table)), netip.MustParseAddr(ip))
		return ok
	}
	if !read("192.168.1.1") {
		t.Error("complete entry not found")
	}
	if read("192.168.1.9") {
		t.Error("an incomplete entry isn't a resolved MAC")
	}
}

func TestParseIpExt(t *testing.T) {
	const text = "TcpExt: SyncookiesSent\nTcpExt: 0\nIpExt: InNoRoutes InMcastPkts InBcastPkts InMcastOctets InBcastOctets\nIpExt: 0 12 30 1200 4500\n"
	v, err := parseIpExt(text)
	if err != nil || v["InBcastPkts"] != 30 || v["InMcastOctets"] != 1200 {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestCountersReadHere(t *testing.T) {
	a, b, err := Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("non-unicast packets %d, octets %d", a, b)
}

// Ping depends on what this machine allows; it must either work or say why.
func TestPingLoopbackOrExplain(t *testing.T) {
	rtt, err := Ping(netip.Addr{}, netip.MustParseAddr("127.0.0.1"), time.Second)
	switch {
	case err == ErrNoICMP:
		t.Skip("no ICMP permission here: ping_group_range excludes this group and there's no CAP_NET_RAW")
	case err != nil:
		t.Fatal(err)
	}
	t.Logf("loopback ping %v", rtt)
}
