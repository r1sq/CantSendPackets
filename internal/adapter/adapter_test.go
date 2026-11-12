package adapter

import (
	"net/netip"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestSortPutsTheConnectedPhysicalAdapterFirst(t *testing.T) {
	list := []Adapter{
		{Name: "vEthernet", Kind: "Other"},
		{Name: "VPN", Kind: "Other", Gateways: addrs("10.8.0.1"), Metric: 1},
		{Name: "Unplugged-ish", Kind: "Ethernet"},
		{Name: "Wi-Fi", Kind: "Wi-Fi", Gateways: addrs("192.168.1.1"), Metric: 50},
		{Name: "Ethernet", Kind: "Ethernet", Gateways: addrs("192.168.1.1"), Metric: 25},
	}
	Sort(list)
	want := []string{"Ethernet", "Wi-Fi", "VPN", "Unplugged-ish", "vEthernet"}
	for i, n := range want {
		if list[i].Name != n {
			t.Fatalf("position %d = %s, want %s", i, list[i].Name, n)
		}
	}
}

func TestPrimaryIPv4PrefersRealAddressOverAPIPA(t *testing.T) {
	if got := (Adapter{IPv4: addrs("169.254.1.1", "10.0.0.5")}).PrimaryIPv4(); got.String() != "10.0.0.5" {
		t.Errorf("%s", got)
	}
	if got := (Adapter{IPv4: addrs("169.254.1.1")}).PrimaryIPv4(); got.String() != "169.254.1.1" {
		t.Errorf("%s", got)
	}
	if (Adapter{}).PrimaryIPv4().IsValid() {
		t.Error("no address should be invalid")
	}
}

func TestGatewayV4SkipsIPv6(t *testing.T) {
	a := Adapter{Gateways: addrs("fe80::1", "192.168.1.1")}
	if a.GatewayV4().String() != "192.168.1.1" {
		t.Errorf("%s", a.GatewayV4())
	}
}

func TestBroadcastAddr(t *testing.T) {
	cases := []struct {
		prefix, want string
		ok           bool
	}{
		{"192.168.1.42/24", "192.168.1.255", true},
		{"10.1.2.3/8", "10.255.255.255", true},
		{"172.16.5.9/20", "172.16.15.255", true},
		{"10.0.0.1/31", "", false},
		{"10.0.0.1/32", "", false},
		{"2001:db8::1/64", "", false},
	}
	for _, c := range cases {
		got, ok := BroadcastAddr(netip.MustParsePrefix(c.prefix))
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Errorf("%s: %v %v", c.prefix, got, ok)
		}
	}
}

func TestLeaseServerIgnoresPlaceholders(t *testing.T) {
	for in, want := range map[string]string{
		"10.16.1.1":       "10.16.1.1",
		"255.255.255.255": "invalid IP", // Windows while rebinding
		"0.0.0.0":         "invalid IP",
	} {
		if got := LeaseServer(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("LeaseServer(%s) = %s, want %s", in, got, want)
		}
	}
	if LeaseServer(netip.Addr{}).IsValid() {
		t.Error("no address should stay no address")
	}
}
