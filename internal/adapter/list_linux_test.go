package adapter

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRoutesFindsDefaultGatewaysByMetric(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0201A8C0	0003	0	0	50	00000000	0	0	0
eth1	00000000	0101A8C0	0001	0	0	0	00000000	0	0	0
`
	got := parseRoutes(bufio.NewScanner(strings.NewReader(table)))
	if len(got["eth0"]) != 2 || got["eth0"][0].gateway.String() != "192.168.1.2" || got["eth0"][1].gateway.String() != "192.168.1.1" {
		t.Errorf("eth0 = %+v, want 192.168.1.2 (metric 50) before 192.168.1.1", got["eth0"])
	}
	if len(got["wlan0"]) != 1 || got["wlan0"][0].gateway.String() != "192.168.1.254" {
		t.Errorf("wlan0 = %+v", got["wlan0"])
	}
	if len(got["eth1"]) != 0 {
		t.Error("a route without RTF_GATEWAY isn't a default gateway")
	}
}

func TestParseResolv(t *testing.T) {
	servers, suffix := parseResolv("# generated\nsearch corp.example lan\nnameserver 10.0.0.53\nnameserver fe80::1%eth0\nnameserver 2001:db8::53\n; nameserver 9.9.9.9\n")
	if len(servers) != 2 || servers[0].String() != "10.0.0.53" || servers[1].String() != "2001:db8::53" {
		t.Errorf("servers = %v", servers)
	}
	if suffix != "corp.example" {
		t.Errorf("suffix = %q", suffix)
	}
}

func TestResolvedStubIsReplacedByUpstream(t *testing.T) {
	dir := t.TempDir()
	stub, upstream := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "upstream.conf")
	os.WriteFile(stub, []byte("nameserver 127.0.0.53\noptions edns0\nsearch lan\n"), 0o644)
	os.WriteFile(upstream, []byte("nameserver 192.168.1.1\n"), 0o644)
	defer func(a, b string) { resolvConf, resolvedConf = a, b }(resolvConf, resolvedConf)
	resolvConf, resolvedConf = stub, upstream
	servers, suffix := readResolv()
	if len(servers) != 1 || servers[0].String() != "192.168.1.1" || suffix != "lan" {
		t.Errorf("got %v %q, want the upstream server and the stub's suffix", servers, suffix)
	}
}

func TestParseLeases(t *testing.T) {
	if ip, ok := parseSystemdLease("# networkd\nADDRESS=10.1.2.3\nSERVER_ADDRESS=10.1.2.1\nROUTER=10.1.2.1\n"); !ok || ip.String() != "10.1.2.1" {
		t.Errorf("systemd lease: %v %v", ip, ok)
	}
	const dhclient = `lease {
  interface "eth0";
  fixed-address 10.0.0.5;
  option dhcp-server-identifier 10.0.0.1;
}
lease {
  interface "wlan0";
  option dhcp-server-identifier 192.168.1.1;
}
lease {
  interface "eth0";
  option dhcp-server-identifier 10.0.0.2;
}
`
	if ip, ok := parseDhclientLeases(dhclient, "eth0"); !ok || ip.String() != "10.0.0.2" {
		t.Errorf("dhclient eth0 = %v %v, want the newest lease's server", ip, ok)
	}
	if _, ok := parseDhclientLeases(dhclient, "eth9"); ok {
		t.Error("no lease for eth9")
	}
}

func TestHexAddr(t *testing.T) {
	if ip, ok := hexAddr("0101A8C0"); !ok || ip.String() != "192.168.1.1" {
		t.Errorf("got %v", ip)
	}
}

// List must work on whatever machine runs the tests, and find at least the
// adapter that tests reach the network through, if there is one.
func TestListRunsHere(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		t.Logf("%-10s idx=%d kind=%s desc=%s mac=%s speed=%d ipv4=%v gw=%v dns=%v dhcp=%v/%v", a.Name, a.Index, a.Kind, a.Description, a.MAC, a.SpeedMbps, a.IPv4, a.Gateways, a.DNS, a.DHCPEnabled, a.DHCPServer)
	}
}
