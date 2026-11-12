package adapter

import "testing"

// These run against the real Windows API, the one thing tests elsewhere can't cover.
func TestListOnRealWindows(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Skip("no active adapters here")
	}
	for _, a := range list {
		t.Logf("%-28s idx=%-3d kind=%-8s mac=%s speed=%d mtu=%d dhcp=%v/%v ipv4=%v prefixes=%v gw=%v dns=%v",
			a.Name, a.Index, a.Kind, a.MAC, a.SpeedMbps, a.MTU, a.DHCPEnabled, a.DHCPServer, a.IPv4, a.PrefixesV4, a.Gateways, a.DNS)
		if a.Index == 0 || a.Name == "" || a.DeviceName == "" {
			t.Errorf("incomplete adapter: %+v", a)
		}
		if a.MTU == 0 || a.MTU > 70000 {
			t.Errorf("%s: implausible MTU %d, which suggests a misread struct", a.Name, a.MTU)
		}
		if len(a.IPv4) != len(a.PrefixesV4) {
			t.Errorf("%s: %d addresses but %d prefixes", a.Name, len(a.IPv4), len(a.PrefixesV4))
		}
		for _, p := range a.PrefixesV4 {
			if p.Bits() <= 0 || p.Bits() > 32 {
				t.Errorf("%s: implausible prefix %v", a.Name, p)
			}
		}
		if a.MAC != "" && a.HardwareAddr() == nil {
			t.Errorf("%s: MAC %q doesn't parse", a.Name, a.MAC)
		}
	}
}
