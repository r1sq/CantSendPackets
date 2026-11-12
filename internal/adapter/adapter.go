// Package adapter describes the machine's network adapters.
package adapter

import (
	"net"
	"net/netip"
	"sort"
)

// Adapter is one network interface and how it's configured.
type Adapter struct {
	Index       uint32       `json:"index"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Kind        string       `json:"kind"` // "Ethernet", "Wi-Fi", "Other"
	MAC         string       `json:"mac"`
	SpeedMbps   uint64       `json:"speedMbps"`
	MTU         uint32       `json:"mtu"`
	DHCPEnabled bool         `json:"dhcpEnabled"`
	DHCPServer  netip.Addr   `json:"dhcpServer"`
	IPv4        []netip.Addr `json:"ipv4"`
	IPv6        []netip.Addr `json:"ipv6"`
	Gateways    []netip.Addr `json:"gateways"`
	DNS         []netip.Addr `json:"dns"`
	DNSSuffix   string       `json:"dnsSuffix"`

	// PrefixesV4 holds each IPv4 address with its subnet.
	PrefixesV4 []netip.Prefix `json:"-"`
	// DeviceName is the OS's internal name, which Npcap needs.
	DeviceName string `json:"-"`
	Metric     uint32 `json:"-"`
}

// LeaseServer turns the DHCP server Windows reports into one that can be
// compared with offers. While the lease is being renewed or rebound Windows
// reports 255.255.255.255, and before it has one 0.0.0.0; neither names a
// server, so both come back as no address. Seen on a real client mid-rebind.
func LeaseServer(reported netip.Addr) netip.Addr {
	if !reported.IsValid() || reported.IsUnspecified() || reported == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}
	}
	return reported
}

// HardwareAddr returns the parsed MAC, or nil.
func (a Adapter) HardwareAddr() net.HardwareAddr {
	m, err := net.ParseMAC(a.MAC)
	if err != nil {
		return nil
	}
	return m
}

// PrimaryIPv4 returns the first usable IPv4 address. Link-local (APIPA) is
// returned only if there's nothing better, since it's what an adapter that has
// failed to get a lease is left with.
func (a Adapter) PrimaryIPv4() netip.Addr {
	var fallback netip.Addr
	for _, ip := range a.IPv4 {
		if !ip.IsLinkLocalUnicast() {
			return ip
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	return fallback
}

// GatewayV4 returns the first IPv4 default gateway.
func (a Adapter) GatewayV4() netip.Addr {
	for _, g := range a.Gateways {
		if g.Is4() {
			return g
		}
	}
	return netip.Addr{}
}

// BroadcastAddr returns a prefix's directed broadcast address. Host routes and
// /31 links have none.
func BroadcastAddr(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() || p.Bits() >= 31 || p.Bits() < 0 {
		return netip.Addr{}, false
	}
	b := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// Sort orders adapters so the one carrying traffic comes first: the one with a
// gateway, then physical before virtual, then lowest route metric.
func Sort(list []Adapter) {
	rank := func(a Adapter) int {
		score := 0
		if !a.GatewayV4().IsValid() {
			score += 4
		}
		if a.Kind == "Other" {
			score += 2
		}
		return score
	}
	sort.SliceStable(list, func(i, j int) bool {
		ri, rj := rank(list[i]), rank(list[j])
		if ri != rj {
			return ri < rj
		}
		return list[i].Metric < list[j].Metric
	})
}
