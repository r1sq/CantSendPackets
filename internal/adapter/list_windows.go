package adapter

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ifTypeEthernet = 6
	ifTypeWiFi     = 71
	ifTypeLoopback = 24
	ifTypeTunnel   = 131

	operStatusUp = 1

	flagDHCPEnabled = 0x4

	gaaIncludeGateways = 0x80
	gaaSkipAnycast     = 0x2
	gaaSkipMulticast   = 0x4
)

// List returns the adapters that are up and could carry traffic, best first.
func List() ([]Adapter, error) {
	size := uint32(32 * 1024)
	for attempt := 0; ; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaIncludeGateways|gaaSkipAnycast|gaaSkipMulticast, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) && attempt < 4 {
			continue // the adapter set changed size: retry with the new one
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var out []Adapter
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != operStatusUp || a.IfType == ifTypeLoopback {
				continue
			}
			ad := convert(a)
			// Skip pseudo-interfaces such as Teredo that have no IPv4 presence.
			if a.IfType == ifTypeTunnel && len(ad.IPv4) == 0 {
				continue
			}
			out = append(out, ad)
		}
		Sort(out)
		return out, nil
	}
}

func convert(a *windows.IpAdapterAddresses) Adapter {
	ad := Adapter{
		Index:       a.IfIndex,
		Name:        windows.UTF16PtrToString(a.FriendlyName),
		Description: windows.UTF16PtrToString(a.Description),
		DeviceName:  windows.BytePtrToString(a.AdapterName),
		MTU:         a.Mtu,
		DNSSuffix:   windows.UTF16PtrToString(a.DnsSuffix),
		DHCPEnabled: a.Flags&flagDHCPEnabled != 0,
		Metric:      a.Ipv4Metric,
	}
	switch a.IfType {
	case ifTypeEthernet:
		ad.Kind = "Ethernet"
	case ifTypeWiFi:
		ad.Kind = "Wi-Fi"
	default:
		ad.Kind = "Other"
	}
	if a.PhysicalAddressLength == 6 {
		ad.MAC = net.HardwareAddr(a.PhysicalAddress[:6]).String()
	}
	// Windows reports "unknown" as all ones.
	if a.ReceiveLinkSpeed != ^uint64(0) {
		ad.SpeedMbps = a.ReceiveLinkSpeed / 1_000_000
	}
	if a.Flags&flagDHCPEnabled != 0 {
		ad.DHCPServer = LeaseServer(toAddr(a.Dhcpv4Server))
	}
	for u := a.FirstUnicastAddress; u != nil; u = u.Next {
		ip := toAddr(u.Address)
		switch {
		case !ip.IsValid():
		case ip.Is4():
			ad.IPv4 = append(ad.IPv4, ip)
			if p, err := ip.Prefix(int(u.OnLinkPrefixLength)); err == nil {
				ad.PrefixesV4 = append(ad.PrefixesV4, netip.PrefixFrom(ip, p.Bits()))
			}
		default:
			ad.IPv6 = append(ad.IPv6, ip)
		}
	}
	for g := a.FirstGatewayAddress; g != nil; g = g.Next {
		if ip := toAddr(g.Address); ip.IsValid() {
			ad.Gateways = append(ad.Gateways, ip)
		}
	}
	for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
		ip := toAddr(d.Address)
		// fec0:0:0:ffff::/48 is a long-dead default Windows lists on adapters
		// with no real IPv6 DNS. Testing it would report a phantom failure.
		if ip.IsValid() && !isDeprecatedSiteLocalDNS(ip) {
			ad.DNS = append(ad.DNS, ip)
		}
	}
	return ad
}

func isDeprecatedSiteLocalDNS(ip netip.Addr) bool {
	if !ip.Is6() {
		return false
	}
	b := ip.As16()
	return b[0] == 0xfe && b[1] == 0xc0 && b[6] == 0xff && b[7] == 0xff
}

func toAddr(sa windows.SocketAddress) netip.Addr {
	if sa.Sockaddr == nil {
		return netip.Addr{}
	}
	switch sa.Sockaddr.Addr.Family {
	case windows.AF_INET:
		raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		ip := netip.AddrFrom4(raw.Addr)
		if ip.IsUnspecified() {
			return netip.Addr{}
		}
		return ip
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		ip := netip.AddrFrom16(raw.Addr)
		if ip.IsLinkLocalUnicast() && raw.Scope_id != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(raw.Scope_id), 10))
		}
		return ip
	}
	return netip.Addr{}
}
