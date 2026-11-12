package adapter

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Where Linux keeps what Windows returns from one call. Variables, so tests can
// point them at fixtures.
var (
	sysClassNet    = "/sys/class/net"
	procNetRoute   = "/proc/net/route"
	resolvConf     = "/etc/resolv.conf"
	resolvedConf   = "/run/systemd/resolve/resolv.conf" // systemd-resolved's upstream servers
	leaseDirs      = []string{"/run/systemd/netif/leases", "/var/lib/NetworkManager"}
	dhclientLeases = []string{"/var/lib/dhcp", "/var/lib/dhclient"}
)

// List returns the adapters that are up and could carry traffic, best first.
func List() ([]Adapter, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	routes := readRoutes(procNetRoute)
	dns, suffix := readResolv()
	dynamic := dynamicIPv4()
	var out []Adapter
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		ad := Adapter{
			Index:      uint32(ifc.Index),
			Name:       ifc.Name,
			DeviceName: ifc.Name,
			MTU:        uint32(ifc.MTU),
			DNSSuffix:  suffix,
		}
		if len(ifc.HardwareAddr) == 6 {
			ad.MAC = ifc.HardwareAddr.String()
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(p.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			bits, _ := p.Mask.Size()
			if ip.Is4() {
				ad.IPv4 = append(ad.IPv4, ip)
				ad.PrefixesV4 = append(ad.PrefixesV4, netip.PrefixFrom(ip, bits))
			} else {
				ad.IPv6 = append(ad.IPv6, ip)
			}
		}
		if len(ad.IPv4) == 0 && len(ad.IPv6) == 0 {
			continue
		}
		for _, r := range routes[ifc.Name] {
			ad.Gateways = append(ad.Gateways, r.gateway)
			if ad.Metric == 0 || r.metric < ad.Metric {
				ad.Metric = r.metric
			}
		}
		if len(ad.IPv4) > 0 {
			ad.DNS = dns
		}
		ad.Kind = kind(ifc.Name, len(ad.Gateways) > 0)
		// Container and VM plumbing (veth, tap) only clutters the list.
		if ad.Kind == "Other" && len(ad.IPv4) == 0 {
			continue
		}
		ad.Description = describe(ifc.Name, ad.Kind)
		ad.SpeedMbps = speed(ifc.Name)
		if server, ok := leaseServer(ifc.Name, ifc.Index); ok {
			ad.DHCPEnabled = true
			ad.DHCPServer = LeaseServer(server)
		} else if dynamic[ifc.Index] {
			// A DHCP client whose lease files aren't known here: the address
			// still says it was leased, though not from which server.
			ad.DHCPEnabled = true
		}
		out = append(out, ad)
	}
	Sort(out)
	return out, nil
}

// kind sorts an interface the way the checks care about: Wi-Fi, a wired path to
// the network, or something virtual. A bridge or bond with a physical port counts
// as wired, since on servers that's where the address lives, and so does
// whatever carries the default route, such as a container's veth.
func kind(name string, hasDefaultRoute bool) string {
	dir := filepath.Join(sysClassNet, name)
	if exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")) {
		return "Wi-Fi"
	}
	if readTrim(filepath.Join(dir, "type")) != "1" { // ARPHRD_ETHER
		return "Other"
	}
	if hasPhysical(name, 0) || hasDefaultRoute {
		return "Ethernet"
	}
	return "Other"
}

// hasPhysical reports whether an interface is, or sits on top of, real hardware.
func hasPhysical(name string, depth int) bool {
	dir := filepath.Join(sysClassNet, name)
	if exists(filepath.Join(dir, "device")) {
		return true
	}
	if depth > 4 {
		return false
	}
	lowers, _ := filepath.Glob(filepath.Join(dir, "lower_*"))
	for _, l := range lowers {
		if hasPhysical(strings.TrimPrefix(filepath.Base(l), "lower_"), depth+1) {
			return true
		}
	}
	return false
}

func describe(name, kind string) string {
	dir := filepath.Join(sysClassNet, name)
	switch {
	case exists(filepath.Join(dir, "bridge")):
		return "Bridge"
	case exists(filepath.Join(dir, "bonding")):
		return "Bond"
	}
	if driver, err := os.Readlink(filepath.Join(dir, "device", "driver")); err == nil {
		return filepath.Base(driver)
	}
	return kind
}

// speed reads the link speed in Mbit/s, or from the first physical port of a
// bridge or bond. Virtual links report none.
func speed(name string) uint64 {
	if v, err := strconv.ParseInt(readTrim(filepath.Join(sysClassNet, name, "speed")), 10, 64); err == nil && v > 0 {
		return uint64(v)
	}
	lowers, _ := filepath.Glob(filepath.Join(sysClassNet, name, "lower_*"))
	for _, l := range lowers {
		if s := speed(strings.TrimPrefix(filepath.Base(l), "lower_")); s > 0 {
			return s
		}
	}
	return 0
}

// dynamicIPv4 returns the interfaces holding an IPv4 address with a finite
// lifetime, which is how the kernel marks a leased one: static addresses are
// IFA_F_PERMANENT.
func dynamicIPv4() map[int]bool {
	out := map[int]bool{}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_INET)
	if err != nil {
		return out
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return out
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		ifa := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
		if ifa.Flags&syscall.IFA_F_PERMANENT == 0 {
			out[int(ifa.Index)] = true
		}
	}
	return out
}

type route struct {
	gateway netip.Addr
	metric  uint32
}

// readRoutes returns each interface's IPv4 default gateways from /proc/net/route,
// lowest metric first.
func readRoutes(path string) map[string][]route {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseRoutes(bufio.NewScanner(f))
}

func parseRoutes(sc *bufio.Scanner) map[string][]route {
	out := map[string][]route{}
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 16)
		if err != nil || flags&0x1 == 0 || flags&0x2 == 0 { // RTF_UP, RTF_GATEWAY
			continue
		}
		gw, ok := hexAddr(f[2])
		if !ok {
			continue
		}
		metric, _ := strconv.ParseUint(f[6], 10, 32)
		r := route{gateway: gw, metric: uint32(metric)}
		list := out[f[0]]
		i := 0
		for i < len(list) && list[i].metric <= r.metric {
			i++
		}
		out[f[0]] = append(list[:i], append([]route{r}, list[i:]...)...)
	}
	return out
}

// hexAddr reads an address as /proc writes it: 8 hex digits in host byte order,
// which is little-endian on everything Linux runs this on.
func hexAddr(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
	return netip.AddrFrom4(a), true
}

// readResolv returns the DNS servers and search suffix. Behind systemd-resolved's
// local stub, the servers worth testing are the upstream ones it forwards to.
func readResolv() ([]netip.Addr, string) {
	servers, suffix := parseResolv(readFile(resolvConf))
	if onlyLoopback(servers) {
		if upstream, s := parseResolv(readFile(resolvedConf)); len(upstream) > 0 {
			servers = upstream
			if suffix == "" {
				suffix = s
			}
		}
	}
	return servers, suffix
}

func parseResolv(text string) (servers []netip.Addr, suffix string) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";") {
			continue
		}
		switch f[0] {
		case "nameserver":
			// A scope suffix (fe80::1%eth0) can't be tested from another adapter.
			if ip, err := netip.ParseAddr(f[1]); err == nil && ip.Zone() == "" {
				servers = append(servers, ip)
			}
		case "search", "domain":
			if suffix == "" {
				suffix = f[1]
			}
		}
	}
	return servers, suffix
}

func onlyLoopback(list []netip.Addr) bool {
	if len(list) == 0 {
		return false
	}
	for _, ip := range list {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// leaseServer finds the DHCP server of the interface's current lease, from
// systemd-networkd, NetworkManager's internal client, or dhclient.
func leaseServer(name string, index int) (netip.Addr, bool) {
	// systemd-networkd names leases by interface index, NetworkManager's internal
	// client by connection and interface; both use the same format.
	candidates := []string{filepath.Join(leaseDirs[0], strconv.Itoa(index))}
	if more, _ := filepath.Glob(filepath.Join(leaseDirs[1], "internal-*-"+name+".lease")); len(more) > 0 {
		candidates = append(candidates, more...)
	}
	for _, path := range candidates {
		if ip, ok := parseSystemdLease(readFile(path)); ok {
			return ip, true
		}
	}
	for _, dir := range dhclientLeases {
		files, _ := filepath.Glob(filepath.Join(dir, "*.lease*"))
		for _, path := range files {
			if ip, ok := parseDhclientLeases(readFile(path), name); ok {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

func parseSystemdLease(text string) (netip.Addr, bool) {
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SERVER_ADDRESS="); ok {
			ip, err := netip.ParseAddr(v)
			return ip, err == nil
		}
	}
	return netip.Addr{}, false
}

// parseDhclientLeases returns the server of the last lease for an interface:
// dhclient appends, so the newest comes last.
func parseDhclientLeases(text, iface string) (netip.Addr, bool) {
	var found netip.Addr
	inLease, matches := false, false
	var server netip.Addr
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		switch {
		case strings.HasPrefix(line, "lease {"):
			inLease, matches, server = true, false, netip.Addr{}
		case line == "}" && inLease:
			if matches && server.IsValid() {
				found = server
			}
			inLease = false
		case inLease && strings.HasPrefix(line, "interface "):
			matches = strings.Trim(strings.TrimPrefix(line, "interface "), `"`) == iface
		case inLease && strings.HasPrefix(line, "option dhcp-server-identifier "):
			server, _ = netip.ParseAddr(strings.TrimPrefix(line, "option dhcp-server-identifier "))
		}
	}
	return found, found.IsValid()
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func readTrim(path string) string { return strings.TrimSpace(readFile(path)) }

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
