package probe

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// ErrNoICMP means this process may open neither an unprivileged ICMP socket
// (net.ipv4.ping_group_range doesn't include its group) nor a raw one.
var ErrNoICMP = verdict.Err("err.icmp.noPermission")

// listenICMP opens the least privileged ICMP socket available. Datagram sockets
// work for ordinary users on most distributions; raw ones need CAP_NET_RAW.
func listenICMP(src netip.Addr) (*icmp.PacketConn, bool, error) {
	addr := "0.0.0.0"
	if src.Is4() {
		addr = src.String()
	}
	if c, err := icmp.ListenPacket("udp4", addr); err == nil {
		return c, true, nil
	}
	if c, err := icmp.ListenPacket("ip4:icmp", addr); err == nil {
		return c, false, nil
	}
	return nil, false, ErrNoICMP
}

// PingAvailable reports whether Ping can work at all for this process.
func PingAvailable() bool {
	c, _, err := listenICMP(netip.Addr{})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

var pingSeq uint32

// Ping sends one ICMP echo from src.
func Ping(src, dst netip.Addr, timeout time.Duration) (time.Duration, error) {
	if !dst.Is4() {
		return 0, verdict.Err("err.icmp.noV6")
	}
	c, dgram, err := listenICMP(src)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	pingSeq++
	seq := int(pingSeq & 0xffff)
	id := os.Getpid() & 0xffff // a datagram socket's kernel replaces it with its port
	payload := []byte("CantSendPackets ping payload....")
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	var to net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if dgram {
		to = &net.UDPAddr{IP: dst.AsSlice()}
	}
	start := time.Now()
	deadline := start.Add(timeout)
	if _, err := c.WriteTo(b, to); err != nil {
		return 0, err
	}
	c.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return 0, verdict.Err("err.timeout")
			}
			return 0, err
		}
		rtt := time.Since(start)
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		switch body := reply.Body.(type) {
		case *icmp.Echo:
			if reply.Type != ipv4.ICMPTypeEchoReply || body.Seq != seq || string(body.Data) != string(payload) {
				continue
			}
			if !dgram && (body.ID != id || !sameHost(from, dst)) {
				continue
			}
			return rtt, nil
		case *icmp.DstUnreach:
			if quotesOurEcho(body.Data, dst) {
				return 0, verdict.Err("err.icmp.hostUnreachable")
			}
		case *icmp.TimeExceeded:
			if quotesOurEcho(body.Data, dst) {
				return 0, verdict.Err("err.icmp.ttlExpired")
			}
		}
	}
}

func sameHost(from net.Addr, dst netip.Addr) bool {
	var ip net.IP
	switch a := from.(type) {
	case *net.IPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	}
	got, ok := netip.AddrFromSlice(ip)
	return ok && got.Unmap() == dst
}

// quotesOurEcho reports whether an ICMP error quotes a packet that was going to dst.
func quotesOurEcho(quoted []byte, dst netip.Addr) bool {
	if len(quoted) < 20 {
		return false
	}
	to, _ := netip.AddrFromSlice(quoted[16:20])
	return to == dst
}

var procNetARP = "/proc/net/arp"

// ARP resolves dst's MAC on the local segment, through the kernel's neighbour
// table: a datagram to the discard port makes the kernel resolve it, with no raw
// socket needed. Like Windows' SendARP, a cached entry answers at once.
func ARP(src, dst netip.Addr) (net.HardwareAddr, time.Duration, error) {
	if !dst.Is4() {
		return nil, 0, verdict.Err("err.arp.noV6")
	}
	start := time.Now()
	if mac, ok := neighbour(dst); ok {
		return mac, time.Since(start), nil
	}
	var laddr *net.UDPAddr
	if src.Is4() {
		laddr = &net.UDPAddr{IP: src.AsSlice()}
	}
	if c, err := net.DialUDP("udp4", laddr, &net.UDPAddr{IP: dst.AsSlice(), Port: 9}); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	for time.Since(start) < 3*time.Second {
		time.Sleep(5 * time.Millisecond)
		if mac, ok := neighbour(dst); ok {
			return mac, time.Since(start), nil
		}
	}
	return nil, 0, verdict.Err("err.arp.noReply")
}

// neighbour looks dst up in /proc/net/arp, counting only complete entries.
func neighbour(dst netip.Addr) (net.HardwareAddr, bool) {
	f, err := os.Open(procNetARP)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	return parseARPTable(bufio.NewScanner(f), dst)
}

func parseARPTable(sc *bufio.Scanner, dst netip.Addr) (net.HardwareAddr, bool) {
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] != dst.String() {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 { // ATF_COM
			continue
		}
		if mac, err := net.ParseMAC(f[3]); err == nil && len(mac) == 6 && mac.String() != "00:00:00:00:00:00" {
			return mac, true
		}
	}
	return nil, false
}

var procNetNetstat = "/proc/net/netstat"

// Counters returns cumulative broadcast and multicast packets and bytes received.
// Linux doesn't count broadcast per interface without a raw socket, so these are
// the kernel's IP-level totals for all interfaces (IpExt): ARP isn't included,
// but the IP broadcasts and multicasts every loop also carries are.
func Counters(ifIndex uint32) (nonUnicast, octets uint64, err error) {
	b, err := os.ReadFile(procNetNetstat)
	if err != nil {
		return 0, 0, err
	}
	v, err := parseIpExt(string(b))
	if err != nil {
		return 0, 0, err
	}
	return v["InBcastPkts"] + v["InMcastPkts"], v["InBcastOctets"] + v["InMcastOctets"], nil
}

func parseIpExt(text string) (map[string]uint64, error) {
	lines := strings.Split(text, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "IpExt:") || !strings.HasPrefix(lines[i+1], "IpExt:") {
			continue
		}
		names, values := strings.Fields(lines[i])[1:], strings.Fields(lines[i+1])[1:]
		out := map[string]uint64{}
		for j := 0; j < len(names) && j < len(values); j++ {
			n, _ := strconv.ParseUint(values[j], 10, 64)
			out[names[j]] = n
		}
		return out, nil
	}
	return nil, errors.New("no IpExt counters in " + procNetNetstat)
}

// WebTestLogin is WebTest for a proxy that wants a login. Linux has no Windows
// login to offer, so only typed credentials are tried, sent as Basic.
func WebTestLogin(ctx context.Context, src netip.Addr, check WebCheck, proxyHost string, _ proxy.LogonLevel, user, password string, timeout time.Duration) (time.Duration, error) {
	if user == "" {
		return 0, monitor.ErrProxyAuth
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return WebTest(ctx, src, check, &url.URL{Scheme: "http", Host: proxyHost, User: url.UserPassword(user, password)})
}
