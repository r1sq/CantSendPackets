package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

var (
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = iphlpapi.NewProc("IcmpSendEcho2Ex")
	procSendARP         = iphlpapi.NewProc("SendARP")
)

// icmpEchoReply mirrors ICMP_ECHO_REPLY for 64-bit processes. Go's alignment
// rules produce the same 40-byte layout as the C struct.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type ipOptionInformation struct {
	TTL, TOS, Flags, OptionsSize uint8
	OptionsData                  uintptr
}

var _ [40 - unsafe.Sizeof(icmpEchoReply{})]byte
var _ [unsafe.Sizeof(icmpEchoReply{}) - 40]byte

var icmpStatus = map[uint32]string{
	11002: "err.icmp.netUnreachable",
	11003: "err.icmp.hostUnreachable",
	11004: "err.icmp.protoUnreachable",
	11005: "err.icmp.portUnreachable",
	11010: "err.timeout",
	11013: "err.icmp.ttlExpired",
	11050: "err.icmp.general",
}

func describeICMP(status uint32) error {
	if key, ok := icmpStatus[status]; ok {
		return verdict.Err(key)
	}
	return verdict.Err("err.icmp.status", "status", status)
}

// to4 packs an IPv4 address the way the Win32 IP APIs want it: network byte
// order in memory, which reads as little-endian on these machines.
func to4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// Ping sends one ICMP echo from src using the unprivileged ICMP API, so no
// elevation or raw socket is needed. Windows reports whole milliseconds.
func Ping(src, dst netip.Addr, timeout time.Duration) (time.Duration, error) {
	if !dst.Is4() {
		return 0, verdict.Err("err.icmp.noV6")
	}
	h, _, callErr := procIcmpCreateFile.Call()
	if h == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("IcmpCreateFile: %w", callErr)
	}
	defer procIcmpCloseHandle.Call(h)

	payload := []byte("CantSendPackets ping payload....")
	buf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+8+64)
	var srcAddr uint32
	if src.Is4() {
		srcAddr = to4(src)
	}
	n, _, callErr := procIcmpSendEcho2Ex.Call(
		h, 0, 0, 0,
		uintptr(srcAddr), uintptr(to4(dst)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(timeout.Milliseconds()),
	)
	if n == 0 {
		// A timeout surfaces here as a failed call rather than a reply status.
		if errno, ok := callErr.(windows.Errno); ok && uint32(errno) >= 11000 && uint32(errno) < 12000 {
			return 0, describeICMP(uint32(errno))
		}
		return 0, callErr
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	if reply.Status != 0 {
		return 0, describeICMP(reply.Status)
	}
	return time.Duration(reply.RoundTripTime) * time.Millisecond, nil
}

// ARP resolves dst's MAC on the local segment. It works against hosts that
// ignore ping, and SendARP needs no elevation.
func ARP(src, dst netip.Addr) (net.HardwareAddr, time.Duration, error) {
	if !dst.Is4() {
		return nil, 0, verdict.Err("err.arp.noV6")
	}
	var macBuf [2]uint32 // SendARP's documented buffer is ULONG[2]
	mac := unsafe.Slice((*byte)(unsafe.Pointer(&macBuf[0])), 8)
	size := uint32(len(mac))
	var srcAddr uint32
	if src.Is4() {
		srcAddr = to4(src)
	}
	start := time.Now()
	r, _, _ := procSendARP.Call(uintptr(to4(dst)), uintptr(srcAddr), uintptr(unsafe.Pointer(&macBuf[0])), uintptr(unsafe.Pointer(&size)))
	rtt := time.Since(start)
	if r != 0 {
		return nil, 0, verdict.Err("err.arp.noReply")
	}
	if size == 0 || size > uint32(len(mac)) {
		return nil, 0, verdict.Err("err.arp.noReply")
	}
	return net.HardwareAddr(append([]byte(nil), mac[:size]...)), rtt, nil
}

// Counters reads cumulative non-unicast receive counters for an interface. No
// elevation or driver is needed.
func Counters(ifIndex uint32) (nonUnicast, broadcastOctets uint64, err error) {
	row := windows.MibIfRow2{InterfaceIndex: ifIndex}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
		return 0, 0, fmt.Errorf("GetIfEntry2Ex: %w", err)
	}
	return row.InNUcastPkts, row.InBroadcastOctets, nil
}

// WebTestWinHTTP is WebTest for a proxy that wants a login, which needs Windows'
// own HTTP stack to speak NTLM and Kerberos with the user's credentials. Unlike
// WebTest it can't bind a source address, so it follows the routing table.
func WebTestWinHTTP(check WebCheck, proxyHost string, level proxy.LogonLevel, user, password string, timeout time.Duration) (time.Duration, error) {
	res, err := proxy.Fetch(proxy.FetchOptions{
		URL: check.URL, ProxyHost: proxyHost, Level: level, User: user, Password: password, Timeout: timeout,
	})
	if errors.Is(err, proxy.ErrCertificate) {
		return 0, monitor.ErrCaptive
	}
	if err != nil {
		return 0, err
	}
	return res.RTT, judge(res.Status, res.Body, check)
}
