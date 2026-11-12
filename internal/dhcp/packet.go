// Package dhcp discovers which DHCP servers answer on a network segment.
//
// It sends DHCPDISCOVER and collects DHCPOFFERs. It never sends DHCPREQUEST, so
// no lease is taken and the machine's own configuration is left alone.
package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
)

const (
	ClientPort = 68
	ServerPort = 67

	opRequest = 1
	opReply   = 2

	headerLen   = 236
	cookieLen   = 4
	minBootpLen = 300

	flagBroadcast = 0x8000
	magicCookie   = 0x63825363

	optPad        = 0
	optSubnetMask = 1
	optRouter     = 3
	optDNS        = 6
	optDomainName = 15
	optLeaseTime  = 51
	optMsgType    = 53
	optServerID   = 54
	optParamList  = 55
	optVendorID   = 60
	optEnd        = 255

	msgDiscover = 1
	msgOffer    = 2
)

// BuildDiscover returns a DHCPDISCOVER using the adapter's real MAC, because
// switches running DHCP snooping drop requests whose chaddr differs from the
// frame's source MAC. The broadcast flag is set so servers broadcast their
// offer, which any socket bound to port 68 can receive.
func BuildDiscover(xid uint32, mac net.HardwareAddr) []byte {
	p := make([]byte, headerLen, minBootpLen)
	p[0] = opRequest
	p[1] = 1 // htype: Ethernet
	p[2] = 6 // hlen
	binary.BigEndian.PutUint32(p[4:], xid)
	binary.BigEndian.PutUint16(p[10:], flagBroadcast)
	copy(p[28:44], mac)

	p = binary.BigEndian.AppendUint32(p, magicCookie)
	p = append(p, optMsgType, 1, msgDiscover)
	p = append(p, optParamList, 6, optSubnetMask, optRouter, optDNS, optDomainName, optLeaseTime, optServerID)
	vendor := "CantSendPackets"
	p = append(p, optVendorID, byte(len(vendor)))
	p = append(p, vendor...)
	p = append(p, optEnd)
	for len(p) < minBootpLen {
		p = append(p, optPad)
	}
	return p
}

// Offer is a parsed DHCPOFFER. Every string in it is attacker-controllable: any
// device on the segment can send one.
type Offer struct {
	YourIP   netip.Addr
	ServerID netip.Addr
	Mask     netip.Addr
	Routers  []netip.Addr
	DNS      []netip.Addr
	Domain   string
	Lease    uint32
}

var errNotOffer = errors.New("not a matching DHCPOFFER")

// ParseOffer accepts only a well-formed offer answering this xid and MAC.
func ParseOffer(p []byte, xid uint32, mac net.HardwareAddr) (Offer, error) {
	if len(p) < headerLen+cookieLen || p[0] != opReply {
		return Offer{}, errNotOffer
	}
	if binary.BigEndian.Uint32(p[4:]) != xid {
		return Offer{}, errNotOffer
	}
	if len(mac) == 6 && !strings.EqualFold(net.HardwareAddr(p[28:34]).String(), mac.String()) {
		return Offer{}, errNotOffer
	}
	if binary.BigEndian.Uint32(p[headerLen:]) != magicCookie {
		return Offer{}, errNotOffer
	}

	o := Offer{YourIP: addr4(p[16:20])}
	msgType := byte(0)
	opts := p[headerLen+cookieLen:]
	for i := 0; i < len(opts); {
		code := opts[i]
		i++
		if code == optPad {
			continue
		}
		if code == optEnd || i >= len(opts) {
			break
		}
		n := int(opts[i])
		i++
		if i+n > len(opts) {
			break // truncated option: keep what was parsed so far
		}
		v := opts[i : i+n]
		i += n
		switch code {
		case optMsgType:
			if n == 1 {
				msgType = v[0]
			}
		case optServerID:
			if n == 4 {
				o.ServerID = addr4(v)
			}
		case optSubnetMask:
			if n == 4 {
				o.Mask = addr4(v)
			}
		case optRouter:
			o.Routers = addrList(v)
		case optDNS:
			o.DNS = addrList(v)
		case optDomainName:
			o.Domain = sanitize(v)
		case optLeaseTime:
			if n == 4 {
				o.Lease = binary.BigEndian.Uint32(v)
			}
		}
	}
	if msgType != msgOffer {
		return Offer{}, errNotOffer
	}
	return o, nil
}

func addr4(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte(b[:4]))
}

// addrList caps the count so a hostile offer cannot bloat the report.
func addrList(b []byte) []netip.Addr {
	var out []netip.Addr
	for i := 0; i+4 <= len(b) && len(out) < 8; i += 4 {
		out = append(out, addr4(b[i:i+4]))
	}
	return out
}

// sanitize reduces untrusted option text to short printable ASCII.
func sanitize(b []byte) string {
	const maxLen = 64
	var s strings.Builder
	for _, c := range b {
		if s.Len() == maxLen {
			break
		}
		if c >= 0x20 && c < 0x7f {
			s.WriteByte(c)
		}
	}
	return s.String()
}
