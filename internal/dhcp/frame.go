package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	etherIPv4 = 0x0800
	etherVLAN = 0x8100
	protoUDP  = 17
)

// EncodeDiscoverFrame wraps a DHCP payload in Ethernet/IPv4/UDP, sourced from
// 0.0.0.0 as a client with no address would. This is what lets the check work
// on an adapter that has failed to get a lease.
func EncodeDiscoverFrame(mac net.HardwareAddr, payload []byte) []byte {
	const ethLen, ipLen, udpLen = 14, 20, 8
	f := make([]byte, ethLen+ipLen+udpLen+len(payload))

	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:], etherIPv4)

	ip := f[ethLen : ethLen+ipLen]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(ipLen+udpLen+len(payload)))
	ip[8] = 64
	ip[9] = protoUDP
	copy(ip[12:16], []byte{0, 0, 0, 0})
	copy(ip[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	udp := f[ethLen+ipLen:]
	binary.BigEndian.PutUint16(udp[0:], ClientPort)
	binary.BigEndian.PutUint16(udp[2:], ServerPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen+len(payload)))
	copy(udp[udpLen:], payload)
	binary.BigEndian.PutUint16(udp[6:], udpChecksum(ip[12:16], ip[16:20], udp))
	return f
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func udpChecksum(src, dst, udp []byte) uint16 {
	pseudo := make([]byte, 0, 12+len(udp))
	pseudo = append(pseudo, src...)
	pseudo = append(pseudo, dst...)
	pseudo = append(pseudo, 0, protoUDP)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(udp)))
	pseudo = append(pseudo, udp...)
	c := checksum(pseudo)
	if c == 0 {
		return 0xffff // RFC 768: zero means "no checksum"
	}
	return c
}

// ServerReply is a UDP datagram from a DHCP server, as seen on the wire.
type ServerReply struct {
	SrcMAC  string
	SrcIP   netip.Addr
	Payload []byte
}

// DecodeServerFrame extracts a server-to-client DHCP datagram from a captured
// Ethernet frame. Captured frames are untrusted, so every length is checked.
func DecodeServerFrame(f []byte) (ServerReply, bool) {
	if len(f) < 14 {
		return ServerReply{}, false
	}
	etherType := binary.BigEndian.Uint16(f[12:])
	off := 14
	if etherType == etherVLAN {
		if len(f) < 18 {
			return ServerReply{}, false
		}
		etherType = binary.BigEndian.Uint16(f[16:])
		off = 18
	}
	if etherType != etherIPv4 || len(f) < off+20 {
		return ServerReply{}, false
	}
	ip := f[off:]
	if ip[0]>>4 != 4 || ip[9] != protoUDP {
		return ServerReply{}, false
	}
	if fragOffset := binary.BigEndian.Uint16(ip[6:]) & 0x1fff; fragOffset != 0 {
		return ServerReply{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return ServerReply{}, false
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[0:]) != ServerPort || binary.BigEndian.Uint16(udp[2:]) != ClientPort {
		return ServerReply{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:]))
	if udpLen < 8 || udpLen > len(udp) {
		return ServerReply{}, false
	}
	return ServerReply{
		SrcMAC:  net.HardwareAddr(f[6:12]).String(),
		SrcIP:   addr4(ip[12:16]),
		Payload: udp[8:udpLen],
	}, true
}
