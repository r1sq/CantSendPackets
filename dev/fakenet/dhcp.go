package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// runDHCP answers DHCPDISCOVERs from one MAC with an OFFER that looks like a home
// router plugged in by mistake. REQUESTs are ignored, so nothing is ever leased.
func runDHCP(ip, only string, d time.Duration) error {
	self, err := netip.ParseAddr(ip)
	if err != nil || !self.Is4() {
		return fmt.Errorf("bad -ip %q", ip)
	}
	want, err := net.ParseMAC(only)
	if err != nil {
		return err
	}
	c, err := net.ListenPacket("udp4", "0.0.0.0:67")
	if err != nil {
		return err
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	deadline := time.Now().Add(d)
	c.SetReadDeadline(deadline)
	fmt.Printf("dhcp: answering %s as %s until %s\n", want, self, deadline.Format("15:04:05"))
	buf := make([]byte, 1500)
	offers := 0
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if strings.Contains(err.Error(), "forcibly closed") { // WSAECONNRESET
				continue
			}
			return err
		}
		p := buf[:n]
		if n < 240 || p[0] != 1 || !strings.EqualFold(net.HardwareAddr(p[28:34]).String(), want.String()) || msgType(p) != 1 {
			continue
		}
		if _, err := c.WriteTo(offer(p, self), dst); err != nil {
			return err
		}
		offers++
		fmt.Printf("dhcp: offer %d to %s (xid %08x, from %s)\n", offers, want, binary.BigEndian.Uint32(p[4:]), from)
	}
	fmt.Printf("dhcp: done, %d offers\n", offers)
	return nil
}

func msgType(p []byte) byte {
	for i := 240; i+1 < len(p); {
		switch p[i] {
		case 0:
			i++
			continue
		case 255:
			return 0
		}
		if p[i] == 53 && p[i+1] == 1 && i+2 < len(p) {
			return p[i+2]
		}
		i += 2 + int(p[i+1])
	}
	return 0
}

func offer(req []byte, self netip.Addr) []byte {
	p := make([]byte, 240, 300)
	p[0], p[1], p[2] = 2, 1, 6
	copy(p[4:8], req[4:8])     // xid
	copy(p[10:12], req[10:12]) // flags
	copy(p[16:20], []byte{192, 168, 77, 100})
	copy(p[28:44], req[28:44]) // chaddr
	binary.BigEndian.PutUint32(p[236:], 0x63825363)
	sid := self.As4()
	opt := func(code byte, v ...byte) { p = append(p, code, byte(len(v))); p = append(p, v...) }
	opt(53, 2) // OFFER
	opt(54, sid[:]...)
	opt(51, 0, 0, 0x0e, 0x10) // 1 hour
	opt(1, 255, 255, 255, 0)
	opt(3, 192, 168, 77, 1)
	opt(6, 192, 168, 77, 1)
	opt(15, []byte("fritz.box")...)
	return append(p, 255)
}
