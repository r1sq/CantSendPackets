// Package loop looks for layer-2 loops from a single endpoint.
//
// An endpoint can't see a switch's forwarding table, so it gathers three kinds
// of evidence, strongest first:
//
//  1. Echo: broadcast a uniquely tagged frame and count how often it comes back.
//     A switch never returns a frame out of the port it arrived on, so seeing it
//     repeatedly means the network forwarded it back to us.
//  2. Repeats: the same frame arriving many times a second. Looped frames are
//     byte-identical on every lap.
//  3. Rate: the adapter's non-unicast packet counters, which need neither a
//     driver nor elevation but can't tell a loop from a chatty device.
package loop

import (
	"bytes"
	"encoding/binary"
	"net"
)

const (
	// EtherType is IEEE's "local experimental" value, so nothing on the network
	// will try to interpret the probes.
	EtherType = 0x88b5

	probeSeqLen = 2
	nonceLen    = 8
)

var (
	probeMagic = []byte("CantSendPackets!")

	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// controlMAC is the 802.1 nearest-bridge group address, which standard
	// switches must not forward. Copies of a frame sent here therefore show how
	// many times the local capture path reports our own transmission, a number
	// Npcap's documentation doesn't pin down, so it's measured instead.
	controlMAC = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

// EncodeProbe builds one probe frame. It's padded to Ethernet's 60-byte minimum.
func EncodeProbe(dst, src net.HardwareAddr, nonce [nonceLen]byte, seq uint16) []byte {
	f := make([]byte, 0, 60)
	f = append(f, dst...)
	f = append(f, src...)
	f = binary.BigEndian.AppendUint16(f, EtherType)
	f = append(f, probeMagic...)
	f = append(f, nonce[:]...)
	f = binary.BigEndian.AppendUint16(f, seq)
	for len(f) < 60 {
		f = append(f, 0)
	}
	return f
}

// probeID identifies which probe a frame is. Only frames with this run's nonce
// count, so another copy of this tool on the segment can't look like an echo.
func probeID(f []byte, nonce [nonceLen]byte) (dst net.HardwareAddr, seq uint16, ok bool) {
	const hdr = 14
	need := hdr + len(probeMagic) + nonceLen + probeSeqLen
	if len(f) < need || binary.BigEndian.Uint16(f[12:]) != EtherType {
		return nil, 0, false
	}
	body := f[hdr:]
	if !bytes.HasPrefix(body, probeMagic) {
		return nil, 0, false
	}
	body = body[len(probeMagic):]
	if !bytes.Equal(body[:nonceLen], nonce[:]) {
		return nil, 0, false
	}
	return net.HardwareAddr(f[:6]), binary.BigEndian.Uint16(body[nonceLen:]), true
}
