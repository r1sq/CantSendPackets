package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/rawcap"
)

// runReflect sends extra copies of each loop probe it sees, as a loop would bring
// them back. Each distinct frame is reflected once, so its own copies (which the
// capture also sees) can't set off a real storm, and the total is capped.
func runReflect(ip string, copies int, d time.Duration) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	list, err := adapter.List()
	if err != nil {
		return err
	}
	var dev string
	for _, a := range list {
		for _, v := range a.IPv4 {
			if v == addr {
				dev = a.DeviceName
			}
		}
	}
	if dev == "" {
		return fmt.Errorf("no adapter has %s", ip)
	}
	h, err := rawcap.Open(dev, rawcap.Options{})
	if err != nil {
		return err
	}
	defer h.Close()
	control := []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	const maxSent = 300
	seen := map[[32]byte]bool{}
	sent := 0
	deadline := time.Now().Add(d)
	fmt.Printf("reflect: %d copies of each probe for %s\n", copies, d)
	for time.Now().Before(deadline) && sent < maxSent {
		f, _, err := h.Next()
		if err != nil {
			return err
		}
		// Only probes (EtherType 0x88b5), not the control frame: that one
		// measures the capture path itself.
		if len(f) < 38 || f[12] != 0x88 || f[13] != 0xb5 || bytes.Equal(f[:6], control) {
			continue
		}
		k := sha256.Sum256(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		for range copies {
			if sent >= maxSent {
				break
			}
			if err := h.Send(f); err != nil {
				return err
			}
			sent++
		}
		fmt.Printf("reflect: probe %x... sent %d copies\n", f[30:38], copies)
	}
	fmt.Printf("reflect: done, %d frames sent\n", sent)
	return nil
}
