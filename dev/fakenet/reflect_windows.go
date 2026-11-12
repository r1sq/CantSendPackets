package main

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/npcap"
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
	h, err := npcap.Open(dev)
	if err != nil {
		return err
	}
	defer h.Close()
	// Only probes, not the control frame: that one measures the capture path itself.
	if err := h.SetFilter("ether proto 0x88b5 and not ether dst 01:80:c2:00:00:0e"); err != nil {
		return err
	}
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
		if f == nil {
			continue
		}
		k := sha256.Sum256(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		frame := append([]byte(nil), f...)
		for range copies {
			if sent >= maxSent {
				break
			}
			if err := h.Send(frame); err != nil {
				return err
			}
			sent++
		}
		fmt.Printf("reflect: probe %x... sent %d copies\n", frame[30:38], copies)
	}
	fmt.Printf("reflect: done, %d frames sent\n", sent)
	return nil
}
