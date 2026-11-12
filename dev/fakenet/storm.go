package main

import (
	"fmt"
	"net"
	"time"
)

// runStorm sends the same small broadcast over and over, which is what a loop
// looks like from a port on it: a high broadcast rate made of repeating frames.
func runStorm(ip string, pps int, d time.Duration) error {
	src, err := net.ResolveUDPAddr("udp4", ip+":0")
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", src)
	if err != nil {
		return err
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 9} // discard
	payload := []byte("fakenet storm test, CantSendPackets")
	fmt.Printf("storm: %d packets/s for %s from %s\n", pps, d, ip)
	start := time.Now()
	sent := 0
	for time.Since(start) < d {
		// Send in 10 ms batches; the target rate is kept on average.
		due := int(time.Since(start).Seconds()*float64(pps)) + 1
		for ; sent < due; sent++ {
			if _, err := c.WriteTo(payload, dst); err != nil {
				return err
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Printf("storm: done, %d packets in %s\n", sent, time.Since(start).Round(time.Millisecond))
	return nil
}
