package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/r1sq/CantSendPackets/internal/rawcap"
)

// runLoopCable copies every frame arriving on one interface out of the other, both
// ways, at most pps per direction. Attached to two ports of the same bridge, that's
// a loop.
func runLoopCable(a, b string, pps int, d time.Duration) error {
	ha, err := rawcap.Open(a, rawcap.Options{InboundOnly: true})
	if err != nil {
		return err
	}
	defer ha.Close()
	hb, err := rawcap.Open(b, rawcap.Options{InboundOnly: true})
	if err != nil {
		return err
	}
	defer hb.Close()

	fmt.Printf("loopcable: %s <-> %s, at most %d frames/s each way, for %s\n", a, b, pps, d)
	deadline := time.Now().Add(d)
	var copied, dropped atomic.Int64
	pipe := func(from, to *rawcap.Handle) error {
		window, inWindow := time.Now(), 0
		for time.Now().Before(deadline) {
			f, _, err := from.Next()
			if err != nil {
				return err
			}
			if f == nil {
				continue
			}
			if now := time.Now(); now.Sub(window) >= time.Second {
				window, inWindow = now, 0
			}
			if inWindow >= pps {
				dropped.Add(1)
				continue
			}
			inWindow++
			if err := to.Send(f); err != nil {
				return err
			}
			copied.Add(1)
		}
		return nil
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = pipe(ha, hb) }()
	go func() { defer wg.Done(); errs[1] = pipe(hb, ha) }()
	wg.Wait()
	fmt.Printf("loopcable: done, %d frames copied, %d dropped over the limit\n", copied.Load(), dropped.Load())
	if errs[0] != nil {
		return errs[0]
	}
	return errs[1]
}
