// Command fakenet makes trouble on a test network on purpose, so the checks can be
// seen to catch it. Use it only on a network you're allowed to test.
//
//	fakenet dhcp    -ip A.B.C.D -only MAC [-for 60s]   answer DISCOVERs from one MAC with an OFFER
//	fakenet storm   -ip A.B.C.D [-pps 1500] [-for 12s] send identical broadcasts, like a storm
//	fakenet reflect -ip A.B.C.D [-copies 3] [-for 30s] resend loop probes, as a loop would (Npcap)
//
// Everything is capped: at most 2 minutes, 2000 packets/s and 10 copies. The DHCP
// responder never sends an ACK, so no one can get a lease from it, and it ignores
// every client but the one named.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	maxDuration = 2 * time.Minute
	maxPps      = 2000
	maxCopies   = 10
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakenet dhcp|storm|reflect [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	ip := fs.String("ip", "", "this machine's address on the test network (required)")
	only := fs.String("only", "", "dhcp: the one client MAC to answer (required)")
	pps := fs.Int("pps", 1500, "storm: packets per second")
	copies := fs.Int("copies", 3, "reflect: copies to send of each probe")
	dur := fs.Duration("for", 0, "how long to run")
	fs.Parse(os.Args[2:])

	if *ip == "" {
		fail("-ip is required")
	}
	limit := func(def time.Duration) time.Duration {
		d := *dur
		if d == 0 {
			d = def
		}
		return min(d, maxDuration)
	}
	var err error
	switch os.Args[1] {
	case "dhcp":
		if *only == "" {
			fail("-only is required")
		}
		err = runDHCP(*ip, *only, limit(60*time.Second))
	case "storm":
		err = runStorm(*ip, min(max(*pps, 1), maxPps), limit(12*time.Second))
	case "reflect":
		err = runReflect(*ip, min(max(*copies, 1), maxCopies), limit(30*time.Second))
	default:
		fail("unknown mode " + os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "fakenet:", msg)
	os.Exit(1)
}
