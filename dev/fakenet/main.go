// Command fakenet makes trouble on a test network on purpose, so the checks can be
// seen to catch it. Use it only on a network you're allowed to test.
//
//	fakenet dhcp    -ip A.B.C.D -only MAC [-for 60s]   answer DISCOVERs from one MAC with an OFFER
//	fakenet storm   -ip A.B.C.D [-pps 1500] [-for 12s] send identical broadcasts, like a storm
//	fakenet reflect -ip A.B.C.D [-copies 3] [-for 30s] resend loop probes, as a loop would (raw capture)
//	fakenet loopcable -a IF -b IF [-pps 1500] [-for 15s] join two bridge ports, making a real loop (Linux)
//
// loopcable is for test networks built from veth pairs and a bridge: frames the
// bridge floods out one port come back in through the other, so they circulate as
// on a switch looped by a cable. Unlike a cable it drops what exceeds -pps, so the
// loop can't take the machine down.
//
// Everything is capped: at most 2 minutes, 2000 packets/s (per direction for
// loopcable) and 10 copies. The DHCP
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
		fmt.Fprintln(os.Stderr, "usage: fakenet dhcp|storm|reflect|loopcable [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	ip := fs.String("ip", "", "this machine's address on the test network (required)")
	only := fs.String("only", "", "dhcp: the one client MAC to answer (required)")
	pps := fs.Int("pps", 1500, "storm, loopcable: packets per second")
	ifA := fs.String("a", "", "loopcable: one interface")
	ifB := fs.String("b", "", "loopcable: the other interface")
	copies := fs.Int("copies", 3, "reflect: copies to send of each probe")
	dur := fs.Duration("for", 0, "how long to run")
	fs.Parse(os.Args[2:])

	if *ip == "" && os.Args[1] != "loopcable" {
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
	case "loopcable":
		if *ifA == "" || *ifB == "" {
			fail("-a and -b are required")
		}
		err = runLoopCable(*ifA, *ifB, min(max(*pps, 1), maxPps), limit(15*time.Second))
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
