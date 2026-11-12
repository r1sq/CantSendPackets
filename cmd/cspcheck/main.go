//go:build windows || linux

// Command cspcheck runs the same checks as the GUI and prints JSON, for diagnosing the
// tool itself or using it over a remote shell, where there's no desktop to show a
// window on. Text appears as the message keys and arguments the GUI translates (see
// frontend/i18n.js).
//
//	cspcheck                               all checks
//	cspcheck -checks monitor,loop          leave out checks unsuitable for this network
//	cspcheck -serve 60s                    be findable and accept speed tests for 60 s
//	cspcheck -serve 60s -speedtest         also test the first instance found
//	cspcheck -speedtest-to 10.0.0.5:47116  test one address, without discovery
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/diag"
	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/peer"
	"github.com/r1sq/CantSendPackets/internal/settings"
	"github.com/r1sq/CantSendPackets/internal/speed"
)

func main() {
	index := flag.Uint("adapter", 0, "adapter index (default: the best one)")
	watch := flag.Duration("watch", 20*time.Second, "how long to run the connectivity monitor")
	checks := flag.String("checks", "monitor,loop,dhcp", "comma-separated checks to run")
	dhcpSocket := flag.Bool("dhcp-socket", false, "use a plain socket for the DHCP check even if capture is available")
	noCapture := flag.Bool("no-capture", false, "run the loop and DHCP checks as without Npcap or root, to compare")
	serve := flag.Duration("serve", 0, "announce this instance and accept speed tests for this long, instead of the checks")
	speedTest := flag.Bool("speedtest", false, "with -serve: run a speed test against the first instance found")
	speedTo := flag.String("speedtest-to", "", "run a speed test against host:port and exit")
	flag.Parse()
	if *noCapture {
		diag.DisableCapture()
	}

	switch {
	case *speedTo != "":
		res, err := speed.Run(context.Background(), *speedTo, speed.Options{}, nil)
		printJSON(map[string]any{"target": *speedTo, "result": res, "error": errText(err)})
		return
	case *serve > 0:
		runServe(*serve, *speedTest)
		return
	}

	list, err := adapter.List()
	if err != nil {
		fatal(err)
	}
	if len(list) == 0 {
		fatal(fmt.Errorf("no active network adapters"))
	}
	selected := list[0]
	for _, a := range list {
		if uint(a.Index) == *index {
			selected = a
		}
	}

	want := strings.Split(*checks, ",")
	ctx := context.Background()
	out := map[string]any{"capture": diag.Capture(), "adapters": list, "selected": selected.Index}
	if slices.Contains(want, "dhcp") {
		if *dhcpSocket {
			out["dhcp"] = diag.RunDHCPSocket(ctx, selected)
		} else {
			out["dhcp"] = diag.RunDHCP(ctx, selected)
		}
	}
	if slices.Contains(want, "loop") {
		out["loop"] = diag.RunLoop(ctx, selected)
	}
	if slices.Contains(want, "monitor") {
		mctx, cancel := context.WithTimeout(ctx, *watch)
		defer cancel()
		var last monitor.Snapshot
		var opts diag.Options
		if path, err := settings.Path(); err == nil {
			if s, err := settings.Load(path); err == nil {
				opts.Override = s.Override()
				opts.Auth = &diag.Auth{}
				opts.Auth.SetTrusted(s.TrustedProxies)
			}
		}
		monitor.Run(mctx, int(selected.Index), diag.Monitor(selected, opts), func(s monitor.Snapshot) { last = s })
		out["monitor"] = last
	}
	printJSON(out)
}

// runServe does what the GUI does in the background.
func runServe(d time.Duration, runTest bool) {
	srv, err := speed.Listen(speed.DefaultPort)
	if err != nil {
		fatal(err)
	}
	defer srv.Close()
	allow := diag.AllowPeer()
	srv.Allow = allow
	var sessions []speed.Session
	srv.OnSession = func(s speed.Session) { sessions = append(sessions, s) }
	go srv.Serve()

	name, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	svc := peer.Start(ctx, peer.Config{Name: name, SpeedPort: srv.Port(), Locals: diag.LocalAnnouncers, Allow: allow})

	out := map[string]any{"name": name, "speedPort": srv.Port(), "announcingFrom": diag.LocalAnnouncers()}
	start := time.Now()
	tested := false
	for ctx.Err() == nil {
		time.Sleep(250 * time.Millisecond)
		found := svc.Peers()
		if len(found) > 0 && out["firstPeerAfterSec"] == nil {
			out["firstPeerAfterSec"] = time.Since(start).Seconds()
		}
		if runTest && !tested {
			for _, p := range found {
				if p.Compatible {
					tested = true
					addr := fmt.Sprintf("%s:%d", p.IP, p.Port)
					res, err := speed.Run(ctx, addr, speed.Options{}, nil)
					out["speedTest"] = map[string]any{"peer": p.Name, "target": addr, "result": res, "error": errText(err)}
					cancel()
					break
				}
			}
		}
		out["peers"] = found
	}
	// Read before stopping: the list is what was there at the end, not at the first
	// sighting, which is what the loop's copy may hold after a long speed test.
	out["peers"] = svc.Peers()
	svc.Wait()
	out["incomingSessions"] = sessions
	printJSON(out)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cspcheck:", err)
	os.Exit(1)
}
