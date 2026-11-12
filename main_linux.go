package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/dhcp"
	"github.com/r1sq/CantSendPackets/internal/diag"
	"github.com/r1sq/CantSendPackets/internal/loop"
)

//go:embed appicon.png
var appIcon []byte

func platformOptions(o *options.App) {
	o.Linux = &linux.Options{
		Icon:             appIcon,
		ProgramName:      "CantSendPackets",
		WebviewGpuPolicy: linux.WebviewGpuPolicyOnDemand,
	}
}

// waitForPredecessor lets the copy that just installed an update finish quitting, so
// this one gets the speed test port and the single-instance lock.
func waitForPredecessor() {
	if len(os.Args) != 3 || os.Args[1] != waitPIDFlag {
		return
	}
	pid, err := strconv.Atoi(os.Args[2])
	if err != nil || pid <= 1 {
		return
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The loop and DHCP checks need raw sockets. Rather than run the whole window as
// root, the window asks pkexec to start this program again in a mode that runs
// one check, prints its report as JSON and exits, before any GUI is set up.
const privilegedFlag = "--privileged-check"

func runPrivilegedCheck() bool {
	if len(os.Args) < 2 || os.Args[1] != privilegedFlag {
		return false
	}
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	index, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		os.Exit(2)
	}
	ad, err := find(uint32(index))
	if err != nil {
		os.Exit(3)
	}
	var report any
	switch os.Args[2] {
	case "loop":
		report = diag.RunLoop(context.Background(), ad)
	case "dhcp":
		report = diag.RunDHCP(context.Background(), ad)
	default:
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		os.Exit(1)
	}
	return true
}

// elevated runs one check through pkexec, which asks for an administrator's
// password. It reports false if that isn't possible or the user declines.
func elevated(ctx context.Context, check string, index uint32, out any) bool {
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return false
	}
	exe, err := currentExe()
	if err != nil {
		return false
	}
	b, err := exec.CommandContext(ctx, pkexec, exe, privilegedFlag, check, strconv.FormatUint(uint64(index), 10)).Output()
	if err != nil {
		return false // declined (126), no authentication agent (127), or failed
	}
	return json.Unmarshal(b, out) == nil
}

// runLoop uses raw capture directly if this process has it (root, or setcap),
// otherwise asks for it, and falls back to counters if that's declined.
func runLoop(ctx context.Context, ad adapter.Adapter) loop.Report {
	if diag.Capture().Available {
		return diag.RunLoop(ctx, ad)
	}
	var r loop.Report
	if elevated(ctx, "loop", ad.Index, &r) {
		return r
	}
	return diag.RunLoop(ctx, ad)
}

func runDHCP(ctx context.Context, ad adapter.Adapter) dhcp.Report {
	if diag.Capture().Available {
		return diag.RunDHCP(ctx, ad)
	}
	var r dhcp.Report
	if elevated(ctx, "dhcp", ad.Index, &r) {
		return r
	}
	return diag.RunDHCP(ctx, ad)
}
