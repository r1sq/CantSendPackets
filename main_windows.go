package main

import (
	"context"
	"os"
	"strconv"

	"github.com/wailsapp/wails/v2/pkg/options"
	wailswin "github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/sys/windows"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/dhcp"
	"github.com/r1sq/CantSendPackets/internal/diag"
	"github.com/r1sq/CantSendPackets/internal/loop"
)

func platformOptions(o *options.App) {
	o.Windows = &wailswin.Options{Theme: wailswin.Dark}
}

// runPrivilegedCheck: Windows needs no elevation, Npcap does the privileged part.
func runPrivilegedCheck() bool { return false }

// waitForPredecessor lets the copy that just installed an update finish quitting, so
// this one gets the speed test port and the single-instance lock. It starts
// regardless if that takes too long, though while the old copy still holds the lock
// this one then only brings its window forward.
func waitForPredecessor() {
	if len(os.Args) != 3 || os.Args[1] != waitPIDFlag {
		return
	}
	pid, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return // already gone
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, 30000)
}

// Checks start at once on Windows: Npcap needs no password, so there's no phase to report.
func runLoop(ctx context.Context, ad adapter.Adapter, _ func(string)) loop.Report {
	return diag.RunLoop(ctx, ad)
}

func runDHCP(ctx context.Context, ad adapter.Adapter, _ func(string)) dhcp.Report {
	return diag.RunDHCP(ctx, ad)
}
