//go:build windows

// Command CantSendPackets is a small Windows network diagnostics app.
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"strconv"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailswin "github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/sys/windows"

	"github.com/r1sq/CantSendPackets/internal/update"
)

//go:embed all:frontend
var frontendFiles embed.FS

// sourceVersion is the version the source is at; see VERSION and CHANGELOG.md.
//
//go:embed VERSION
var sourceVersion string

// version is the release tag, set when building a release. Any other build is
// "vX.Y.Z-dev" (see update.BuildVersion), which never updates itself.
var version string

func main() {
	version = update.BuildVersion(sourceVersion, version)
	waitForPredecessor()
	assets, err := fs.Sub(frontendFiles, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	app := &App{}
	err = wails.Run(&options.App{
		Title:            "CantSendPackets",
		Width:            1120,
		Height:           760,
		MinWidth:         940,
		MinHeight:        640,
		Frameless:        true,
		BackgroundColour: &options.RGBA{R: 0x11, G: 0x12, B: 0x13, A: 0xff},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []any{app},
		Windows:          &wailswin.Options{Theme: wailswin.Dark},
		// One window per Windows session: starting it again brings that one
		// forward. Other users on the same PC (a terminal server) get their own.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "CantSendPackets-5d3f8c2a-7b14-4e9b-a0c6-1f2e8d9b4c71",
			OnSecondInstanceLaunch: app.onSecondInstance,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}

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
