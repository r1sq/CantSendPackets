//go:build windows || linux

// Command CantSendPackets is a small network diagnostics app for Windows and Linux.
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

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
	if runPrivilegedCheck() {
		return // ran one check with elevated rights for a window that asked; see main_linux.go
	}
	waitForPredecessor()
	assets, err := fs.Sub(frontendFiles, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	app := &App{}
	opts := &options.App{
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
		// One window per user session: starting it again brings that one forward.
		// Other users on the same PC (a terminal server) get their own.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "CantSendPackets-5d3f8c2a-7b14-4e9b-a0c6-1f2e8d9b4c71",
			OnSecondInstanceLaunch: app.onSecondInstance,
		},
	}
	platformOptions(opts)
	exitOnSignal()
	if err := wails.Run(opts); err != nil {
		log.Fatal(err)
	}
}

// exitOnSignal makes sure SIGTERM and SIGINT end the program. Wails catches them
// and asks the GUI toolkit to quit, but on Linux that request is lost if it comes
// before GTK's main loop runs (seen on a slow CI machine), and the process then
// never exits. Wails gets a moment to shut down cleanly; then this ends it.
// Settings are saved as they change, so nothing waits on a clean exit.
func exitOnSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}()
}
