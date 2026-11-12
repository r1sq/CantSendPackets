//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/dhcp"
	"github.com/r1sq/CantSendPackets/internal/diag"
	"github.com/r1sq/CantSendPackets/internal/loop"
	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/peer"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/settings"
	"github.com/r1sq/CantSendPackets/internal/speed"
	"github.com/r1sq/CantSendPackets/internal/update"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	npcapURL = "https://npcap.com/#download"
	repoURL  = "https://github.com/" + update.Repo
)

// App is the surface the frontend calls. Its exported methods are the whole API.
type App struct {
	ctx context.Context

	mu          sync.Mutex
	stopMonitor context.CancelFunc

	settingsPath string
	settings     settings.Settings
	auth         diag.Auth

	peers       *peer.Service
	speedServer *speed.Server
	stopPeers   context.CancelFunc
	peerErr     verdict.Msg

	speedCancel context.CancelFunc

	update updateState
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.settings = settings.Default()
	if path, err := settings.Path(); err == nil {
		a.settingsPath = path
		// An unusable file gives the defaults, and the app still starts.
		a.settings, _ = settings.Load(path)
	}
	a.auth.SetTrusted(a.settings.TrustedProxies)
	if a.settings.Discoverable {
		a.startDiscovery()
	}
	if exe, err := currentExe(); err == nil {
		update.Cleanup(exe)
	}
	go a.updateLoop()
}

func (a *App) shutdown(context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopMonitor != nil {
		a.stopMonitor()
	}
	if a.speedCancel != nil {
		a.speedCancel()
	}
	a.stopDiscoveryLocked()
}

// Npcap reports whether the deeper tests are available.
func (a *App) Npcap() diag.NpcapStatus { return diag.Npcap() }

// Adapters lists usable adapters, best first.
func (a *App) Adapters() ([]adapter.Adapter, error) {
	list, err := adapter.List()
	if list == nil {
		list = []adapter.Adapter{}
	}
	return list, err
}

func find(index uint32) (adapter.Adapter, error) {
	list, err := adapter.List()
	if err != nil {
		return adapter.Adapter{}, err
	}
	for _, ad := range list {
		if ad.Index == index {
			return ad, nil
		}
	}
	return adapter.Adapter{}, fmt.Errorf("adapter %d is no longer available", index)
}

// StartMonitor replaces any running monitor with one for this adapter. Results
// arrive as "monitor" events.
func (a *App) StartMonitor(index uint32) error {
	ad, err := find(index)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(a.ctx)

	a.mu.Lock()
	if a.stopMonitor != nil {
		a.stopMonitor()
	}
	a.stopMonitor = cancel
	a.mu.Unlock()

	a.mu.Lock()
	opts := diag.Options{Override: a.settings.Override(), Auth: &a.auth}
	a.mu.Unlock()
	go monitor.Run(ctx, int(index), diag.Monitor(ad, opts), func(s monitor.Snapshot) {
		runtime.EventsEmit(a.ctx, "monitor", s)
	})
	return nil
}

// RunLoopCheck looks for a layer-2 loop on the adapter's segment.
func (a *App) RunLoopCheck(index uint32) (loop.Report, error) {
	ad, err := find(index)
	if err != nil {
		return loop.Report{}, err
	}
	return diag.RunLoop(a.ctx, ad), nil
}

// RunDHCPCheck looks for DHCP servers on the adapter's segment.
func (a *App) RunDHCPCheck(index uint32) (dhcp.Report, error) {
	ad, err := find(index)
	if err != nil {
		return dhcp.Report{}, err
	}
	return diag.RunDHCP(a.ctx, ad), nil
}

// OpenNpcapPage opens Npcap's download page. URLs are fixed here rather than taken
// from the frontend, so the page can't be made to open anything else.
func (a *App) OpenNpcapPage() { runtime.BrowserOpenURL(a.ctx, npcapURL) }

// OpenRepoPage opens the project's GitHub page.
func (a *App) OpenRepoPage() { runtime.BrowserOpenURL(a.ctx, repoURL) }

// ---------------------------------------------------------------- settings

// Settings returns the current settings.
func (a *App) Settings() settings.Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// SaveSettings validates and applies settings. It returns a message if they were
// refused, or an empty one on success. The frontend restarts monitoring afterwards.
func (a *App) SaveSettings(s settings.Settings) verdict.Msg {
	if m := proxy.CheckOverride(s.Override()); !m.IsZero() {
		return m
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// The approved list isn't edited through this form.
	s.TrustedProxies = a.settings.TrustedProxies
	if err := a.saveLocked(s); err != nil {
		return verdict.M("settings.err.saveFailed", "detail", err.Error())
	}
	switch {
	case s.Discoverable && a.peers == nil:
		a.startDiscoveryLocked()
	case !s.Discoverable:
		a.stopDiscoveryLocked()
	}
	a.emitPeersLocked()
	return verdict.Msg{}
}

func (a *App) saveLocked(s settings.Settings) error {
	if a.settingsPath != "" {
		if err := settings.Save(a.settingsPath, s); err != nil {
			return err
		}
	}
	a.settings = s
	a.auth.SetTrusted(s.TrustedProxies)
	return nil
}

// SetProxyCredentials stores a login for this session only.
func (a *App) SetProxyCredentials(host, user, password string) {
	a.auth.SetCredentials(host, user, password)
}

// ClearProxyCredentials forgets a typed login.
func (a *App) ClearProxyCredentials() { a.auth.ClearCredentials() }

// TrustProxy approves a proxy for Windows logins and remembers that.
func (a *App) TrustProxy(host string) verdict.Msg {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.settings
	s.TrustedProxies = append(append([]string{}, s.TrustedProxies...), host)
	if err := a.saveLocked(s); err != nil {
		return verdict.M("settings.err.saveFailed", "detail", err.Error())
	}
	return verdict.Msg{}
}

// ---------------------------------------------------------------- updates

const (
	waitPIDFlag         = "--wait-pid"
	updateCheckInterval = 24 * time.Hour
	// updateCheckDelay keeps the check out of the way of the first results.
	updateCheckDelay = 10 * time.Second
)

type updateState struct {
	checking   bool
	installing bool
	upToDate   bool
	available  *update.Available
	err        verdict.Msg
}

// UpdateStatus is what the UI shows about updates.
type UpdateStatus struct {
	Current    string      `json:"current"`
	Enabled    bool        `json:"enabled"`
	Checking   bool        `json:"checking"`
	Installing bool        `json:"installing"`
	UpToDate   bool        `json:"upToDate"`
	Available  string      `json:"available"`
	Error      verdict.Msg `json:"error"`
}

func updatesEnabled() bool {
	_, ok := update.ParseVersion(version)
	return ok && update.PublicKey() != nil
}

func (a *App) updateStatusLocked() UpdateStatus {
	st := UpdateStatus{
		Current: version, Enabled: updatesEnabled(), Checking: a.update.checking,
		Installing: a.update.installing, UpToDate: a.update.upToDate, Error: a.update.err,
	}
	if a.update.available != nil {
		st.Available = a.update.available.Version
	}
	return st
}

func (a *App) emitUpdateLocked() {
	runtime.EventsEmit(a.ctx, "update", a.updateStatusLocked())
}

// UpdateStatus returns the current state.
func (a *App) UpdateStatus() UpdateStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.updateStatusLocked()
}

func (a *App) updateLoop() {
	if !updatesEnabled() {
		return
	}
	timer := time.NewTimer(updateCheckDelay)
	defer timer.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-timer.C:
		}
		a.mu.Lock()
		enabled := a.settings.CheckUpdates
		a.mu.Unlock()
		if enabled {
			a.checkForUpdate(false)
		}
		timer.Reset(updateCheckInterval)
	}
}

func (a *App) fetcher() *diag.UpdateFetcher {
	a.mu.Lock()
	defer a.mu.Unlock()
	return &diag.UpdateFetcher{Options: diag.Options{Override: a.settings.Override(), Auth: &a.auth}}
}

func assetName() string {
	return "CantSendPackets-windows-" + goruntime.GOARCH + ".exe"
}

// checkForUpdate looks for a release. A background check keeps quiet on failure, as
// being offline isn't worth interrupting anyone for; a requested one reports it.
func (a *App) checkForUpdate(requested bool) {
	a.mu.Lock()
	if a.update.checking || a.update.installing {
		a.mu.Unlock()
		return
	}
	a.update.checking, a.update.err = true, verdict.Msg{}
	a.emitUpdateLocked()
	a.mu.Unlock()

	found, err := update.Check(a.ctx, a.fetcher(), version, assetName(), update.PublicKey())

	a.mu.Lock()
	defer a.mu.Unlock()
	a.update.checking = false
	switch {
	case err != nil && requested:
		a.update.err = verdict.AsMsg(err)
	case err == nil:
		a.update.available, a.update.upToDate = found, found == nil
	}
	a.emitUpdateLocked()
}

// CheckForUpdate looks for a new release now. The result arrives as an "update" event.
func (a *App) CheckForUpdate() { go a.checkForUpdate(true) }

// OpenReleasePage opens the available release's page. The address comes from the
// signed version, not from anything the frontend passes in.
func (a *App) OpenReleasePage() {
	a.mu.Lock()
	avail := a.update.available
	a.mu.Unlock()
	if avail != nil {
		runtime.BrowserOpenURL(a.ctx, avail.PageURL)
	}
}

// InstallUpdate downloads, verifies and installs the available release, then restarts
// into it. Failures arrive as an "update" event, and the running copy stays as it was.
func (a *App) InstallUpdate() {
	a.mu.Lock()
	avail := a.update.available
	if avail == nil || a.update.installing {
		a.mu.Unlock()
		return
	}
	a.update.installing, a.update.err = true, verdict.Msg{}
	a.emitUpdateLocked()
	a.mu.Unlock()

	go func() {
		err := a.installUpdate(avail)
		if err == nil {
			runtime.Quit(a.ctx)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.update.installing = false
		a.update.err = verdict.AsMsg(err)
		a.emitUpdateLocked()
	}()
}

func (a *App) installUpdate(avail *update.Available) error {
	exe, err := currentExe()
	if err != nil {
		return verdict.Err("err.update.install", "detail", err.Error())
	}
	data, err := update.Download(a.ctx, a.fetcher(), avail)
	if err != nil {
		return err
	}
	rollback, err := update.Install(exe, data)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, waitPIDFlag, strconv.Itoa(os.Getpid()))
	if err := cmd.Start(); err != nil {
		// Antivirus software refusing an unsigned download ends up here.
		if rbErr := rollback(); rbErr != nil {
			return errors.Join(verdict.Err("err.update.start", "detail", err.Error()), rbErr)
		}
		return verdict.Err("err.update.start", "detail", err.Error())
	}
	return nil
}

func currentExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// ---------------------------------------------------------------- other instances

// PeerStatus is what the speed test card shows.
type PeerStatus struct {
	Visible bool        `json:"visible"`
	Name    string      `json:"name"`
	Port    int         `json:"port"`
	Peers   []peer.Peer `json:"peers"`
	Error   verdict.Msg `json:"error"`
}

func (a *App) startDiscovery() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startDiscoveryLocked()
}

func (a *App) startDiscoveryLocked() {
	srv, err := speed.Listen(speed.DefaultPort)
	if err != nil {
		a.peerErr = verdict.M("err.speed.listen", "detail", err.Error())
		return
	}
	a.peerErr = verdict.Msg{}
	allow := diag.AllowPeer()
	srv.Allow = allow
	srv.OnSession = func(s speed.Session) { runtime.EventsEmit(a.ctx, "speed-incoming", s) }
	go srv.Serve()

	ctx, cancel := context.WithCancel(a.ctx)
	a.speedServer, a.stopPeers = srv, cancel
	a.peers = peer.Start(ctx, peer.Config{
		Name:      hostname(),
		SpeedPort: srv.Port(),
		Locals:    diag.LocalAnnouncers,
		Allow:     allow,
		OnChange: func([]peer.Peer) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.emitPeersLocked()
		},
	})
}

func (a *App) stopDiscoveryLocked() {
	if a.stopPeers != nil {
		a.stopPeers()
		a.stopPeers = nil
	}
	if a.speedServer != nil {
		// Closing waits for running streams, whose deadlines bound it.
		go a.speedServer.Close()
		a.speedServer = nil
	}
	a.peers = nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "?"
	}
	return name
}

func (a *App) statusLocked() PeerStatus {
	st := PeerStatus{Visible: a.peers != nil, Name: hostname(), Peers: []peer.Peer{}, Error: a.peerErr}
	if a.peers != nil {
		st.Peers = a.peers.Peers()
	}
	if a.speedServer != nil {
		st.Port = a.speedServer.Port()
	}
	return st
}

func (a *App) emitPeersLocked() {
	runtime.EventsEmit(a.ctx, "peers", a.statusLocked())
}

// PeerStatus returns the current list.
func (a *App) PeerStatus() PeerStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statusLocked()
}

// ProbePeer looks for an instance at a specific address, for networks broadcasts
// don't reach. If one answers, it joins the list.
func (a *App) ProbePeer(address string) verdict.Msg {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return verdict.M("err.peer.badAddress")
	}
	a.mu.Lock()
	svc := a.peers
	a.mu.Unlock()
	if svc == nil || !svc.Probe(ip) {
		return verdict.M("err.peer.probeFailed")
	}
	return verdict.Msg{}
}

// SpeedOutcome is a finished speed test. Errors travel as a message rather than a
// rejected promise, so they stay translatable.
type SpeedOutcome struct {
	Result    speed.Result `json:"result"`
	Error     verdict.Msg  `json:"error"`
	Cancelled bool         `json:"cancelled"`
}

// RunSpeedTest measures the connection to another instance. Progress arrives as
// "speed-progress" events.
func (a *App) RunSpeedTest(peerID string) SpeedOutcome {
	a.mu.Lock()
	svc := a.peers
	if a.speedCancel != nil {
		a.mu.Unlock()
		return SpeedOutcome{Error: verdict.M("err.speed.alreadyRunning")}
	}
	if svc == nil {
		a.mu.Unlock()
		return SpeedOutcome{Error: verdict.M("err.speed.gone")}
	}
	target, ok := svc.Find(peerID)
	if !ok {
		a.mu.Unlock()
		return SpeedOutcome{Error: verdict.M("err.speed.gone")}
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.speedCancel = cancel
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.speedCancel = nil
		a.mu.Unlock()
		cancel()
	}()

	addr := net.JoinHostPort(target.IP.String(), fmt.Sprint(target.Port))
	res, err := speed.Run(ctx, addr, speed.Options{}, func(p speed.Progress) {
		runtime.EventsEmit(a.ctx, "speed-progress", map[string]any{
			"peerId": peerID, "direction": p.Direction, "mbps": p.Mbps, "fraction": p.Fraction,
		})
	})
	switch {
	case errors.Is(err, context.Canceled):
		return SpeedOutcome{Cancelled: true}
	case err != nil:
		return SpeedOutcome{Error: verdict.AsMsg(err)}
	}
	return SpeedOutcome{Result: res}
}

// CancelSpeedTest stops a running test.
func (a *App) CancelSpeedTest() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.speedCancel != nil {
		a.speedCancel()
	}
}
