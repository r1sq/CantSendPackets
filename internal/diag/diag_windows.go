// Package diag wires the platform-neutral checks to Windows and Npcap.
package diag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/dhcp"
	"github.com/r1sq/CantSendPackets/internal/loop"
	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/npcap"
	"github.com/r1sq/CantSendPackets/internal/peer"
	"github.com/r1sq/CantSendPackets/internal/probe"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/update"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	dnsTestName = "www.msftconnecttest.com"

	// loopFilter is everything the loop check looks at. It's applied in the
	// driver because during a storm most traffic matches nothing else anyway.
	loopFilter = "ether broadcast or ether multicast"
	dhcpFilter = "udp and src port 67 and dst port 68"
)

// NpcapStatus reports whether the deeper tests are available.
type NpcapStatus struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
}

// Npcap checks for the driver.
func Npcap() NpcapStatus {
	v, err := npcap.Version()
	return NpcapStatus{Available: err == nil, Version: v}
}

// openCapture opens a filtered capture on the adapter.
func openCapture(a adapter.Adapter, filter string) (*npcap.Handle, error) {
	h, err := npcap.Open(a.DeviceName)
	if err != nil {
		return nil, err
	}
	if err := h.SetFilter(filter); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// RunLoop performs the loop check, using capture when Npcap is available.
func RunLoop(ctx context.Context, a adapter.Adapter) loop.Report {
	cfg := loop.Config{
		MAC:      a.HardwareAddr(),
		Wireless: a.Kind == "Wi-Fi",
		Counters: func() (uint64, uint64, error) { return probe.Counters(a.Index) },
	}
	rand.Read(cfg.Nonce[:])

	switch {
	case !Npcap().Available:
		cfg.CaptureNote = verdict.M("loop.note.noNpcap")
	case cfg.MAC == nil:
		cfg.CaptureNote = verdict.M("loop.note.noMac")
	default:
		h, err := openCapture(a, loopFilter)
		if err != nil {
			cfg.CaptureNote = verdict.M("loop.note.openFailed", "detail", err.Error())
			break
		}
		defer h.Close()
		cfg.Capture = h
	}
	return loop.Run(ctx, cfg)
}

// pcapTransport speaks DHCP through a raw capture, so it works with no IP
// address, sees the sender's MAC and can't be blocked by the firewall.
type pcapTransport struct {
	h   *npcap.Handle
	mac []byte
}

func (t *pcapTransport) Send(payload []byte) error {
	return t.h.Send(dhcp.EncodeDiscoverFrame(t.mac, payload))
}

func (t *pcapTransport) Recv(timeout time.Duration) (dhcp.ServerReply, error) {
	deadline := time.Now().Add(timeout)
	for {
		f, _, err := t.h.Next()
		if err != nil {
			return dhcp.ServerReply{}, err
		}
		if f != nil {
			if r, ok := dhcp.DecodeServerFrame(f); ok {
				return r, nil
			}
		}
		if !time.Now().Before(deadline) {
			return dhcp.ServerReply{}, dhcp.ErrTimeout
		}
	}
}

func (t *pcapTransport) Close() error {
	t.h.Close()
	return nil
}

// RunDHCP looks for DHCP servers, preferring capture when Npcap is available.
func RunDHCP(ctx context.Context, a adapter.Adapter) dhcp.Report {
	return runDHCP(ctx, a, false)
}

// RunDHCPSocket uses the plain socket even if Npcap is there, to compare the two.
func RunDHCPSocket(ctx context.Context, a adapter.Adapter) dhcp.Report {
	return runDHCP(ctx, a, true)
}

func runDHCP(ctx context.Context, a adapter.Adapter, forceSocket bool) dhcp.Report {
	mac := a.HardwareAddr()
	if mac == nil {
		return dhcp.Evaluate(nil, 0, dhcp.MethodSocket, a.DHCPServer, verdict.Err("err.dhcp.noMac"))
	}
	var xidBytes [4]byte
	rand.Read(xidBytes[:])
	xid := binary.BigEndian.Uint32(xidBytes[:])

	var tr dhcp.Transport
	method := dhcp.MethodCapture
	if !forceSocket && Npcap().Available {
		if h, err := openCapture(a, dhcpFilter); err == nil {
			tr = &pcapTransport{h: h, mac: mac}
		}
	}
	if tr == nil {
		method = dhcp.MethodSocket
		ip := a.PrimaryIPv4()
		if !ip.IsValid() {
			return dhcp.Evaluate(nil, 0, method, a.DHCPServer, verdict.Err("err.dhcp.noIP"))
		}
		st, err := dhcp.NewSocketTransport(dhcp.SocketConfig{BindIP: ip})
		if err != nil {
			return dhcp.Evaluate(nil, 0, method, a.DHCPServer, err)
		}
		tr = st
	}
	defer tr.Close()

	servers, sent, err := dhcp.Probe(ctx, tr, mac, xid, dhcp.Options{})
	if method == dhcp.MethodSocket {
		fillMACs(a, servers)
	}
	return dhcp.Evaluate(servers, sent, method, a.DHCPServer, err)
}

// fillMACs recovers server MACs over ARP, which sockets can't report. A server
// behind a relay won't answer, and is simply left blank.
func fillMACs(a adapter.Adapter, servers []dhcp.Server) {
	for i := range servers {
		if mac, _, err := probe.ARP(a.PrimaryIPv4(), servers[i].ID()); err == nil {
			servers[i].SourceMAC = mac.String()
		}
	}
}

// Web tests. Each confirms the real server answered: a filter or portal can't
// fake Google's empty 204 or Cloudflare's trace page, and over HTTPS it can't even
// try without being caught by certificate verification.
var (
	checkMicrosoft  = probe.WebCheck{URL: "http://www.msftconnecttest.com/connecttest.txt", WantStatus: 200, WantContains: "Microsoft Connect Test"}
	checkCloudflare = probe.WebCheck{URL: "https://www.cloudflare.com/cdn-cgi/trace", WantStatus: 200, WantContains: "h=www.cloudflare.com"}
	checkGoogle     = probe.WebCheck{URL: "https://www.google.com/generate_204", WantStatus: 204}
)

// LocalAnnouncers lists where discovery hellos go: physical adapters only, so a PC
// doesn't announce itself into a VPN or a virtual switch.
func LocalAnnouncers() []peer.Local {
	list, err := adapter.List()
	if err != nil {
		return nil
	}
	var out []peer.Local
	for _, ad := range list {
		if ad.Kind == "Other" {
			continue
		}
		for _, p := range ad.PrefixesV4 {
			targets := []netip.Addr{netip.AddrFrom4([4]byte{255, 255, 255, 255})}
			if b, ok := adapter.BroadcastAddr(p); ok {
				targets = append(targets, b)
			}
			out = append(out, peer.Local{IP: p.Addr(), Targets: targets})
		}
	}
	return out
}

// IsOwnAddress reports whether ip belongs to this PC, on any adapter.
func IsOwnAddress(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	list, err := adapter.List()
	if err != nil {
		return false
	}
	for _, ad := range list {
		for _, v := range ad.IPv4 {
			if v == ip {
				return true
			}
		}
	}
	return false
}

// AllowPeer returns the filter for who may use discovery and the speed test. This
// PC's subnets are cached briefly, because the filter runs for every packet and
// connection from the network, which mustn't each cost a system call.
func AllowPeer() func(netip.Addr) bool {
	var mu sync.Mutex
	var at time.Time
	var cache []netip.Prefix
	return func(ip netip.Addr) bool {
		mu.Lock()
		if time.Since(at) >= 10*time.Second {
			at, cache = time.Now(), nil
			if list, err := adapter.List(); err == nil {
				for _, ad := range list {
					cache = append(cache, ad.PrefixesV4...)
				}
			}
		}
		local := cache
		mu.Unlock()
		return peer.AllowedSource(ip, local)
	}
}

// UpdateFetcher downloads through whatever proxy this network needs, including one
// that wants a login, since an update check behind a proxy is the common case here.
type UpdateFetcher struct {
	Options Options
	mu      sync.Mutex
	byHost  map[string]proxy.Result
}

func (f *UpdateFetcher) detect(rawURL string) proxy.Result {
	u, err := url.Parse(rawURL)
	if err != nil {
		return proxy.Result{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// A PAC file answers per URL, and WPAD is slow, so this asks once per host.
	if r, ok := f.byHost[u.Host]; ok {
		return r
	}
	if f.byHost == nil {
		f.byHost = map[string]proxy.Result{}
	}
	r := proxy.Detect([]string{rawURL}, f.Options.Override)
	// Keyed by host from here on: later URLs on it share this one's route.
	f.byHost[u.Host] = r
	return r
}

// Get implements update.Fetcher.
func (f *UpdateFetcher) Get(ctx context.Context, rawURL string, max int64) ([]byte, error) {
	detected := f.detect(rawURL)
	var route *url.URL
	for _, list := range detected.Routes {
		if len(list) > 0 {
			route = list[0]
			break
		}
	}
	data, err := update.HTTPGet(ctx, rawURL, update.HTTPOptions{Proxy: route}, max)
	if route == nil || !errors.Is(err, update.ErrProxyAuth) {
		return data, err
	}
	auth := f.Options.Auth
	if auth == nil {
		auth = &Auth{}
	}
	user, password, trusted := auth.forHost(route.Host)
	res, err := proxy.Fetch(proxy.FetchOptions{
		URL: rawURL, ProxyHost: route.Host, Level: proxy.LogonPolicy(detected.Source, route.Host, trusted),
		User: user, Password: password, Timeout: 2 * time.Minute, FollowRedirects: true, MaxBody: int(max) + 1,
	})
	if err != nil {
		return nil, err
	}
	if err := update.CheckStatus(res.Status); err != nil {
		return nil, err
	}
	if int64(len(res.Body)) > max {
		return nil, verdict.Err("err.update.tooLarge")
	}
	return res.Body, nil
}

// Auth holds what's known about proxy logins for this session. A typed password
// lives only here, in memory, and is never written anywhere.
type Auth struct {
	mu       sync.Mutex
	host     string
	user     string
	password string
	trusted  []string
}

// SetCredentials stores a typed login for a proxy.
func (a *Auth) SetCredentials(host, user, password string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.host, a.user, a.password = host, user, password
}

// ClearCredentials forgets the typed login.
func (a *Auth) ClearCredentials() { a.SetCredentials("", "", "") }

// SetTrusted replaces the list of proxies approved for Windows logins.
func (a *Auth) SetTrusted(hosts []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trusted = append([]string{}, hosts...)
}

func (a *Auth) forHost(host string) (user, password string, trusted []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.EqualFold(a.host, host) {
		user, password = a.user, a.password
	}
	return user, password, a.trusted
}

// Options are the user's choices that affect monitoring.
type Options struct {
	Override proxy.Override
	Auth     *Auth
}

// router holds the outcome of proxy detection, which runs in the background
// because WPAD can take seconds. Web probes wait for it.
type router struct {
	ready  chan struct{}
	urls   []string
	opts   Options
	result proxy.Result

	mu           sync.Mutex
	active       *url.URL // the proxy that last answered, for failover lists
	authRequired map[string]bool
	authMethod   string
	authRejected bool
	windowsTried bool
}

func newRouter(urls []string, opts Options) *router {
	if opts.Auth == nil {
		opts.Auth = &Auth{}
	}
	r := &router{ready: make(chan struct{}), urls: urls, opts: opts, authRequired: map[string]bool{}}
	go func() {
		r.result = proxy.Detect(urls, opts.Override)
		close(r.ready)
	}()
	return r
}

// webProbe runs one web test. It uses Go's HTTP client until a proxy asks for a
// login. From then on that proxy goes through WinHTTP, which can answer it.
func (r *router) webProbe(ctx context.Context, src netip.Addr, check probe.WebCheck) (time.Duration, error) {
	route := r.route(check.URL)
	if route == nil {
		return probe.WebTest(ctx, src, check, nil)
	}
	host := route.Host
	r.mu.Lock()
	needed := r.authRequired[host]
	r.mu.Unlock()
	if !needed {
		rtt, err := probe.WebTest(ctx, src, check, route)
		if !errors.Is(err, monitor.ErrProxyAuth) {
			return rtt, err
		}
		r.mu.Lock()
		r.authRequired[host] = true
		r.mu.Unlock()
	}

	user, password, trusted := r.opts.Auth.forHost(host)
	level := proxy.LogonPolicy(r.result.Source, host, trusted)
	rtt, err := probe.WebTestWinHTTP(check, host, level, user, password, 8*time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()
	rejected := errors.Is(err, monitor.ErrProxyAuth)
	r.authRejected = rejected && user != ""
	// Only the full attempt counts: Windows' intranet default may decline a proxy
	// that would accept the login once the user approves it.
	r.windowsTried = rejected && user == "" && level == proxy.LogonAlways
	if !rejected {
		switch {
		case err != nil:
			// Some other failure says nothing about the login either way.
		case user != "":
			r.authMethod = "typed"
		default:
			r.authMethod = "windows"
		}
	} else {
		r.authMethod = ""
	}
	return rtt, err
}

func (r *router) wait(ctx context.Context) {
	select {
	case <-r.ready:
	case <-ctx.Done():
	}
}

func (r *router) isReady() bool {
	select {
	case <-r.ready:
		return true
	default:
		return false
	}
}

// route picks the proxy for a URL: the one known to answer if it serves this URL,
// otherwise the first listed. nil means direct.
func (r *router) route(rawURL string) *url.URL {
	list := r.result.Routes[rawURL]
	if len(list) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range list {
		if r.active != nil && u.Host == r.active.Host {
			return u
		}
	}
	return list[0]
}

func (r *router) setActive(u *url.URL) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = u
}

func (r *router) address() string {
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if active != nil {
		return active.Host
	}
	if list := r.result.Primary(r.urls); len(list) > 0 {
		return list[0].Host
	}
	return ""
}

func (r *router) state() monitor.ProxyState {
	if !r.isReady() {
		return monitor.ProxyState{Detecting: true}
	}
	r.mu.Lock()
	required := len(r.authRequired) > 0
	method, rejected, windows := r.authMethod, r.authRejected, r.windowsTried
	r.mu.Unlock()
	return monitor.ProxyState{
		Active:              len(r.result.Primary(r.urls)) > 0,
		Address:             r.address(),
		Source:              string(r.result.Source),
		PACURL:              r.result.PACURL,
		Issue:               r.result.Issue,
		AuthRequired:        required,
		AuthMethod:          method,
		AuthRejected:        rejected,
		WindowsLoginOffered: windows,
	}
}

// Monitor builds the monitor's configuration for an adapter: everything along the
// path, nearest first, all sourced from this adapter's address. Proxy detection
// starts here, so restarting the monitor re-detects.
func Monitor(a adapter.Adapter, opts Options) monitor.Config {
	src := a.PrimaryIPv4()
	var out []monitor.Target

	ping := func(id string, group monitor.Group, label verdict.Msg, dst netip.Addr, advisory bool) monitor.Target {
		return monitor.Target{
			ID: id, Group: group, Label: label, Addr: dst.String(), Kind: "ping", Advisory: advisory,
			Interval: 2 * time.Second, Timeout: 1500 * time.Millisecond,
			Probe: func(ctx context.Context) (time.Duration, error) {
				return probe.Ping(src, dst, 1000*time.Millisecond)
			},
		}
	}

	if gw := a.GatewayV4(); gw.IsValid() {
		out = append(out, ping("gw-ping", monitor.GroupGateway, verdict.M("target.gateway"), gw, false))
		out = append(out, monitor.Target{
			ID: "gw-arp", Group: monitor.GroupGateway, Label: verdict.M("target.gatewayArp"), Addr: gw.String(), Kind: "arp",
			Interval: 10 * time.Second, Timeout: 5 * time.Second,
			Probe: func(ctx context.Context) (time.Duration, error) {
				_, rtt, err := probe.ARP(src, gw)
				return rtt, err
			},
		})
	}
	for i, d := range a.DNS {
		out = append(out, monitor.Target{
			ID: "dns-" + d.String(), Group: monitor.GroupDNS, Label: verdict.M("target.dns", "n", i+1), Addr: d.String(), Kind: "dns",
			Interval: 3 * time.Second, Timeout: 2 * time.Second,
			Probe: func(ctx context.Context) (time.Duration, error) {
				return probe.DNS(ctx, src, d, 53, dnsTestName)
			},
		})
	}
	if !src.IsValid() {
		return monitor.Config{Targets: out}
	}

	urls := []string{checkMicrosoft.URL, checkCloudflare.URL, checkGoogle.URL}
	r := newRouter(urls, opts)

	web := func(id string, label verdict.Msg, check probe.WebCheck, host, kind string, interval time.Duration) monitor.Target {
		return monitor.Target{
			ID: id, Group: monitor.GroupInternet, Label: label, Addr: host, Kind: kind,
			Interval: interval, Timeout: 8 * time.Second,
			Prepare: r.wait,
			Describe: func() (string, bool) {
				return host, r.isReady() && r.route(check.URL) != nil
			},
			Probe: func(ctx context.Context) (time.Duration, error) {
				return r.webProbe(ctx, src, check)
			},
		}
	}

	out = append(out,
		monitor.Target{
			ID: "proxy", Group: monitor.GroupProxy, Label: verdict.M("target.proxy"), Kind: "tcp", Optional: true,
			Interval: 5 * time.Second, Timeout: 6 * time.Second,
			Prepare:  r.wait,
			Describe: func() (string, bool) { return r.address(), false },
			Probe: func(ctx context.Context) (time.Duration, error) {
				list := r.result.Primary(urls)
				if len(list) == 0 {
					return 0, monitor.ErrNotApplicable
				}
				// Windows moves on to the next proxy of a list if one is dead.
				var firstErr error
				for _, u := range list {
					one, cancel := context.WithTimeout(ctx, 2*time.Second)
					rtt, err := probe.TCP(one, src, u.Host)
					cancel()
					if err == nil {
						r.setActive(u)
						return rtt, nil
					}
					if firstErr == nil {
						firstErr = err
					}
				}
				return 0, firstErr
			},
		},
		web("net-cf-web", verdict.M("target.cloudflareWeb"), checkCloudflare, "www.cloudflare.com", "https", 15*time.Second),
		web("net-g-web", verdict.M("target.googleWeb"), checkGoogle, "www.google.com", "https", 15*time.Second),
		web("net-ms-web", verdict.M("target.microsoftWeb"), checkMicrosoft, "msftconnecttest.com", "http", 30*time.Second),
		ping("net-cf", monitor.GroupInternet, verdict.M("target.cloudflarePing"), netip.MustParseAddr("1.1.1.1"), true),
		ping("net-g", monitor.GroupInternet, verdict.M("target.googlePing"), netip.MustParseAddr("8.8.8.8"), true),
	)
	return monitor.Config{Targets: out, Proxy: r.state}
}
