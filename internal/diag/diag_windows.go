package diag

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/npcap"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/update"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	// loopFilter is everything the loop check looks at. It's applied in the
	// driver because during a storm most traffic matches nothing else anyway.
	loopFilter = "ether broadcast or ether multicast"
	dhcpFilter = "udp and src port 67 and dst port 68"

	noCaptureNote = "loop.note.noNpcap"
)

// NpcapStatus is CaptureStatus under the name the app's frontend knows it by.
type NpcapStatus = CaptureStatus

// Npcap checks for the driver.
func Npcap() NpcapStatus { return Capture() }

// Capture checks for Npcap, which the deeper tests need.
func Capture() CaptureStatus {
	v, err := npcap.Version()
	return CaptureStatus{Available: err == nil, Version: v}
}

// openCapture opens a filtered capture on the adapter.
func openCapture(a adapter.Adapter, purpose capturePurpose) (frames, error) {
	filter := loopFilter
	if purpose == captureDHCP {
		filter = dhcpFilter
	}
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

// pingAvailable: Windows' ICMP API needs no privileges.
func pingAvailable() bool { return true }

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
