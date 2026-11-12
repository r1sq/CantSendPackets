package diag

import (
	"context"
	"net/url"
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

// windowsLogin: WinHTTP can answer a proxy with the Windows login.
const windowsLogin = true

// fetchWithLogin downloads through a proxy that asked for a login, with WinHTTP.
func fetchWithLogin(_ context.Context, rawURL string, route *url.URL, level proxy.LogonLevel, user, password string, max int64) ([]byte, error) {
	res, err := proxy.Fetch(proxy.FetchOptions{
		URL: rawURL, ProxyHost: route.Host, Level: level,
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
