package diag

import (
	"context"
	"net/url"

	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/probe"
	"github.com/r1sq/CantSendPackets/internal/proxy"
	"github.com/r1sq/CantSendPackets/internal/rawcap"
	"github.com/r1sq/CantSendPackets/internal/update"
)

const noCaptureNote = "loop.note.noRawAccess"

// Capture checks whether this process may open raw sockets, which the deeper
// tests need: root, or the CAP_NET_RAW capability.
func Capture() CaptureStatus {
	if rawcap.Available() {
		return CaptureStatus{Available: true, Version: "AF_PACKET"}
	}
	return CaptureStatus{}
}

// openCapture opens a capture on the adapter, filtered in the kernel.
func openCapture(a adapter.Adapter, purpose capturePurpose) (frames, error) {
	opts := rawcap.Options{Filter: rawcap.NonUnicast}
	if purpose == captureDHCP {
		opts.Filter = rawcap.DHCPServerReplies
	}
	h, err := rawcap.Open(a.DeviceName, opts)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// pingAvailable depends on ping_group_range and capabilities.
func pingAvailable() bool { return probe.PingAvailable() }

// windowsLogin: Linux has no account login to offer a proxy.
const windowsLogin = false

// fetchWithLogin downloads through a proxy that asked for a login. Only typed
// credentials can answer it, sent as Basic.
func fetchWithLogin(ctx context.Context, rawURL string, route *url.URL, _ proxy.LogonLevel, user, password string, max int64) ([]byte, error) {
	if user == "" {
		return nil, update.ErrProxyAuth
	}
	withLogin := *route
	withLogin.User = url.UserPassword(user, password)
	return update.HTTPGet(ctx, rawURL, update.HTTPOptions{Proxy: &withLogin}, max)
}
