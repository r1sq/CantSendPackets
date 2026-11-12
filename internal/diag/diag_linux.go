package diag

import (
	"github.com/r1sq/CantSendPackets/internal/adapter"
	"github.com/r1sq/CantSendPackets/internal/probe"
	"github.com/r1sq/CantSendPackets/internal/rawcap"
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
