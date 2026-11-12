package loop

import (
	"context"
	"net"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// Capture is a raw frame source and sink. Run calls it from one goroutine, since
// libpcap handles aren't safe to share.
type Capture interface {
	// Next returns one frame, or a nil frame if none arrived before its timeout.
	Next() (frame []byte, at time.Time, err error)
	Send(frame []byte) error
}

// Counters reads the adapter's cumulative receive counters.
type Counters func() (nonUnicastPkts, broadcastOctets uint64, err error)

// Config describes one check.
type Config struct {
	Capture  Capture // nil when Npcap isn't available
	MAC      net.HardwareAddr
	Nonce    [nonceLen]byte
	Counters Counters
	Duration time.Duration
	Wireless bool
	// CaptureNote explains why Capture is nil, for the report.
	CaptureNote verdict.Msg
	// Probes is how many broadcast/control pairs to send. In a real loop each
	// broadcast keeps circulating, so this stays small.
	Probes int
}

// Run gathers evidence for Duration and evaluates it.
func Run(ctx context.Context, cfg Config) Report {
	if cfg.Duration == 0 {
		cfg.Duration = 8 * time.Second
	}
	if cfg.Probes == 0 {
		cfg.Probes = 3
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	rateCh := make(chan Rate, 1)
	go func() { rateCh <- sampleRate(ctx, cfg.Counters, cfg.Duration) }()

	start := time.Now()
	ev := Evidence{Wireless: cfg.Wireless, CaptureNote: cfg.CaptureNote}
	if cfg.Capture != nil {
		a := newAnalyzer(cfg.Nonce)
		sent, err := runCapture(ctx, cfg, a)
		if err != nil {
			ev.CaptureNote = verdict.M("loop.note.captureFailed", "detail", err.Error())
		} else {
			ev.Echo = a.echo(sent)
		}
		ev.Repeats, ev.Talkers, ev.Frames = a.topRepeats(5), a.topTalkers(5), a.frames
	} else {
		<-ctx.Done()
	}
	ev.Rate = <-rateCh
	ev.DurationSec = time.Since(start).Seconds()
	return Evaluate(ev)
}

// runCapture spaces probes across the first part of the window, leaving the rest
// for late copies to come back. Each probe is preceded by its control frame.
func runCapture(ctx context.Context, cfg Config, a *analyzer) (sent int, err error) {
	gap := cfg.Duration / time.Duration(cfg.Probes*2+1)
	next := time.Now().Add(gap)
	for ctx.Err() == nil {
		if sent < cfg.Probes && !time.Now().Before(next) {
			seq := uint16(sent)
			if err := cfg.Capture.Send(EncodeProbe(controlMAC, cfg.MAC, cfg.Nonce, seq)); err != nil {
				return sent, err
			}
			if err := cfg.Capture.Send(EncodeProbe(broadcastMAC, cfg.MAC, cfg.Nonce, seq)); err != nil {
				return sent, err
			}
			sent++
			next = next.Add(gap)
		}
		f, at, err := cfg.Capture.Next()
		if err != nil {
			return sent, err
		}
		if f != nil {
			a.observe(at, f)
		}
	}
	return sent, nil
}

// sampleRate turns counter deltas into a per-second series.
func sampleRate(ctx context.Context, read Counters, window time.Duration) Rate {
	if read == nil {
		return summariseRate(nil, 0)
	}
	lastPkts, lastOctets, err := read()
	if err != nil {
		return summariseRate(nil, 0)
	}
	firstOctets := lastOctets
	start, last := time.Now(), time.Now()
	samples := []float64{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(start).Seconds()
			kbps := 0.0
			if elapsed > 0 {
				kbps = float64(lastOctets-firstOctets) / 1024 / elapsed
			}
			return summariseRate(samples, kbps)
		case <-tick.C:
			pkts, octets, err := read()
			if err != nil {
				continue
			}
			now := time.Now()
			if pkts >= lastPkts { // counters reset if the adapter restarts
				samples = append(samples, float64(pkts-lastPkts)/now.Sub(last).Seconds())
			}
			lastPkts, lastOctets, last = pkts, octets, now
		}
	}
}
