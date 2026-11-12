package loop

import (
	"sort"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// Thresholds. The rate figures are rules of thumb for a client access port, not
// a standard, which is why rate alone never claims to have found a loop.
const (
	RateWarnPps    = 300.0
	RateProblemPps = 1000.0

	// RepeatWarnPerS sits above normal discovery bursts: SSDP and mDNS repeat
	// themselves a handful of times a second, not dozens.
	RepeatWarnPerS = 15
)

// Echo is the result of the active probe. Extra is how many more copies of a
// broadcast probe came back than the Baseline measured with the control frame.
type Echo struct {
	Sent          int `json:"sent"`
	MaxCopies     int `json:"maxCopies"`
	ControlCopies int `json:"controlCopies"`
	Baseline      int `json:"baseline"`
	Extra         int `json:"extra"`
}

// Rate is what the adapter's own counters showed.
type Rate struct {
	Available     bool      `json:"available"`
	AvgPps        float64   `json:"avgPps"`
	MedianPps     float64   `json:"medianPps"`
	PeakPps       float64   `json:"peakPps"`
	BroadcastKBps float64   `json:"broadcastKBps"`
	SamplesPps    []float64 `json:"samplesPps"`
}

// Evidence is all the input the verdict depends on.
type Evidence struct {
	Echo        *Echo // nil when the active probe couldn't run
	Rate        Rate
	Repeats     []Repeat
	Talkers     []Talker
	Frames      int
	DurationSec float64
	Wireless    bool
	CaptureNote verdict.Msg // why capture was unavailable, if it was
}

// Report is the outcome shown to the user.
type Report struct {
	Verdict     verdict.Level `json:"verdict"`
	Headline    verdict.Msg   `json:"headline"`
	Detail      verdict.Msg   `json:"detail"`
	Notes       []verdict.Msg `json:"notes"`
	Method      verdict.Msg   `json:"method"`
	DurationSec float64       `json:"durationSec"`
	Echo        *Echo         `json:"echo"`
	Rate        Rate          `json:"rate"`
	Repeats     []Repeat      `json:"repeats"`
	Talkers     []Talker      `json:"talkers"`
	Frames      int           `json:"frames"`
}

// Evaluate derives the verdict. Echo outranks everything: it's the only signal
// that directly shows the network sending our own frame back.
func Evaluate(e Evidence) Report {
	r := Report{
		Method: verdict.M("loop.method.counters"), DurationSec: e.DurationSec, Echo: e.Echo, Rate: e.Rate,
		Repeats: e.Repeats, Talkers: e.Talkers, Frames: e.Frames, Notes: []verdict.Msg{},
	}
	if r.Repeats == nil {
		r.Repeats = []Repeat{}
	}
	if r.Talkers == nil {
		r.Talkers = []Talker{}
	}
	if e.Echo != nil {
		r.Method = verdict.M("loop.method.active")
	}
	set := func(level verdict.Level, key string, kv ...any) {
		r.Verdict = level
		r.Headline, r.Detail = verdict.Pair(key, kv...)
	}

	repeatSources := map[string]bool{}
	for _, rp := range e.Repeats {
		repeatSources[rp.SourceMAC] = true
	}
	storm := e.Rate.Available && e.Rate.MedianPps >= RateProblemPps
	busy := e.Rate.Available && e.Rate.MedianPps >= RateWarnPps

	switch {
	case e.Echo != nil && e.Echo.Extra >= 2:
		set(verdict.Problem, "loop.echo", "extra", e.Echo.Extra)

	case len(repeatSources) >= 2:
		// Independent senders all repeating points at the network, not a device.
		set(verdict.Problem, "loop.repeats", "sources", len(repeatSources), "perSecond", RepeatWarnPerS)

	case storm && e.Echo != nil && e.Echo.Extra == 0:
		set(verdict.Problem, "loop.stormNoEcho", "rate", e.Rate.MedianPps)

	case storm:
		set(verdict.Problem, "loop.storm", "rate", e.Rate.MedianPps)

	case e.Echo != nil && e.Echo.Extra == 1:
		set(verdict.Warn, "loop.echoOnce")

	case len(repeatSources) == 1:
		set(verdict.Warn, "loop.oneDevice", "mac", e.Repeats[0].SourceMAC, "perSecond", RepeatWarnPerS)

	case busy:
		set(verdict.Warn, "loop.busy", "rate", e.Rate.MedianPps)

	case e.Echo == nil && !e.Rate.Available:
		set(verdict.Unknown, "loop.noData")

	case e.Echo == nil && e.Rate.PeakPps == 0:
		// Real segments always have some ARP or discovery chatter, so a flat zero
		// more likely means this driver doesn't report the counter.
		set(verdict.Unknown, "loop.noCounters")

	case e.Echo == nil:
		set(verdict.OK, "loop.passiveClean", "rate", e.Rate.MedianPps)

	default:
		set(verdict.OK, "loop.clean", "sent", e.Echo.Sent, "seconds", e.DurationSec)
	}

	if e.Echo == nil && !e.CaptureNote.IsZero() {
		r.Notes = append(r.Notes, e.CaptureNote)
	}
	if e.Wireless && e.Echo != nil {
		r.Notes = append(r.Notes, verdict.M("loop.note.wifi"))
	}
	return r
}

// summariseRate reduces per-second samples to a Rate. The median drives the
// verdict so a single burst can't trigger an alarm.
func summariseRate(samples []float64, broadcastKBps float64) Rate {
	r := Rate{Available: len(samples) > 0, SamplesPps: samples, BroadcastKBps: broadcastKBps}
	if len(samples) == 0 {
		r.SamplesPps = []float64{}
		return r
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, s := range sorted {
		sum += s
	}
	r.AvgPps = sum / float64(len(sorted))
	r.PeakPps = sorted[len(sorted)-1]
	mid := len(sorted) / 2
	r.MedianPps = sorted[mid]
	if len(sorted)%2 == 0 {
		r.MedianPps = (sorted[mid-1] + sorted[mid]) / 2
	}
	return r
}
