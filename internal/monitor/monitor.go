// Package monitor continuously probes a set of targets and works out, from which
// of them respond, where along the path a problem lies.
package monitor

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// Group places a target along the path from this machine outward.
type Group string

const (
	GroupGateway  Group = "gateway"
	GroupDNS      Group = "dns"
	GroupProxy    Group = "proxy"
	GroupInternet Group = "internet"
)

var (
	// ErrCaptive marks a web probe that got an answer, but not the real one.
	ErrCaptive = verdict.Err("err.intercepted")
	// ErrProxyAuth marks a proxy that's reachable but wants a login.
	ErrProxyAuth = verdict.Err("err.proxyAuth")
	// ErrNotApplicable ends a target that turns out not to apply, such as the
	// proxy row on a network with no proxy. Its row never appears.
	ErrNotApplicable = errors.New("not applicable")
)

const (
	windowSize = 60
	// recentN is how many latest samples decide "down". One lost ping isn't an
	// outage; three in a row are.
	recentN = 3
	// lossWarnPct ignores the odd lost ping but flags sustained loss.
	lossWarnPct = 5
)

// ProbeFunc performs one measurement.
type ProbeFunc func(ctx context.Context) (time.Duration, error)

// Target is one thing to watch.
type Target struct {
	ID       string
	Group    Group
	Label    verdict.Msg
	Addr     string
	Kind     string // "ping", "arp", "dns", "tcp", "http", "https"
	Interval time.Duration
	Timeout  time.Duration
	Probe    ProbeFunc

	// Prepare, if set, runs once before probing and may block, for example until
	// proxy detection has finished. The target stays pending meanwhile.
	Prepare func(ctx context.Context)
	// Describe, if set, overrides Addr and reports whether a proxy is in the path.
	Describe func() (addr string, viaProxy bool)
	// Advisory marks a target whose failure isn't a fault if the web still works:
	// plenty of networks block ping to the internet on purpose.
	Advisory bool
	// Optional hides the target until it has a result.
	Optional bool
}

// Status is a target's current condition.
type Status string

const (
	StatusPending  Status = "pending"
	StatusUp       Status = "up"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
	// StatusBlocked is an advisory target failing while the web works.
	StatusBlocked Status = "blocked"
)

// State is a snapshot of one target for display. History holds round-trip times
// in milliseconds, oldest first, with -1 for a failed probe.
type State struct {
	ID        string      `json:"id"`
	Group     Group       `json:"group"`
	Label     verdict.Msg `json:"label"`
	Addr      string      `json:"addr"`
	Kind      string      `json:"kind"`
	ViaProxy  bool        `json:"viaProxy"`
	Status    Status      `json:"status"`
	LastMs    float64     `json:"lastMs"`
	AvgMs     float64     `json:"avgMs"`
	LossPct   float64     `json:"lossPct"`
	Error     verdict.Msg `json:"error"`
	Captive   bool        `json:"captive"`
	ProxyAuth bool        `json:"proxyAuth"`
	Advisory  bool        `json:"advisory"`
	History   []float64   `json:"history"`
	// IntervalSec is the spacing of History's samples.
	IntervalSec float64 `json:"intervalSec"`
}

// ProxyState is what proxy detection found, for display and for the summary.
type ProxyState struct {
	Detecting bool        `json:"detecting"`
	Active    bool        `json:"active"`
	Address   string      `json:"address"`
	Source    string      `json:"source"`
	PACURL    string      `json:"pacUrl"`
	Issue     verdict.Msg `json:"issue"`
	// AuthRequired means the proxy asked for a login.
	AuthRequired bool `json:"authRequired"`
	// AuthMethod is what got accepted: "windows", "typed", or empty.
	AuthMethod string `json:"authMethod"`
	// AuthRejected means credentials the user typed were refused.
	AuthRejected bool `json:"authRejected"`
	// WindowsLoginOffered means the user's Windows login was tried and not accepted,
	// so approving it again wouldn't help.
	WindowsLoginOffered bool `json:"windowsLoginOffered"`
}

// Config is what to monitor.
type Config struct {
	Targets []Target
	// Proxy reports detection state. It may be nil.
	Proxy func() ProxyState
}

// Snapshot is what the UI receives on every tick.
type Snapshot struct {
	AdapterIndex int        `json:"adapterIndex"`
	Summary      Summary    `json:"summary"`
	Proxy        ProxyState `json:"proxy"`
	Targets      []State    `json:"targets"`
}

type tracker struct {
	target  Target
	history []float64
	lastErr error
}

func (t *tracker) record(rtt time.Duration, err error) {
	v := float64(rtt.Microseconds()) / 1000
	if err != nil {
		v = -1
	}
	t.history = append(t.history, v)
	if len(t.history) > windowSize {
		t.history = t.history[len(t.history)-windowSize:]
	}
	t.lastErr = err
}

func (t *tracker) state() State {
	s := State{
		ID: t.target.ID, Group: t.target.Group, Label: t.target.Label, Addr: t.target.Addr, Kind: t.target.Kind,
		Advisory: t.target.Advisory, Status: StatusPending,
		History: append([]float64{}, t.history...), IntervalSec: t.target.Interval.Seconds(),
	}
	if t.target.Describe != nil {
		s.Addr, s.ViaProxy = t.target.Describe()
	}
	if len(t.history) == 0 {
		return s
	}
	var sum float64
	var okCount, failCount int
	for _, v := range t.history {
		if v < 0 {
			failCount++
			continue
		}
		sum += v
		okCount++
	}
	if okCount > 0 {
		s.AvgMs = sum / float64(okCount)
	}
	s.LossPct = 100 * float64(failCount) / float64(len(t.history))
	s.LastMs = t.history[len(t.history)-1]
	if t.lastErr != nil {
		s.Error = verdict.AsMsg(t.lastErr)
		s.Captive = errors.Is(t.lastErr, ErrCaptive)
		s.ProxyAuth = errors.Is(t.lastErr, ErrProxyAuth)
	}

	recent := t.history[max(0, len(t.history)-recentN):]
	recentFails := 0
	for _, v := range recent {
		if v < 0 {
			recentFails++
		}
	}
	switch {
	case recentFails == len(recent) && (len(recent) == recentN || okCount == 0):
		s.Status = StatusDown
	case recentFails > 0 || s.LossPct >= lossWarnPct:
		s.Status = StatusDegraded
	default:
		s.Status = StatusUp
	}
	return s
}

// applyAdvisory marks failing advisory targets as blocked if the web works, since
// that shows the failure is a policy rather than a fault. A portal or a proxy
// waiting for a login counts too: such a network wouldn't pass ping anyway.
func applyAdvisory(states []State) {
	explained := false
	for _, s := range states {
		if s.Group == GroupInternet && !s.Advisory && (s.Status == StatusUp || s.Status == StatusDegraded || s.Captive || s.ProxyAuth) {
			explained = true
		}
	}
	if !explained {
		return
	}
	for i := range states {
		if states[i].Advisory && states[i].Status == StatusDown {
			states[i].Status = StatusBlocked
			states[i].Error = verdict.M("err.pingBlocked")
		}
	}
}

// Run probes every target until ctx ends, calling emit about once a second.
// emit is never called concurrently.
func Run(ctx context.Context, adapterIndex int, cfg Config, emit func(Snapshot)) {
	trackers := make([]*tracker, len(cfg.Targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, tg := range cfg.Targets {
		tr := &tracker{target: tg}
		trackers[i] = tr
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tg.Prepare != nil {
				tg.Prepare(ctx)
			}
			tick := time.NewTicker(tg.Interval)
			defer tick.Stop()
			for ctx.Err() == nil {
				pctx, cancel := context.WithTimeout(ctx, tg.Timeout)
				rtt, err := tg.Probe(pctx)
				cancel()
				if ctx.Err() != nil || errors.Is(err, ErrNotApplicable) {
					return // a cancelled probe says nothing about the network
				}
				mu.Lock()
				tr.record(rtt, err)
				mu.Unlock()
				select {
				case <-ctx.Done():
				case <-tick.C:
				}
			}
		}()
	}
	defer wg.Wait()

	snapshot := func() Snapshot {
		var proxy ProxyState
		if cfg.Proxy != nil {
			proxy = cfg.Proxy()
		}
		mu.Lock()
		defer mu.Unlock()
		states := make([]State, 0, len(trackers))
		for _, tr := range trackers {
			if tr.target.Optional && len(tr.history) == 0 {
				continue
			}
			states = append(states, tr.state())
		}
		applyAdvisory(states)
		return Snapshot{AdapterIndex: adapterIndex, Summary: Summarize(states, proxy), Proxy: proxy, Targets: states}
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	emit(snapshot())
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			emit(snapshot())
		}
	}
}
