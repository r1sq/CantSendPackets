package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

func TestTrackerStatus(t *testing.T) {
	fail := errors.New("timeout")
	cases := []struct {
		name string
		seq  []error
		want Status
	}{
		{"no samples", nil, StatusPending},
		{"healthy", []error{nil, nil, nil}, StatusUp},
		{"one lost ping isn't an outage", []error{nil, nil, fail}, StatusDegraded},
		{"three in a row is", []error{nil, fail, fail, fail}, StatusDown},
		{"first probe failing with no history is down", []error{fail}, StatusDown},
		{"recovered, loss remembered", []error{fail, fail, fail, nil}, StatusDegraded},
	}
	for _, c := range cases {
		tr := &tracker{target: Target{ID: "x"}}
		for _, e := range c.seq {
			tr.record(5*time.Millisecond, e)
		}
		if got := tr.state().Status; got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestTrackerStats(t *testing.T) {
	tr := &tracker{}
	tr.record(10*time.Millisecond, nil)
	tr.record(20*time.Millisecond, nil)
	tr.record(0, errors.New("x"))
	tr.record(30*time.Millisecond, nil)
	s := tr.state()
	if s.AvgMs != 20 {
		t.Errorf("failed probes must not skew the average: %v", s.AvgMs)
	}
	if s.LossPct != 25 {
		t.Errorf("loss = %v", s.LossPct)
	}
	if s.History[2] != -1 {
		t.Errorf("failure marker missing: %v", s.History)
	}
}

func TestTrackerErrorForms(t *testing.T) {
	tr := &tracker{}
	tr.record(0, fmt.Errorf("wrapped: %w", ErrCaptive))
	if s := tr.state(); !s.Captive || s.Error.Key != "err.intercepted" {
		t.Errorf("%+v", s)
	}
	tr.record(0, ErrProxyAuth)
	if s := tr.state(); !s.ProxyAuth || s.Captive {
		t.Errorf("%+v", s)
	}
	tr.record(0, errors.New("some OS text"))
	if s := tr.state(); s.Error.Key != "err.raw" || s.Error.Args["text"] != "some OS text" {
		t.Errorf("untranslated errors must still be shown verbatim: %+v", s.Error)
	}
}

func TestHistoryIsBounded(t *testing.T) {
	tr := &tracker{}
	for i := 0; i < windowSize*3; i++ {
		tr.record(time.Millisecond, nil)
	}
	if len(tr.history) != windowSize {
		t.Errorf("len = %d", len(tr.history))
	}
}

func TestLongAgoBlipReadsAsUp(t *testing.T) {
	tr := &tracker{}
	tr.record(0, errors.New("x"))
	for i := 0; i < 59; i++ {
		tr.record(time.Millisecond, nil)
	}
	if got := tr.state().Status; got != StatusUp {
		t.Errorf("%s", got)
	}
}

func st(group Group, kind, label string, status Status) State {
	return State{Group: group, Kind: kind, Label: verdict.M("t." + label), Addr: label, Status: status}
}

const (
	up      = StatusUp
	down    = StatusDown
	pending = StatusPending
)

func gw(s Status) State   { return st(GroupGateway, "ping", "gw", s) }
func dnsS(s Status) State { return st(GroupDNS, "dns", "d", s) }
func ping(s Status) State { return st(GroupInternet, "ping", "ping", s) }
func web(s Status) State  { return st(GroupInternet, "https", "web", s) }
func prx(s Status) State  { return st(GroupProxy, "tcp", "proxy", s) }

var (
	noProxy  = ProxyState{}
	viaProxy = ProxyState{Active: true, Address: "proxy:8080"}
)

func TestSummarize(t *testing.T) {
	blocked := ping(down)
	blocked.Status = StatusBlocked
	captive := web(down)
	captive.Captive = true
	auth := web(down)
	auth.ProxyAuth = true
	lossy := gw(StatusDegraded)
	lossy.LossPct = 10
	blip := gw(StatusUp)
	blip.LossPct = 1

	cases := []struct {
		name   string
		states []State
		proxy  ProxyState
		want   verdict.Level
		key    string
	}{
		{"all good", []State{gw(up), dnsS(up), ping(up), web(up)}, noProxy, verdict.OK, "summary.ok.h"},
		{"nothing to test", nil, noProxy, verdict.Unknown, "summary.nothing.h"},
		{"starting", []State{gw(pending), ping(pending), web(pending)}, noProxy, verdict.Unknown, "summary.checking.h"},
		{"failing ping says nothing until the web probes report", []State{gw(up), ping(down), web(pending)}, noProxy, verdict.Unknown, "summary.checking.h"},

		{"gateway dead", []State{gw(down), dnsS(down), ping(down), web(down)}, noProxy, verdict.Problem, "summary.gatewayDown.h"},
		{"wan down", []State{gw(up), dnsS(down), ping(down), web(down)}, noProxy, verdict.Problem, "summary.upstream.h"},
		{"no gateway", []State{ping(down), web(down)}, noProxy, verdict.Problem, "summary.noGateway.h"},
		{"dns dead", []State{gw(up), dnsS(down), ping(up), web(up)}, noProxy, verdict.Problem, "summary.dnsDown.h"},
		{"no dns configured", []State{gw(up), ping(up), web(up)}, noProxy, verdict.Warn, "summary.noDns.h"},
		{"gateway ignores ping but web works", []State{gw(down), dnsS(up), ping(up), web(up)}, noProxy, verdict.OK, "summary.okNoGatewayReply.h"},
		{"captive portal blocking ping too", []State{gw(up), dnsS(up), ping(down), captive}, noProxy, verdict.Warn, "summary.captive.h"},
		{"sustained loss", []State{lossy, dnsS(up), ping(up), web(up)}, noProxy, verdict.Warn, "summary.loss.h"},
		{"tiny loss isn't reported", []State{blip, dnsS(up), ping(up), web(up)}, noProxy, verdict.OK, "summary.ok.h"},

		// The cases that prompted this design: behind a proxy, ping is meaningless.
		{"behind proxy, ping blocked, all fine", []State{gw(up), dnsS(up), prx(up), blocked, web(up)}, viaProxy, verdict.OK, "summary.okProxy.h"},
		{"proxy unreachable", []State{gw(up), dnsS(up), prx(down), ping(down), web(down)}, viaProxy, verdict.Problem, "summary.proxyDown.h"},
		{"proxy up but no internet", []State{gw(up), dnsS(up), prx(up), ping(down), web(down)}, viaProxy, verdict.Problem, "summary.proxyNoInternet.h"},
		{"proxy wants a login", []State{gw(up), dnsS(up), prx(up), ping(down), auth}, viaProxy, verdict.Warn, "summary.proxyAuth.h"},
		{"proxy row not back yet", []State{gw(up), dnsS(up), ping(down), web(down)}, viaProxy, verdict.Unknown, "summary.checking.h"},
		{"gateway dead outranks proxy", []State{gw(down), dnsS(down), prx(down), ping(down), web(down)}, viaProxy, verdict.Problem, "summary.gatewayDown.h"},
		{"ping works, web doesn't, no proxy found", []State{gw(up), dnsS(up), ping(up), web(down)}, noProxy, verdict.Problem, "summary.webBlocked.h"},
		{"blocked ping alone isn't reported as loss", []State{gw(up), dnsS(up), blocked, web(up)}, noProxy, verdict.OK, "summary.ok.h"},
		{"one site filtered", []State{gw(up), dnsS(up), web(up), st(GroupInternet, "https", "web2", down)}, noProxy, verdict.Warn, "summary.webPartial.h"},
	}
	for _, c := range cases {
		got := Summarize(c.states, c.proxy)
		if got.Verdict != c.want || got.Headline.Key != c.key {
			t.Errorf("%s: got %s %s, want %s %s", c.name, got.Verdict, got.Headline, c.want, c.key)
		}
	}
}

func TestRejectedLoginIsDistinct(t *testing.T) {
	auth := web(down)
	auth.ProxyAuth = true
	got := Summarize([]State{gw(up), dnsS(up), prx(up), auth}, ProxyState{Active: true, Address: "p:1", AuthRejected: true})
	if got.Headline.Key != "summary.proxyAuthRejected.h" {
		t.Errorf("%s", got.Headline)
	}
}

func TestOneDNSDownNamesIt(t *testing.T) {
	got := Summarize([]State{gw(up), st(GroupDNS, "dns", "d1", up), st(GroupDNS, "dns", "d2", down), web(up)}, noProxy)
	if got.Headline.Key != "summary.oneDnsDown.h" || got.Headline.Args["addr"] != "d2" {
		t.Errorf("%s", got.Headline)
	}
}

func TestGatewayAliveViaARPOnly(t *testing.T) {
	arp := st(GroupGateway, "arp", "gw arp", up)
	got := Summarize([]State{gw(down), arp, dnsS(down), ping(down), web(down)}, noProxy)
	if got.Headline.Key != "summary.upstream.h" {
		t.Errorf("%s", got.Headline)
	}
}

func TestRarelySampledProbesDoNotReportLoss(t *testing.T) {
	for _, kind := range []string{"arp", "http", "https"} {
		rare := st(GroupGateway, kind, "rare", StatusDegraded)
		rare.LossPct = 50
		got := Summarize([]State{gw(up), rare, dnsS(up), ping(up), web(up)}, noProxy)
		if got.Verdict != verdict.OK {
			t.Errorf("%s: %s %s", kind, got.Verdict, got.Headline)
		}
	}
}

func TestAdvisoryBlockedOnlyWhenWebWorks(t *testing.T) {
	advisory := ping(down)
	advisory.Advisory = true

	states := []State{advisory, web(up)}
	applyAdvisory(states)
	if states[0].Status != StatusBlocked || states[0].Error.Key != "err.pingBlocked" {
		t.Errorf("%+v", states[0])
	}

	states = []State{advisory, web(down)}
	applyAdvisory(states)
	if states[0].Status != StatusDown {
		t.Errorf("with the web also down, a failing ping is a real failure: %s", states[0].Status)
	}

	auth := web(down)
	auth.ProxyAuth = true
	states = []State{advisory, auth}
	applyAdvisory(states)
	if states[0].Status != StatusBlocked {
		t.Errorf("a pending proxy login explains a failing ping: %s", states[0].Status)
	}

	nonAdvisory := gw(down)
	states = []State{nonAdvisory, web(up)}
	applyAdvisory(states)
	if states[0].Status != StatusDown {
		t.Errorf("only advisory targets may be excused: %s", states[0].Status)
	}
}

func cfg(targets ...Target) Config { return Config{Targets: targets} }

func TestRunProbesAndEmits(t *testing.T) {
	var calls atomic.Int32
	target := Target{
		ID: "a", Group: GroupGateway, Interval: 10 * time.Millisecond, Timeout: time.Second,
		Probe: func(context.Context) (time.Duration, error) {
			calls.Add(1)
			return time.Millisecond, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	var last Snapshot
	var emits int
	Run(ctx, 7, cfg(target), func(s Snapshot) { last, emits = s, emits+1 })
	if emits < 2 || calls.Load() < 10 {
		t.Fatalf("emits=%d calls=%d", emits, calls.Load())
	}
	if last.AdapterIndex != 7 || last.Targets[0].Status != StatusUp {
		t.Errorf("%+v", last)
	}
}

func TestPrepareHoldsTargetPending(t *testing.T) {
	release := make(chan struct{})
	var probed atomic.Bool
	target := Target{
		ID: "a", Interval: time.Millisecond, Timeout: time.Second,
		Prepare: func(context.Context) { <-release },
		Probe:   func(context.Context) (time.Duration, error) { probed.Store(true); return 0, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()
	first := true
	Run(ctx, 1, cfg(target), func(s Snapshot) {
		if first {
			if probed.Load() || s.Targets[0].Status != StatusPending {
				t.Error("probed before Prepare finished")
			}
			close(release)
			first = false
		}
	})
	if !probed.Load() {
		t.Error("never probed after Prepare")
	}
}

func TestOptionalTargetAppearsOnlyOnceItHasResults(t *testing.T) {
	never := Target{
		ID: "np", Optional: true, Interval: time.Millisecond, Timeout: time.Second,
		Probe: func(context.Context) (time.Duration, error) { return 0, ErrNotApplicable },
	}
	does := Target{
		ID: "yes", Optional: true, Interval: time.Millisecond, Timeout: time.Second,
		Probe: func(context.Context) (time.Duration, error) { return time.Millisecond, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()
	var last Snapshot
	Run(ctx, 1, cfg(never, does), func(s Snapshot) { last = s })
	if len(last.Targets) != 1 || last.Targets[0].ID != "yes" {
		t.Errorf("%+v", last.Targets)
	}
}

func TestDescribeOverridesAddress(t *testing.T) {
	tr := &tracker{target: Target{Addr: "old", Describe: func() (string, bool) { return "new", true }}}
	if s := tr.state(); s.Addr != "new" || !s.ViaProxy {
		t.Errorf("%+v", s)
	}
}

func TestSnapshotCarriesProxyState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var last Snapshot
	Run(ctx, 1, Config{Proxy: func() ProxyState { return viaProxy }}, func(s Snapshot) { last = s })
	if !last.Proxy.Active || last.Proxy.Address != "proxy:8080" {
		t.Errorf("%+v", last.Proxy)
	}
}

// A slow probe must not stop others updating, and stopping must discard the
// in-flight result: an abort isn't a network failure.
func TestCancelDoesNotRecordFailure(t *testing.T) {
	target := Target{
		ID: "slow", Interval: time.Millisecond, Timeout: time.Hour,
		Probe: func(ctx context.Context) (time.Duration, error) {
			<-ctx.Done()
			return 0, fmt.Errorf("cancelled: %w", ctx.Err())
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var last Snapshot
	Run(ctx, 1, cfg(target), func(s Snapshot) { last = s })
	if len(last.Targets[0].History) != 0 {
		t.Errorf("recorded %v", last.Targets[0].History)
	}
}
