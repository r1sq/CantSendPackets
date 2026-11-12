package loop

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

var (
	testMAC   = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 1}
	testNonce = [nonceLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
)

// fakeSegment simulates what a capture handle reports on a given network.
type fakeSegment struct {
	selfCopies    int // how many times the local capture path reports our own send
	loopCopies    int // how many laps a broadcast makes
	switchFilters bool
	background    [][]byte // frames delivered in a burst as soon as capture starts
	sendErr       error

	inbox [][]byte
	sends int
}

func (s *fakeSegment) Send(f []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sends++
	for i := 0; i < s.selfCopies; i++ {
		s.inbox = append(s.inbox, f)
	}
	isControl := net.HardwareAddr(f[:6]).String() == controlMAC.String()
	if isControl && s.switchFilters {
		return nil
	}
	for i := 0; i < s.loopCopies; i++ {
		s.inbox = append(s.inbox, f)
	}
	return nil
}

func (s *fakeSegment) Next() ([]byte, time.Time, error) {
	if len(s.background) > 0 {
		s.inbox = append(s.inbox, s.background...)
		s.background = nil
	}
	if len(s.inbox) == 0 {
		time.Sleep(time.Millisecond)
		return nil, time.Time{}, nil
	}
	f := s.inbox[0]
	s.inbox = s.inbox[1:]
	return f, time.Unix(1000, 0), nil
}

func run(t *testing.T, seg *fakeSegment, counters Counters) Report {
	t.Helper()
	return Run(context.Background(), Config{
		Capture: seg, MAC: testMAC, Nonce: testNonce, Counters: counters,
		Duration: 60 * time.Millisecond, Probes: 3,
	})
}

// The self-copy count is unknown on real Npcap, so the verdict must hold for
// each plausible value.
func TestEchoVerdictAcrossCaptureBehaviours(t *testing.T) {
	cases := []struct {
		name string
		seg  fakeSegment
		want verdict.Level
	}{
		{"clean, capture hides own frames", fakeSegment{selfCopies: 0, switchFilters: true}, verdict.OK},
		{"clean, capture shows own frames once", fakeSegment{selfCopies: 1, switchFilters: true}, verdict.OK},
		{"clean, capture shows own frames twice", fakeSegment{selfCopies: 2, switchFilters: true}, verdict.OK},
		{"clean, dumb switch", fakeSegment{selfCopies: 1, switchFilters: false}, verdict.OK},
		{"loop, managed switches", fakeSegment{selfCopies: 1, loopCopies: 40, switchFilters: true}, verdict.Problem},
		{"loop, dumb switch forwards control too", fakeSegment{selfCopies: 1, loopCopies: 40, switchFilters: false}, verdict.Problem},
		{"loop, capture hides own frames", fakeSegment{selfCopies: 0, loopCopies: 40, switchFilters: true}, verdict.Problem},
		{"single reflection", fakeSegment{selfCopies: 1, loopCopies: 1, switchFilters: true}, verdict.Warn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seg := c.seg
			rep := run(t, &seg, nil)
			if rep.Verdict != c.want {
				t.Fatalf("verdict = %s (%s), echo = %+v", rep.Verdict, rep.Headline, rep.Echo)
			}
			if rep.Echo == nil || rep.Echo.Sent != 3 {
				t.Fatalf("echo = %+v", rep.Echo)
			}
		})
	}
}

func TestProbesSentAreBounded(t *testing.T) {
	seg := &fakeSegment{switchFilters: true}
	run(t, seg, nil)
	if seg.sends != 6 { // 3 pairs: every extra frame would loop forever on a real loop
		t.Errorf("sent %d frames", seg.sends)
	}
}

func TestOtherRunsProbesAreNotEchoes(t *testing.T) {
	other := EncodeProbe(broadcastMAC, net.HardwareAddr{2, 0, 0, 0, 0, 9}, [nonceLen]byte{9}, 0)
	seg := &fakeSegment{selfCopies: 1, switchFilters: true}
	for i := 0; i < 5; i++ {
		seg.background = append(seg.background, other)
	}
	if rep := run(t, seg, nil); rep.Echo.Extra != 0 {
		t.Errorf("another instance's probes counted as echoes: %+v", rep.Echo)
	}
}

func arpFrame(src byte, target byte) []byte {
	f := make([]byte, 60)
	copy(f[:6], broadcastMAC)
	f[6], f[11] = 2, src
	f[12], f[13] = 0x08, 0x06
	f[40] = target
	return f
}

func repeated(f []byte, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = f
	}
	return out
}

func TestRepeatedFrames(t *testing.T) {
	t.Run("one chatty device is a warning", func(t *testing.T) {
		seg := &fakeSegment{switchFilters: true, background: repeated(arpFrame(1, 1), 40)}
		rep := run(t, seg, nil)
		if rep.Verdict != verdict.Warn || len(rep.Repeats) != 1 || rep.Repeats[0].PeakPerS != 40 {
			t.Fatalf("%s %s %+v", rep.Verdict, rep.Headline, rep.Repeats)
		}
		if rep.Repeats[0].EtherType != "0x0806" || rep.Repeats[0].SourceMAC != "02:00:00:00:00:01" {
			t.Errorf("repeat misdescribed: %+v", rep.Repeats[0])
		}
	})
	t.Run("several devices repeating is a loop even if probes are lost", func(t *testing.T) {
		bg := append(repeated(arpFrame(1, 1), 40), repeated(arpFrame(2, 2), 40)...)
		seg := &fakeSegment{switchFilters: true, background: bg}
		if rep := run(t, seg, nil); rep.Verdict != verdict.Problem {
			t.Fatalf("%s %s", rep.Verdict, rep.Headline)
		}
	})
	t.Run("normal discovery bursts are fine", func(t *testing.T) {
		seg := &fakeSegment{switchFilters: true, background: repeated(arpFrame(1, 1), RepeatWarnPerS-1)}
		if rep := run(t, seg, nil); rep.Verdict != verdict.OK || len(rep.Repeats) != 0 {
			t.Fatalf("%s %s %+v", rep.Verdict, rep.Headline, rep.Repeats)
		}
	})
}

func TestRepeatPeakIsPerSecond(t *testing.T) {
	a := newAnalyzer(testNonce)
	f := arpFrame(1, 1)
	for i := 0; i < 60; i++ {
		a.observe(time.Unix(int64(1000+i), 0), f) // same frame, once a second: normal
	}
	if got := a.topRepeats(5); len(got) != 0 {
		t.Errorf("a periodic frame isn't a repeat: %+v", got)
	}
}

func TestAnalyzerHandlesRuntFrames(t *testing.T) {
	a := newAnalyzer(testNonce)
	for n := 0; n < 40; n++ {
		a.observe(time.Unix(1, 0), make([]byte, n))
	}
	probe := EncodeProbe(broadcastMAC, testMAC, testNonce, 0)
	for n := 0; n < len(probe); n++ {
		a.observe(time.Unix(1, 0), probe[:n])
	}
}

func TestAnalyzerMemoryIsBounded(t *testing.T) {
	a := newAnalyzer(testNonce)
	f := arpFrame(1, 1)
	for i := 0; i < maxTracked+500; i++ {
		f[50], f[51], f[52] = byte(i), byte(i>>8), byte(i>>16)
		a.observe(time.Unix(1, 0), f)
	}
	if len(a.stats) > maxTracked {
		t.Errorf("tracked %d frames", len(a.stats))
	}
}

func TestEvaluateWithoutCapture(t *testing.T) {
	rate := func(median float64) Rate { return Rate{Available: true, MedianPps: median, PeakPps: median} }
	cases := []struct {
		name string
		ev   Evidence
		want verdict.Level
	}{
		{"quiet", Evidence{Rate: rate(12)}, verdict.OK},
		{"busy", Evidence{Rate: rate(RateWarnPps)}, verdict.Warn},
		{"storm", Evidence{Rate: rate(RateProblemPps)}, verdict.Problem},
		{"driver reports nothing", Evidence{Rate: rate(0)}, verdict.Unknown},
		{"no data at all", Evidence{}, verdict.Unknown},
	}
	for _, c := range cases {
		if got := Evaluate(c.ev); got.Verdict != c.want {
			t.Errorf("%s: verdict = %s (%s), want %s", c.name, got.Verdict, got.Headline, c.want)
		}
	}
}

func TestStormWithCleanEchoBlamesDeviceNotLoop(t *testing.T) {
	rep := Evaluate(Evidence{
		Echo: &Echo{Sent: 3, Extra: 0},
		Rate: Rate{Available: true, MedianPps: 5000, PeakPps: 6000},
	})
	if rep.Verdict != verdict.Problem || rep.Headline.Key != "loop.stormNoEcho.h" {
		t.Fatalf("%s %s", rep.Verdict, rep.Headline)
	}
}

func TestLimitedModeIsLabelled(t *testing.T) {
	rep := Evaluate(Evidence{Rate: Rate{Available: true, MedianPps: 10, PeakPps: 10}, CaptureNote: verdict.M("loop.note.noNpcap")})
	if rep.Method.Key != "loop.method.counters" || len(rep.Notes) != 1 {
		t.Errorf("limited mode must be visible: %+v", rep)
	}
}

func TestCaptureFailureFallsBackToCounters(t *testing.T) {
	seg := &fakeSegment{sendErr: errors.New("adapter went away")}
	rep := run(t, seg, func() (uint64, uint64, error) { return 0, 0, nil })
	if rep.Echo != nil {
		t.Error("a failed probe must not report a clean echo")
	}
	if len(rep.Notes) == 0 {
		t.Error("the capture failure should be explained")
	}
}

func TestSummariseRateUsesMedianAgainstBursts(t *testing.T) {
	r := summariseRate([]float64{10, 12, 9000, 11, 13}, 1)
	if r.MedianPps != 12 || r.PeakPps != 9000 {
		t.Errorf("%+v", r)
	}
	if rep := Evaluate(Evidence{Rate: r}); rep.Verdict != verdict.OK {
		t.Errorf("one burst shouldn't alarm: %s", rep.Verdict)
	}
}

func TestSampleRateFromCounters(t *testing.T) {
	var pkts atomic.Uint64
	read := func() (uint64, uint64, error) { return pkts.Add(100), pkts.Load() * 100, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	r := sampleRate(ctx, read, 2500*time.Millisecond)
	if !r.Available || len(r.SamplesPps) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.MedianPps < 80 || r.MedianPps > 120 {
		t.Errorf("median = %v, want about 100", r.MedianPps)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		Run(ctx, Config{Duration: time.Hour})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run ignored cancellation")
	}
}
