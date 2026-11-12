package speed

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := ListenAddr("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })
	return s, s.l.Addr().String()
}

func errKey(err error) string { return verdict.AsMsg(err).Key }

func TestFullRunOverLoopback(t *testing.T) {
	_, addr := startServer(t)
	var progress []Progress
	var mu sync.Mutex
	res, err := Run(context.Background(), addr, Options{Streams: 3, Seconds: 2}, func(p Progress) {
		mu.Lock()
		progress = append(progress, p)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	// Loopback easily exceeds this. Mostly it shows the arithmetic isn't off by
	// a factor of 1000.
	if res.DownMbps < 100 || res.UpMbps < 100 {
		t.Errorf("implausibly slow: %+v", res)
	}
	if res.DownMbps > 2_000_000 || res.UpMbps > 2_000_000 {
		t.Errorf("implausibly fast: down %v up %v", res.DownMbps, res.UpMbps)
	}
	if len(res.DownSamples) < 4 || len(res.UpSamples) < 4 {
		t.Errorf("samples: %d %d", len(res.DownSamples), len(res.UpSamples))
	}
	if res.ConnectMs <= 0 {
		t.Errorf("connect: %v", res.ConnectMs)
	}
	seen := map[string]bool{}
	for i, p := range progress {
		seen[p.Direction] = true
		if p.Fraction < 0 || p.Fraction > 1 {
			t.Errorf("fraction %v", p.Fraction)
		}
		if i > 0 && p.Fraction < progress[i-1].Fraction {
			t.Errorf("progress went backwards at %d", i)
		}
	}
	if !seen["download"] || !seen["upload"] {
		t.Errorf("directions seen: %v", seen)
	}
}

func TestTheRateIsCorrect(t *testing.T) {
	// A server that sends a known amount at a known pace, to check the figure
	// against arithmetic rather than plausibility.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const perTick = 125_000 // 100 ms at 10 Mbit/s
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.ReadFull(c, make([]byte, headerLen))
		c.Write([]byte{statusOK})
		chunk := make([]byte, perTick)
		for i := 0; i < 30; i++ {
			c.Write(chunk)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	mbps, _, _, err := runOne(context.Background(), l.Addr().String(), ModeDownload, Options{Streams: 1, Seconds: 3}, func(float64, float64) {})
	if err != nil {
		t.Fatal(err)
	}
	if mbps < 8 || mbps > 11 {
		t.Errorf("rate = %.2f Mbit/s, want about 10", mbps)
	}
}

func TestOneSessionAtATime(t *testing.T) {
	_, addr := startServer(t)
	done := make(chan error, 1)
	go func() {
		_, _, _, err := runOne(context.Background(), addr, ModeDownload, Options{Streams: 2, Seconds: 2}, func(float64, float64) {})
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	_, _, _, err := runOne(context.Background(), addr, ModeDownload, Options{Streams: 1, Seconds: 2}, func(float64, float64) {})
	if errKey(err) != "err.speed.busy" {
		t.Errorf("second client got %v", err)
	}
	if err := <-done; err != nil {
		t.Errorf("first client disturbed: %v", err)
	}
	// And it's free again afterwards.
	time.Sleep(100 * time.Millisecond)
	if _, _, _, err := runOne(context.Background(), addr, ModeDownload, Options{Streams: 1, Seconds: 2}, func(float64, float64) {}); err != nil {
		t.Errorf("after the session: %v", err)
	}
}

func rawRequest(t *testing.T, addr string, h header) byte {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(h.encode())
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("no status: %v", err)
	}
	return b[0]
}

func TestServerRefusesRequestsOverItsLimits(t *testing.T) {
	_, addr := startServer(t)
	cases := map[string]header{
		"too long":     {Version: ProtocolVersion, Mode: ModeDownload, Streams: 1, Seconds: MaxSeconds + 1},
		"way too long": {Version: ProtocolVersion, Mode: ModeDownload, Streams: 1, Seconds: 255},
		"too short":    {Version: ProtocolVersion, Mode: ModeDownload, Streams: 1, Seconds: 1},
		"no streams":   {Version: ProtocolVersion, Mode: ModeDownload, Streams: 0, Seconds: 5},
		"too many":     {Version: ProtocolVersion, Mode: ModeDownload, Streams: MaxStreams + 1, Seconds: 5},
		"bad mode":     {Version: ProtocolVersion, Mode: 9, Streams: 1, Seconds: 5},
	}
	for name, h := range cases {
		if got := rawRequest(t, addr, h); got != statusBadRequest {
			t.Errorf("%s: status %d", name, got)
		}
	}
	if got := rawRequest(t, addr, header{Version: 99, Mode: ModeDownload, Streams: 1, Seconds: 5}); got != statusBadVersion {
		t.Errorf("version: status %d", got)
	}
}

func TestStreamsCantExceedTheDeclaredCount(t *testing.T) {
	_, addr := startServer(t)
	h := header{Version: ProtocolVersion, Mode: ModeDownload, Streams: 2, Seconds: 2}
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	statuses := make([]byte, 3)
	for i := range statuses {
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		c.Write(h.encode())
		c.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1)
		io.ReadFull(c, b)
		statuses[i] = b[0]
	}
	if statuses[0] != statusOK || statuses[1] != statusOK || statuses[2] != statusBusy {
		t.Errorf("statuses %v", statuses)
	}
}

func TestDownloadStopsAtTheDeadlineEvenIfTheClientKeepsReading(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(header{Version: ProtocolVersion, Mode: ModeDownload, Streams: 1, Seconds: 2}.encode())
	start := time.Now()
	c.SetDeadline(start.Add(6 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("server didn't end the stream: %v", err)
	}
	if took := time.Since(start); took < 1500*time.Millisecond || took > 3*time.Second {
		t.Errorf("stream lasted %v", took)
	}
}

func TestServerDropsAClientThatNeverSpeaks(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout + time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("expected the server to hang up")
	} else if ne := (net.Error)(nil); errors.As(err, &ne) && ne.Timeout() {
		t.Error("server kept a silent connection open past the handshake timeout")
	}
}

func TestGarbageIsDropped(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(make([]byte, headerLen))
	c.SetDeadline(time.Now().Add(time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Error("garbage got an answer")
	}
}

func TestDecodeHeader(t *testing.T) {
	h := header{Version: 1, Mode: ModeUpload, Streams: 4, Seconds: 6, Token: [16]byte{1, 2, 3}}
	got, ok := decodeHeader(h.encode())
	if !ok || got != h {
		t.Errorf("%+v %v", got, ok)
	}
	for n := 0; n < headerLen; n++ {
		if _, ok := decodeHeader(h.encode()[:n]); ok {
			t.Errorf("accepted %d bytes", n)
		}
	}
}

func TestAllowFilterRejectsBeforeAnyWork(t *testing.T) {
	s, addr := startServer(t)
	var asked atomic.Int32
	s.Allow = func(ip netip.Addr) bool {
		asked.Add(1)
		return false
	}
	_, _, _, err := runOne(context.Background(), addr, ModeDownload, Options{Streams: 1, Seconds: 2}, func(float64, float64) {})
	if err == nil {
		t.Fatal("rejected client got through")
	}
	if asked.Load() == 0 {
		t.Error("filter wasn't consulted")
	}
}

func TestSessionEventsReportWhoAndWhat(t *testing.T) {
	s, addr := startServer(t)
	events := make(chan Session, 8)
	s.OnSession = func(e Session) { events <- e }
	if _, _, _, err := runOne(context.Background(), addr, ModeUpload, Options{Streams: 2, Seconds: 2}, func(float64, float64) {}); err != nil {
		t.Fatal(err)
	}
	got := map[bool]Session{}
	for i := 0; i < 2; i++ {
		select {
		case e := <-events:
			got[e.Active] = e
		case <-time.After(2 * time.Second):
			t.Fatal("missing session event")
		}
	}
	if got[true].From != "127.0.0.1" || got[true].Mode != "upload" {
		t.Errorf("%+v", got)
	}
}

func TestCancelEndsARunPromptly(t *testing.T) {
	_, addr := startServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, addr, Options{Streams: 2, Seconds: 20}, nil)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run ignored cancellation")
	}
}

func TestCancelledClientFreesTheServerForTheNextOne(t *testing.T) {
	_, addr := startServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	go Run(ctx, addr, Options{Streams: 2, Seconds: 20}, nil)
	time.Sleep(300 * time.Millisecond)
	cancel()
	time.Sleep(300 * time.Millisecond)
	if _, _, _, err := runOne(context.Background(), addr, ModeDownload, Options{Streams: 1, Seconds: 2}, func(float64, float64) {}); err != nil {
		t.Errorf("server still tied up: %v", err)
	}
}

func TestDeadServerIsATranslatableError(t *testing.T) {
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	_, err := Run(context.Background(), addr, Options{Seconds: 2}, nil)
	if errKey(err) != "err.speed.connect" {
		t.Errorf("%v", err)
	}
}

func TestListenFallsBackWhenThePortIsTaken(t *testing.T) {
	a, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Listen(a.Port())
	if err != nil {
		t.Fatalf("second instance must still start: %v", err)
	}
	defer b.Close()
	if b.Port() == a.Port() || b.Port() == 0 {
		t.Errorf("ports %d %d", a.Port(), b.Port())
	}
}
