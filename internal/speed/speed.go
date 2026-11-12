// Package speed is a small throughput test between two instances of this app,
// doing the core of what iperf does with nothing extra to ship or trust.
//
// Each stream is one TCP connection opened by the client. It starts with a fixed
// header, and the server answers with one status byte. Then, for a download the
// server sends until the time is up and closes; for an upload the client sends,
// half-closes, and the server replies with what it actually received. Upload is
// measured at the receiver because bytes "sent" include whatever is still queued
// in the sender's socket buffers.
//
// The first second is left out of the result, so TCP slow start doesn't drag down
// the figure.
//
// Any device that can reach the port can start a test, so the server limits what
// that's worth: one session at a time, a hard cap on duration and streams, and
// deadlines on every connection.
package speed

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	// DefaultPort is tried first. If it's taken (say, a second instance on this
	// PC) the server takes any free port, and discovery announces whichever it got.
	DefaultPort = 47116

	ProtocolVersion = 1
	MaxStreams      = 8
	MaxSeconds      = 30
	minSeconds      = 2

	headerLen = 32
	reportLen = 24

	warmup = time.Second

	handshakeTimeout = 3 * time.Second
	// grace is how long past its stated duration a connection may live.
	grace = 5 * time.Second
	// maxHandshakes bounds connections that haven't identified themselves yet.
	maxHandshakes = 16

	bufferSize = 128 * 1024
)

var magic = [4]byte{'C', 'S', 'P', 'T'}

// Mode is the direction, seen from the client.
type Mode byte

const (
	ModeDownload Mode = 1
	ModeUpload   Mode = 2
)

const (
	statusOK byte = iota
	statusBusy
	statusBadVersion
	statusBadRequest
)

// payload is random so compression along the path can't flatter the result.
var payload = func() []byte {
	b := make([]byte, bufferSize)
	rand.Read(b)
	return b
}()

type header struct {
	Version byte
	Mode    Mode
	Streams byte
	Seconds byte
	Token   [16]byte
}

func (h header) encode() []byte {
	b := make([]byte, headerLen)
	copy(b, magic[:])
	b[4], b[5], b[6], b[7] = h.Version, byte(h.Mode), h.Streams, h.Seconds
	copy(b[8:24], h.Token[:])
	return b
}

func decodeHeader(b []byte) (header, bool) {
	if len(b) != headerLen || [4]byte(b[:4]) != magic {
		return header{}, false
	}
	h := header{Version: b[4], Mode: Mode(b[5]), Streams: b[6], Seconds: b[7]}
	copy(h.Token[:], b[8:24])
	return h, true
}

func (h header) valid() bool {
	return (h.Mode == ModeDownload || h.Mode == ModeUpload) &&
		h.Streams >= 1 && h.Streams <= MaxStreams &&
		h.Seconds >= minSeconds && h.Seconds <= MaxSeconds
}

// Session describes a test someone else is running against this server.
type Session struct {
	From   string `json:"from"`
	Mode   string `json:"mode"`
	Active bool   `json:"active"`
}

func (m Mode) String() string {
	if m == ModeUpload {
		return "upload"
	}
	return "download"
}

// Server answers tests.
type Server struct {
	l net.Listener
	// Allow rejects connections by source address. nil allows all.
	Allow func(netip.Addr) bool
	// OnSession reports sessions starting and ending. It may be nil.
	OnSession func(Session)

	sem chan struct{}

	mu  sync.Mutex
	cur *session
	wg  sync.WaitGroup
}

type session struct {
	head   header
	from   string
	start  time.Time
	joined int
	active int
}

// Listen opens the server's port on all interfaces, falling back to any free port
// if port is taken.
func Listen(port int) (*Server, error) {
	l, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		if l, err = net.Listen("tcp4", "0.0.0.0:0"); err != nil {
			return nil, err
		}
	}
	return &Server{l: l, sem: make(chan struct{}, maxHandshakes)}, nil
}

// ListenAddr opens the server on a specific address, for tests.
func ListenAddr(addr string) (*Server, error) {
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	return &Server{l: l, sem: make(chan struct{}, maxHandshakes)}, nil
}

// Port returns the port in use.
func (s *Server) Port() int { return s.l.Addr().(*net.TCPAddr).Port }

// Close stops accepting and waits for running streams, which their deadlines bound.
func (s *Server) Close() error {
	err := s.l.Close()
	s.wg.Wait()
	return err
}

// Serve accepts connections until Close.
func (s *Server) Serve() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}
		ip, _ := netip.AddrFromSlice(remote.IP.To4())
		if s.Allow != nil && !s.Allow(ip) {
			conn.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close() // too many unidentified connections
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn, ip.String())
		}()
	}
}

func (s *Server) handle(conn net.Conn, from string) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	buf := make([]byte, headerLen)
	_, err := io.ReadFull(conn, buf)
	h, ok := decodeHeader(buf)
	<-s.sem
	if err != nil || !ok {
		return
	}
	if h.Version != ProtocolVersion {
		conn.Write([]byte{statusBadVersion})
		return
	}
	if !h.valid() {
		conn.Write([]byte{statusBadRequest})
		return
	}
	sess, joined := s.join(h, from)
	if !joined {
		conn.Write([]byte{statusBusy})
		return
	}
	defer s.leave(sess)

	// The session's start fixes the end for all its streams, however late they
	// joined, so a client can't extend a test by reconnecting.
	end := sess.start.Add(time.Duration(h.Seconds) * time.Second)
	conn.SetDeadline(end.Add(grace))
	if _, err := conn.Write([]byte{statusOK}); err != nil {
		return
	}
	if h.Mode == ModeDownload {
		for time.Now().Before(end) {
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
		return
	}
	s.receive(conn, sess)
}

func (s *Server) receive(conn net.Conn, sess *session) {
	warm := sess.start.Add(warmup)
	buf := make([]byte, bufferSize)
	var total, measured uint64
	for {
		n, err := conn.Read(buf)
		total += uint64(n)
		if time.Now().After(warm) {
			measured += uint64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return
		}
	}
	report := make([]byte, 0, reportLen)
	report = binary.BigEndian.AppendUint64(report, total)
	report = binary.BigEndian.AppendUint64(report, measured)
	report = binary.BigEndian.AppendUint64(report, uint64(time.Since(warm).Milliseconds()))
	conn.Write(report)
}

func (s *Server) join(h header, from string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		s.cur = &session{head: h, from: from, start: time.Now(), joined: 1, active: 1}
		s.notify(s.cur, true)
		return s.cur, true
	}
	c := s.cur
	if c.head.Token == h.Token && c.from == from && c.head.Mode == h.Mode && c.joined < int(c.head.Streams) {
		c.joined++
		c.active++
		return c, true
	}
	return nil, false
}

func (s *Server) leave(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.active--
	if sess.active == 0 && s.cur == sess {
		s.cur = nil
		s.notify(sess, false)
	}
}

func (s *Server) notify(sess *session, active bool) {
	if s.OnSession != nil {
		go s.OnSession(Session{From: sess.from, Mode: sess.head.Mode.String(), Active: active})
	}
}

// Options configures a client run.
type Options struct {
	Streams int
	// Seconds is the length of each direction.
	Seconds int
	// Source optionally binds the local address, to test a specific adapter.
	Source netip.Addr
}

func (o *Options) defaults() {
	if o.Streams == 0 {
		o.Streams = 4
	}
	if o.Seconds == 0 {
		o.Seconds = 6
	}
}

// Result is a finished test. Rates are in megabits per second.
type Result struct {
	DownMbps    float64   `json:"downMbps"`
	UpMbps      float64   `json:"upMbps"`
	ConnectMs   float64   `json:"connectMs"`
	Streams     int       `json:"streams"`
	Seconds     int       `json:"seconds"`
	DownSamples []float64 `json:"downSamples"`
	UpSamples   []float64 `json:"upSamples"`
}

// Progress reports the current rate during a run.
type Progress struct {
	Direction string  `json:"direction"`
	Mbps      float64 `json:"mbps"`
	// Fraction is how far through the whole test this is, 0 to 1.
	Fraction float64 `json:"fraction"`
}

// sampleEvery is the resolution of the live rate.
const sampleEvery = 250 * time.Millisecond

// Run tests download and then upload against addr ("host:port").
func Run(ctx context.Context, addr string, opt Options, onProgress func(Progress)) (Result, error) {
	opt.defaults()
	if onProgress == nil {
		onProgress = func(Progress) {}
	}
	res := Result{Streams: opt.Streams, Seconds: opt.Seconds}

	report := func(direction string, base float64) func(float64, float64) {
		return func(mbps, frac float64) {
			onProgress(Progress{Direction: direction, Mbps: mbps, Fraction: base + frac/2})
		}
	}
	var err error
	if res.DownMbps, res.DownSamples, res.ConnectMs, err = runOne(ctx, addr, ModeDownload, opt, report("download", 0)); err != nil {
		return res, err
	}
	// The server needs a moment to close the last session's streams.
	time.Sleep(100 * time.Millisecond)
	if res.UpMbps, res.UpSamples, _, err = runOne(ctx, addr, ModeUpload, opt, report("upload", 0.5)); err != nil {
		return res, err
	}
	return res, nil
}

type streamResult struct {
	received uint64 // download: bytes after warmup at this end; upload: as reported
	windowMs uint64
	err      error
}

func runOne(ctx context.Context, addr string, mode Mode, opt Options, report func(mbps, frac float64)) (float64, []float64, float64, error) {
	h := header{Version: ProtocolVersion, Mode: mode, Streams: byte(opt.Streams), Seconds: byte(opt.Seconds)}
	rand.Read(h.Token[:])

	dialer := net.Dialer{Timeout: handshakeTimeout}
	if opt.Source.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(opt.Source, 0))
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The first stream goes alone: it finds out at once if the server is busy,
	// and its time to connect is the figure reported.
	dialStart := time.Now()
	first, err := openStream(runCtx, &dialer, addr, h)
	if err != nil {
		return 0, nil, 0, err
	}
	connectMs := float64(time.Since(dialStart).Microseconds()) / 1000
	start := time.Now()

	conns := []net.Conn{first}
	for i := 1; i < opt.Streams; i++ {
		c, err := openStream(runCtx, &dialer, addr, h)
		if err != nil {
			for _, open := range conns {
				open.Close()
			}
			return 0, nil, 0, err
		}
		conns = append(conns, c)
	}
	stop := context.AfterFunc(runCtx, func() {
		for _, c := range conns {
			c.Close()
		}
	})
	defer stop()

	duration := time.Duration(opt.Seconds) * time.Second
	var moved atomic.Uint64
	results := make(chan streamResult, len(conns))
	for _, c := range conns {
		go func() {
			defer c.Close()
			c.SetDeadline(start.Add(duration + grace))
			if mode == ModeDownload {
				results <- readStream(c, start.Add(warmup), start, &moved)
			} else {
				results <- writeStream(c, start.Add(duration), &moved)
			}
		}()
	}

	// Sample the live rate until every stream has reported.
	var samples []float64
	var last uint64
	lastAt := start
	tick := time.NewTicker(sampleEvery)
	defer tick.Stop()
	var total, windowMs uint64
	var firstErr error
	for pending := len(conns); pending > 0; {
		select {
		case r := <-results:
			pending--
			total += r.received
			windowMs = max(windowMs, r.windowMs)
			if r.err != nil && firstErr == nil {
				firstErr = r.err
			}
		case now := <-tick.C:
			cur := moved.Load()
			mbps := float64(cur-last) * 8 / now.Sub(lastAt).Seconds() / 1e6
			last, lastAt = cur, now
			samples = append(samples, mbps)
			report(mbps, min(1, now.Sub(start).Seconds()/duration.Seconds()))
		}
	}
	if ctx.Err() != nil {
		return 0, samples, connectMs, ctx.Err()
	}
	if firstErr != nil {
		return 0, samples, connectMs, firstErr
	}
	if windowMs == 0 {
		return 0, samples, connectMs, verdict.Err("err.speed.tooShort")
	}
	return float64(total) * 8 / (float64(windowMs) / 1000) / 1e6, samples, connectMs, nil
}

func openStream(ctx context.Context, d *net.Dialer, addr string, h header) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, verdict.Err("err.speed.connect", "addr", addr)
	}
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if _, err := c.Write(h.encode()); err != nil {
		c.Close()
		return nil, verdict.Err("err.speed.connect", "addr", addr)
	}
	status := make([]byte, 1)
	if _, err := io.ReadFull(c, status); err != nil {
		c.Close()
		return nil, verdict.Err("err.speed.noAnswer", "addr", addr)
	}
	switch status[0] {
	case statusOK:
		return c, nil
	case statusBusy:
		c.Close()
		return nil, verdict.Err("err.speed.busy")
	case statusBadVersion:
		c.Close()
		return nil, verdict.Err("err.speed.version")
	}
	c.Close()
	return nil, verdict.Err("err.speed.refused")
}

func readStream(c net.Conn, warm, start time.Time, moved *atomic.Uint64) streamResult {
	buf := make([]byte, bufferSize)
	var measured uint64
	for {
		n, err := c.Read(buf)
		moved.Add(uint64(n))
		if time.Now().After(warm) {
			measured += uint64(n)
		}
		if errors.Is(err, io.EOF) {
			return streamResult{received: measured, windowMs: uint64(time.Since(warm).Milliseconds())}
		}
		if err != nil {
			return streamResult{err: verdict.Err("err.speed.interrupted")}
		}
	}
}

func writeStream(c net.Conn, until time.Time, moved *atomic.Uint64) streamResult {
	for time.Now().Before(until) {
		n, err := c.Write(payload)
		moved.Add(uint64(n))
		if err != nil {
			return streamResult{err: verdict.Err("err.speed.interrupted")}
		}
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return streamResult{err: verdict.Err("err.speed.interrupted")}
	}
	if err := tcp.CloseWrite(); err != nil {
		return streamResult{err: verdict.Err("err.speed.interrupted")}
	}
	rep := make([]byte, reportLen)
	if _, err := io.ReadFull(c, rep); err != nil {
		return streamResult{err: verdict.Err("err.speed.noReport")}
	}
	return streamResult{received: binary.BigEndian.Uint64(rep[8:]), windowMs: binary.BigEndian.Uint64(rep[16:])}
}
