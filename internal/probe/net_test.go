package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

func TestBuildQuery(t *testing.T) {
	q, err := BuildQuery(0x1234, "a.bc.")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 2, 'b', 'c', 0, 0, 1, 0, 1}
	if string(q) != string(want) {
		t.Errorf("% x", q)
	}
	for _, bad := range []string{"", "a..b", strings.Repeat("x", 64) + ".com"} {
		if _, err := BuildQuery(1, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckResponse(t *testing.T) {
	reply := func(flagsLo byte) []byte { return []byte{0, 7, 0x81, flagsLo, 0, 1, 0, 1, 0, 0, 0, 0} }
	if err := CheckResponse(reply(0x80), 7); err != nil {
		t.Errorf("NOERROR: %v", err)
	}
	if err := CheckResponse(reply(0x82), 7); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Errorf("SERVFAIL: %v", err)
	}
	if err := CheckResponse(reply(0x83), 7); err != nil {
		t.Errorf("NXDOMAIN proves the server works, e.g. internal DNS behind a proxy: %v", err)
	}
	if err := CheckResponse(reply(0x80), 8); err == nil {
		t.Error("id mismatch accepted")
	}
	if err := CheckResponse(reply(0x80)[:5], 7); err == nil {
		t.Error("short reply accepted")
	}
	if err := CheckResponse([]byte{0, 7, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 7); err == nil {
		t.Error("a query echoed back isn't a reply")
	}
}

// fakeDNS answers on loopback. respond can rewrite the flags, or drop by
// returning nil.
func fakeDNS(t *testing.T, respond func(q []byte) []byte) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if r := respond(buf[:n]); r != nil {
				c.WriteToUDP(r, from)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func dnsCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestDNS(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	ok := func(q []byte) []byte {
		r := append([]byte(nil), q...)
		r[2], r[3] = 0x81, 0x80
		return r
	}
	t.Run("answers", func(t *testing.T) {
		ap := fakeDNS(t, ok)
		if _, err := DNS(dnsCtx(t), lo, ap.Addr().Unmap(), int(ap.Port()), "example.com"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("servfail is an error", func(t *testing.T) {
		ap := fakeDNS(t, func(q []byte) []byte {
			r := ok(q)
			r[3] = 0x82
			return r
		})
		if _, err := DNS(dnsCtx(t), lo, ap.Addr().Unmap(), int(ap.Port()), "example.com"); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("silence times out", func(t *testing.T) {
		ap := fakeDNS(t, func([]byte) []byte { return nil })
		_, err := DNS(dnsCtx(t), lo, ap.Addr().Unmap(), int(ap.Port()), "example.com")
		if err == nil || err.Error() != "err.dns.noReply" {
			t.Fatalf("%v", err)
		}
	})
	t.Run("stray datagram is ignored", func(t *testing.T) {
		ap := fakeDNS(t, func(q []byte) []byte {
			binary.BigEndian.PutUint16(q, binary.BigEndian.Uint16(q)+1)
			return ok(q)
		})
		_, err := DNS(dnsCtx(t), lo, ap.Addr().Unmap(), int(ap.Port()), "example.com")
		if err == nil || err.Error() != "err.dns.noReply" {
			t.Fatalf("%v", err)
		}
	})
}

func TestWebTest(t *testing.T) {
	const want = "Microsoft Connect Test"
	lo := netip.MustParseAddr("127.0.0.1")
	serve := func(h http.HandlerFunc) *httptest.Server {
		s := httptest.NewServer(h)
		t.Cleanup(s.Close)
		return s
	}
	ctx := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		t.Cleanup(cancel)
		return c
	}
	check := func(url string) WebCheck { return WebCheck{URL: url, WantStatus: 200, WantContains: want} }

	t.Run("real page", func(t *testing.T) {
		s := serve(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(want)) })
		if _, err := WebTest(ctx(), lo, check(s.URL), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("status-only check, like generate_204", func(t *testing.T) {
		s := serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
		if _, err := WebTest(ctx(), lo, WebCheck{URL: s.URL, WantStatus: 204}, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("redirect is a captive portal, and isn't followed", func(t *testing.T) {
		followed := false
		s := serve(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" {
				followed = true
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		})
		if _, err := WebTest(ctx(), lo, check(s.URL), nil); !errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
		if followed {
			t.Error("followed a redirect from an untrusted network")
		}
	})
	t.Run("wrong content is a captive portal", func(t *testing.T) {
		s := serve(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>sign in</html>")) })
		if _, err := WebTest(ctx(), lo, check(s.URL), nil); !errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("untrusted certificate is interception", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(want)) }))
		defer s.Close()
		if _, err := WebTest(ctx(), lo, check(s.URL), nil); !errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("server error is a failure, not a portal", func(t *testing.T) {
		s := serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
		_, err := WebTest(ctx(), lo, check(s.URL), nil)
		if err == nil || errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("unreachable is a plain failure", func(t *testing.T) {
		s := serve(func(http.ResponseWriter, *http.Request) {})
		url := s.URL
		s.Close()
		_, err := WebTest(ctx(), lo, check(url), nil)
		if err == nil || errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
}

// fakeProxy is a small forward proxy: plain requests get a canned response per
// test, and CONNECT is tunnelled or refused.
type fakeProxy struct {
	*httptest.Server
	plainRequests []string
	connects      []string
}

func newFakeProxy(t *testing.T, connectStatus int, plain http.HandlerFunc) (*fakeProxy, *url.URL) {
	t.Helper()
	p := &fakeProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			p.plainRequests = append(p.plainRequests, r.URL.String())
			plain(w, r)
			return
		}
		p.connects = append(p.connects, r.Host)
		if connectStatus != http.StatusOK {
			w.WriteHeader(connectStatus)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		// Take the connection over before answering, and write the answer by
		// hand: going through the ResponseWriter first can leave the response
		// and the client's first tunnel bytes in buffers the hijack bypasses.
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		go io.Copy(upstream, buffered) // includes anything already read past the request
		io.Copy(client, upstream)
	}))
	t.Cleanup(p.Close)
	u, err := url.Parse(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	return p, u
}

func TestWebTestThroughProxy(t *testing.T) {
	const want = "Microsoft Connect Test"
	// The target host doesn't exist: only a proxy could produce an answer, so a
	// pass proves the request really went through it.
	httpCheck := WebCheck{URL: "http://site.invalid/connecttest.txt", WantStatus: 200, WantContains: want}
	ctx := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		t.Cleanup(cancel)
		return c
	}
	lo := netip.MustParseAddr("127.0.0.1")
	serves := func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(want)) }

	t.Run("plain HTTP goes through the proxy", func(t *testing.T) {
		p, u := newFakeProxy(t, 200, serves)
		if _, err := WebTest(ctx(), lo, httpCheck, u); err != nil {
			t.Fatal(err)
		}
		if len(p.plainRequests) != 1 || !strings.Contains(p.plainRequests[0], "site.invalid") {
			t.Errorf("%v", p.plainRequests)
		}
	})
	t.Run("proxy wants a login, plain HTTP", func(t *testing.T) {
		_, u := newFakeProxy(t, 200, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(407) })
		if _, err := WebTest(ctx(), lo, httpCheck, u); !errors.Is(err, monitor.ErrProxyAuth) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("proxy wants a login, HTTPS", func(t *testing.T) {
		p, u := newFakeProxy(t, 407, serves)
		_, err := WebTest(ctx(), lo, WebCheck{URL: "https://site.invalid/", WantStatus: 204}, u)
		if !errors.Is(err, monitor.ErrProxyAuth) {
			t.Fatalf("%v", err)
		}
		if len(p.connects) != 1 || p.connects[0] != "site.invalid:443" {
			t.Errorf("%v", p.connects)
		}
	})
	t.Run("filter refuses HTTPS", func(t *testing.T) {
		_, u := newFakeProxy(t, 403, serves)
		_, err := WebTest(ctx(), lo, WebCheck{URL: "https://site.invalid/", WantStatus: 204}, u)
		if !errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("proxy can't reach upstream", func(t *testing.T) {
		_, u := newFakeProxy(t, 502, serves)
		_, err := WebTest(ctx(), lo, WebCheck{URL: "https://site.invalid/", WantStatus: 204}, u)
		if err == nil || errors.Is(err, monitor.ErrCaptive) || errors.Is(err, monitor.ErrProxyAuth) {
			t.Fatalf("%v", err)
		}
		if verdict.AsMsg(err).Key != "err.httpStatus" {
			t.Errorf("%v", err)
		}
	})
	t.Run("HTTPS really tunnels through", func(t *testing.T) {
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
		defer origin.Close()
		p, u := newFakeProxy(t, 200, serves)
		// The test certificate isn't trusted, so reaching the TLS verification
		// step at all proves the tunnel carried the handshake to the origin.
		_, err := WebTest(ctx(), lo, WebCheck{URL: origin.URL, WantStatus: 204}, u)
		if !errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
		if len(p.connects) != 1 {
			t.Errorf("%v", p.connects)
		}
	})
	t.Run("dead proxy is a plain failure", func(t *testing.T) {
		_, u := newFakeProxy(t, 200, serves)
		dead, _ := net.Listen("tcp", "127.0.0.1:0")
		u.Host = dead.Addr().String()
		dead.Close()
		_, err := WebTest(ctx(), lo, httpCheck, u)
		if err == nil || errors.Is(err, monitor.ErrCaptive) {
			t.Fatalf("%v", err)
		}
	})
}

func TestTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	lo := netip.MustParseAddr("127.0.0.1")
	if _, err := TCP(context.Background(), lo, addr); err != nil {
		t.Errorf("open port: %v", err)
	}
	l.Close()
	if _, err := TCP(context.Background(), lo, addr); err == nil {
		t.Error("closed port should fail")
	}
}

func TestLocalUDPMatchesFamily(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.2")
	v6 := netip.MustParseAddr("2001:db8::1")
	if localUDP(v4, v6) != nil {
		t.Error("a v4 source can't reach a v6 server")
	}
	if localUDP(v4, v4) == nil {
		t.Error("same family should bind")
	}
	if localUDP(netip.Addr{}, v4) != nil {
		t.Error("no source means no bind")
	}
}
