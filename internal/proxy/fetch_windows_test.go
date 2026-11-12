package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// loginProxy is a forward proxy on loopback that demands a login, recording what
// WinHTTP really sends. This exercises the real API calls, values and handshake.
type loginProxy struct {
	*httptest.Server
	offered []string
	accept  func(auth string) bool

	mu       sync.Mutex
	auths    []string
	targets  []string
	requests int
}

func newLoginProxy(t *testing.T, offered []string, accept func(string) bool, ok http.HandlerFunc) *loginProxy {
	t.Helper()
	p := &loginProxy{offered: offered, accept: accept}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		p.mu.Lock()
		p.requests++
		p.targets = append(p.targets, r.Method+" "+r.URL.String()+" "+r.Host)
		if auth != "" {
			p.auths = append(p.auths, auth)
		}
		p.mu.Unlock()
		if len(offered) == 0 || (auth != "" && accept(auth)) {
			ok(w, r)
			return
		}
		for _, o := range offered {
			w.Header().Add("Proxy-Authenticate", o)
		}
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *loginProxy) host() string { return strings.TrimPrefix(p.URL, "http://") }

func (p *loginProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.auths...)
}

func hello(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hello")) }

const target = "http://site.invalid/page?x=1"

func fetch(t *testing.T, o FetchOptions) FetchResult {
	t.Helper()
	if o.URL == "" {
		o.URL = target
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	res, err := Fetch(o)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	return res
}

func TestFetchGoesThroughTheProxy(t *testing.T) {
	p := newLoginProxy(t, nil, nil, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonNever})
	if res.Status != 200 || string(res.Body) != "hello" {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(p.targets[0], "site.invalid/page?x=1") {
		t.Errorf("the name only exists at the proxy, so it must have gone there: %v", p.targets)
	}
	if len(p.seen()) != 0 {
		t.Errorf("credentials sent unasked: %v", p.seen())
	}
}

func TestWindowsLoginAnswersAnNTLMChallenge(t *testing.T) {
	p := newLoginProxy(t, []string{"NTLM"}, func(a string) bool { return strings.HasPrefix(a, "NTLM ") }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonAlways})
	if res.Status != 200 {
		t.Fatalf("status %d, sent %v", res.Status, p.seen())
	}
	got := p.seen()
	if len(got) == 0 {
		t.Fatal("no credentials sent")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got[0], "NTLM "))
	if err != nil || !strings.HasPrefix(string(raw), "NTLMSSP\x00") {
		t.Errorf("not an NTLM message: %q", got[0])
	}
	t.Logf("WinHTTP sent an NTLM negotiate message of %d bytes", len(raw))
}

func TestWindowsLoginPrefersNegotiate(t *testing.T) {
	p := newLoginProxy(t, []string{"NTLM", "Negotiate"}, func(a string) bool { return a != "" }, hello)
	fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonAlways})
	got := p.seen()
	if len(got) == 0 || !strings.HasPrefix(got[0], "Negotiate ") {
		t.Errorf("%v", got)
	}
}

// The security property: a proxy nobody approved gets nothing.
func TestNoCredentialsWithoutApproval(t *testing.T) {
	p := newLoginProxy(t, []string{"Negotiate", "NTLM"}, func(string) bool { return true }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonNever})
	if res.Status != 407 {
		t.Errorf("status %d", res.Status)
	}
	if got := p.seen(); len(got) != 0 {
		t.Errorf("sent to an unapproved proxy: %v", got)
	}
}

func TestWindowsLoginNeverUsesBasic(t *testing.T) {
	p := newLoginProxy(t, []string{`Basic realm="x"`}, func(string) bool { return true }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonAlways})
	if res.Status != 407 || len(p.seen()) != 0 {
		t.Errorf("status %d, sent %v", res.Status, p.seen())
	}
}

func TestIntranetLevelOnlyLogs(t *testing.T) {
	// Microsoft doesn't define "intranet", so this records what it does here. Either
	// way the fetch must end, and the app then asks the user.
	p := newLoginProxy(t, []string{"NTLM"}, func(a string) bool { return strings.HasPrefix(a, "NTLM ") }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonIntranet})
	t.Logf("intranet level, proxy on loopback: status %d, sent %d credential headers", res.Status, len(p.seen()))
	if res.Status != 200 && res.Status != 407 {
		t.Errorf("status %d", res.Status)
	}
}

func TestTypedCredentials(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("max:gehe:im"))
	p := newLoginProxy(t, []string{`Basic realm="x"`}, func(a string) bool { return a == want }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonNever, User: "max", Password: "gehe:im"})
	if res.Status != 200 || string(res.Body) != "hello" {
		t.Fatalf("%+v, sent %v", res, p.seen())
	}
}

func TestRefusedLoginEndsPromptly(t *testing.T) {
	p := newLoginProxy(t, []string{`Basic realm="x"`}, func(string) bool { return false }, hello)
	res := fetch(t, FetchOptions{ProxyHost: p.host(), Level: LogonNever, User: "max", Password: "wrong"})
	if res.Status != 407 {
		t.Errorf("status %d", res.Status)
	}
	if p.requests > maxSends {
		t.Errorf("%d requests", p.requests)
	}
}

func TestHTTPSChallengeOnConnect(t *testing.T) {
	p := newLoginProxy(t, []string{"NTLM"}, func(a string) bool { return strings.HasPrefix(a, "NTLM ") }, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	res, err := Fetch(FetchOptions{URL: "https://site.invalid/", ProxyHost: p.host(), Level: LogonAlways, Timeout: 5 * time.Second})
	t.Logf("result %+v, err %v, targets %v", res, err, p.targets)
	if len(p.seen()) == 0 || !strings.HasPrefix(p.seen()[0], "NTLM ") {
		t.Errorf("didn't answer the challenge on CONNECT: %v", p.seen())
	}
	if !strings.HasPrefix(p.targets[0], "CONNECT ") {
		t.Errorf("%v", p.targets)
	}
}

func TestRedirects(t *testing.T) {
	p := newLoginProxy(t, nil, nil, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "/next") {
			w.Write([]byte("arrived"))
			return
		}
		http.Redirect(w, r, "http://site.invalid/next", http.StatusFound)
	})
	if res := fetch(t, FetchOptions{ProxyHost: p.host()}); res.Status != 302 {
		t.Errorf("tests must see the redirect itself: %d", res.Status)
	}
	res := fetch(t, FetchOptions{ProxyHost: p.host(), FollowRedirects: true})
	if res.Status != 200 || string(res.Body) != "arrived" {
		t.Errorf("downloads must follow it: %+v", res)
	}
}

func TestBodyLimit(t *testing.T) {
	p := newLoginProxy(t, nil, nil, func(w http.ResponseWriter, _ *http.Request) { w.Write(make([]byte, 1<<20)) })
	res := fetch(t, FetchOptions{ProxyHost: p.host(), MaxBody: 100_000})
	if len(res.Body) < 100_000 || len(res.Body) > 200_000 {
		t.Errorf("read %d bytes", len(res.Body))
	}
}

func TestUnreachableProxyIsTranslated(t *testing.T) {
	p := newLoginProxy(t, nil, nil, hello)
	host := p.host()
	p.Close()
	_, err := Fetch(FetchOptions{URL: target, ProxyHost: host, Timeout: 3 * time.Second})
	if err == nil {
		t.Fatal("no error")
	}
	if verdict.AsMsg(err).Key == "err.raw" {
		t.Errorf("untranslated: %v", err)
	}
	t.Logf("%v", err)
}

func TestRealSettingsAndDetection(t *testing.T) {
	s := ReadSettings()
	t.Logf("this machine: auto-detect=%v pac=%q manual=%q bypass=%q winhttp=%q", s.AutoDetect, s.PACURL, s.Manual, s.ManualBypass, s.WinHTTP)

	urls := []string{"http://www.msftconnecttest.com/connecttest.txt", "https://www.google.com/generate_204"}
	start := time.Now()
	r := Detect(urls, Override{})
	t.Logf("detected after %v: source=%s pac=%q primary=%v issue=%s", time.Since(start).Round(time.Millisecond), r.Source, r.PACURL, r.Primary(urls), r.Issue)

	if r := Detect(urls, Override{Mode: OverrideDirect}); r.Source != SourceOverrideDirect {
		t.Errorf("%+v", r)
	}
	if r := Detect(urls, Override{Mode: OverrideManual, Address: "p:3128"}); hosts(r.Primary(urls)) != "p:3128" {
		t.Errorf("%+v", r)
	}
}
