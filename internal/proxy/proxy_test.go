package proxy

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

const (
	httpURL  = "http://www.msftconnecttest.com/connecttest.txt"
	httpsURL = "https://www.google.com/generate_204"
)

var testURLs = []string{httpURL, httpsURL}

func hosts(list []*url.URL) string {
	var out []string
	for _, u := range list {
		out = append(out, u.Host)
	}
	return strings.Join(out, ",")
}

func TestParseList(t *testing.T) {
	cases := []struct {
		name, list, scheme, want string
	}{
		{"plain", "proxy:8080", "http", "proxy:8080"},
		{"plain applies to https too", "proxy:8080", "https", "proxy:8080"},
		{"no port", "proxy", "http", "proxy:80"},
		{"url form", "http://proxy:3128", "http", "proxy:3128"},
		{"failover list", "a:8080;b:8080", "https", "a:8080,b:8080"},
		{"space separated", "a:8080 b:8080", "http", "a:8080,b:8080"},
		{"per scheme", "http=a:80;https=b:443", "https", "b:443"},
		{"per scheme, other", "http=a:80;https=b:443", "http", "a:80"},
		{"scheme not listed means direct", "ftp=a:21", "https", ""},
		{"specific beats general", "c:1;https=b:443", "https", "b:443"},
		{"direct token", "DIRECT", "http", ""},
		{"direct as fallback", "a:8080;DIRECT", "http", "a:8080"},
		{"empty", "", "http", ""},
		{"ipv6", "[2001:db8::1]:3128", "http", "[2001:db8::1]:3128"},
		{"unsupported scheme skipped", "socks5://s:1080;a:80", "http", "a:80"},
		{"junk skipped", "://;a:80", "http", "a:80"},
	}
	for _, c := range cases {
		if got := hosts(ParseList(c.list, c.scheme)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseListDropsCredentials(t *testing.T) {
	got := ParseList("http://user:secret@proxy:8080", "http")
	if len(got) != 1 || got[0].User != nil {
		t.Fatalf("%v", got)
	}
}

func TestBypassed(t *testing.T) {
	cases := []struct {
		host, list string
		want       bool
	}{
		{"server", "<local>", true},
		{"www.google.com", "<local>", false},
		{"www.firma.intern", "*.intern", true},
		{"www.google.com", "*.intern;10.*", false},
		{"10.1.2.3", "*.intern;10.*", true},
		{"WWW.Google.COM", "*.google.com", true},
		{"www.google.com", "http://www.google.com:80", true},
		{"www.google.com", "", false},
		{"www.google.com", "[bad", false},
	}
	for _, c := range cases {
		if got := Bypassed(c.host, c.list); got != c.want {
			t.Errorf("%q in %q = %v", c.host, c.list, got)
		}
	}
}

type fakeDiscoverer struct {
	wpadURL string
	wpadErr error
	pac     map[string]string // PAC URL to proxy list
	pacErr  error
	wpads   int
}

func (f *fakeDiscoverer) WPAD() (string, error) {
	f.wpads++
	if f.wpadErr != nil {
		return "", f.wpadErr
	}
	return f.wpadURL, nil
}

func (f *fakeDiscoverer) Evaluate(pacURL, _ string) (string, error) {
	if f.pacErr != nil {
		return "", f.pacErr
	}
	return f.pac[pacURL], nil
}

func TestResolvePrecedence(t *testing.T) {
	const wpadPAC, cfgPAC = "http://wpad/wpad.dat", "http://cfg/proxy.pac"
	offersWPAD := func() *fakeDiscoverer {
		return &fakeDiscoverer{wpadURL: wpadPAC, pac: map[string]string{wpadPAC: "wpad-proxy:8080", cfgPAC: "pac-proxy:8080"}}
	}
	noWPAD := func() *fakeDiscoverer {
		return &fakeDiscoverer{wpadErr: ErrNoWPAD, pac: map[string]string{cfgPAC: "pac-proxy:8080"}}
	}
	cases := []struct {
		name  string
		s     Settings
		d     *fakeDiscoverer
		want  Source
		proxy string
	}{
		{"auto-detect finds WPAD", Settings{AutoDetect: true}, offersWPAD(), SourceWPAD, "wpad-proxy:8080"},
		{"WPAD beats PAC and manual", Settings{AutoDetect: true, PACURL: cfgPAC, Manual: "m:1"}, offersWPAD(), SourceWPAD, "wpad-proxy:8080"},
		{"no WPAD falls to PAC", Settings{AutoDetect: true, PACURL: cfgPAC}, noWPAD(), SourcePAC, "pac-proxy:8080"},
		{"no WPAD falls to manual", Settings{AutoDetect: true, Manual: "m:1"}, noWPAD(), SourceManual, "m:1"},
		{"PAC beats manual", Settings{PACURL: cfgPAC, Manual: "m:1"}, noWPAD(), SourcePAC, "pac-proxy:8080"},
		{"manual only", Settings{Manual: "m:1"}, offersWPAD(), SourceManual, "m:1"},
		{"machine-wide WinHTTP", Settings{WinHTTP: "w:1"}, noWPAD(), SourceWinHTTP, "w:1"},
		{"manual beats WinHTTP", Settings{Manual: "m:1", WinHTTP: "w:1"}, noWPAD(), SourceManual, "m:1"},
		{"nothing set, WPAD found anyway", Settings{}, offersWPAD(), SourceWPADOff, "wpad-proxy:8080"},
		{"nothing at all", Settings{}, noWPAD(), SourceNone, ""},
		{"auto-detect on, no WPAD", Settings{AutoDetect: true}, noWPAD(), SourceNone, ""},
	}
	for _, c := range cases {
		r := Resolve(c.s, c.d, testURLs)
		if r.Source != c.want || hosts(r.Primary(testURLs)) != c.proxy {
			t.Errorf("%s: %s via %q, want %s via %q", c.name, r.Source, hosts(r.Primary(testURLs)), c.want, c.proxy)
		}
		if !r.Issue.IsZero() {
			t.Errorf("%s: unexpected issue %s", c.name, r.Issue)
		}
	}
}

func TestManualProxyDoesNotProbeWPAD(t *testing.T) {
	d := &fakeDiscoverer{wpadErr: ErrNoWPAD}
	Resolve(Settings{Manual: "m:1"}, d, testURLs)
	if d.wpads != 0 {
		t.Error("a machine with a fixed proxy shouldn't go looking for WPAD")
	}
}

func TestBrokenPACIsReportedAndFallsBack(t *testing.T) {
	d := &fakeDiscoverer{wpadErr: ErrNoWPAD, pacErr: errors.New("download failed")}
	r := Resolve(Settings{PACURL: "http://cfg/p.pac", Manual: "m:1"}, d, testURLs)
	if r.Source != SourceManual || r.Issue.Key != "proxy.issue.pac" {
		t.Errorf("source %s, issue %s", r.Source, r.Issue)
	}
	r = Resolve(Settings{PACURL: "http://cfg/p.pac"}, d, testURLs)
	if r.Source != SourceNone || r.Issue.IsZero() {
		t.Errorf("a configured PAC that fails must be reported even when going direct: %+v", r)
	}
}

func TestPACMayGoDirect(t *testing.T) {
	d := &fakeDiscoverer{wpadErr: ErrNoWPAD, pac: map[string]string{"http://p": ""}}
	r := Resolve(Settings{PACURL: "http://p"}, d, testURLs)
	if r.Source != SourcePAC || r.Primary(testURLs) != nil {
		t.Errorf("%+v", r)
	}
}

func TestBypassAppliesPerURL(t *testing.T) {
	r := Resolve(Settings{Manual: "m:1", ManualBypass: "*.google.com"}, &fakeDiscoverer{}, testURLs)
	if len(r.Routes[httpsURL]) != 0 || len(r.Routes[httpURL]) != 1 {
		t.Errorf("%+v", r.Routes)
	}
}

func TestOverrideBeatsEverything(t *testing.T) {
	const pac = "http://mine/p.pac"
	d := &fakeDiscoverer{wpadURL: "http://wpad/w", pac: map[string]string{"http://wpad/w": "w:1", pac: "from-pac:1"}}
	base := Settings{AutoDetect: true, Manual: "m:1"}

	withMode := func(o Override) Result {
		s := base
		s.Override = o
		return Resolve(s, d, testURLs)
	}
	if r := withMode(Override{Mode: OverrideDirect}); r.Source != SourceOverrideDirect || r.Primary(testURLs) != nil {
		t.Errorf("direct: %+v", r)
	}
	if r := withMode(Override{Mode: OverrideManual, Address: "mine:3128"}); r.Source != SourceOverrideManual || hosts(r.Primary(testURLs)) != "mine:3128" {
		t.Errorf("manual: %+v", r)
	}
	if r := withMode(Override{Mode: OverridePAC, PACURL: pac}); r.Source != SourceOverridePAC || hosts(r.Primary(testURLs)) != "from-pac:1" {
		t.Errorf("pac: %+v", r)
	}
	if r := withMode(Override{Mode: OverrideAuto}); r.Source != SourceWPAD {
		t.Errorf("auto must still detect: %+v", r)
	}
	if r := withMode(Override{}); r.Source != SourceWPAD {
		t.Errorf("no setting must still detect: %+v", r)
	}
	r := withMode(Override{Mode: OverrideManual, Address: "mine:3128", Bypass: "*.google.com"})
	if len(r.Routes[httpsURL]) != 0 || len(r.Routes[httpURL]) != 1 {
		t.Errorf("bypass: %+v", r.Routes)
	}
}

func TestBrokenOverridePACDoesNotFallBackToAnotherProxy(t *testing.T) {
	d := &fakeDiscoverer{wpadURL: "http://wpad/w", pacErr: errors.New("nope")}
	s := Settings{AutoDetect: true, Manual: "m:1", Override: Override{Mode: OverridePAC, PACURL: "http://mine/p"}}
	r := Resolve(s, d, testURLs)
	if r.Primary(testURLs) != nil || r.Issue.IsZero() || d.wpads != 0 {
		t.Errorf("%+v, wpads=%d", r, d.wpads)
	}
}

func TestLogonPolicy(t *testing.T) {
	cases := []struct {
		name    string
		source  Source
		trusted []string
		want    LogonLevel
	}{
		{"manual proxy", SourceManual, nil, LogonAlways},
		{"admin PAC", SourcePAC, nil, LogonAlways},
		{"machine-wide", SourceWinHTTP, nil, LogonAlways},
		{"typed in this app", SourceOverrideManual, nil, LogonAlways},
		{"PAC in this app", SourceOverridePAC, nil, LogonAlways},
		{"WPAD, Windows uses it", SourceWPAD, nil, LogonIntranet},
		{"WPAD, Windows doesn't use it: never volunteer credentials", SourceWPADOff, nil, LogonNever},
		{"no proxy", SourceNone, nil, LogonNever},
		{"approved WPAD host", SourceWPADOff, []string{"PROXY:8080"}, LogonAlways},
		{"approval is per host", SourceWPADOff, []string{"other:8080"}, LogonNever},
		{"approval upgrades WPAD too", SourceWPAD, []string{"proxy:8080"}, LogonAlways},
	}
	for _, c := range cases {
		if got := LogonPolicy(c.source, "proxy:8080", c.trusted); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestChooseScheme(t *testing.T) {
	all := SchemeBasic | SchemeNTLM | SchemeDigest | SchemeNegotiate
	cases := []struct {
		name    string
		offered uint32
		typed   bool
		want    uint32
	}{
		{"prefers Negotiate", all, false, SchemeNegotiate},
		{"then NTLM", SchemeBasic | SchemeNTLM, false, SchemeNTLM},
		{"Windows credentials never go over Basic", SchemeBasic, false, 0},
		{"or Digest", SchemeDigest, false, 0},
		{"typed may use Digest", SchemeBasic | SchemeDigest, true, SchemeDigest},
		{"typed may use Basic if that's all there is", SchemeBasic, true, SchemeBasic},
		{"typed still prefers the strongest", all, true, SchemeNegotiate},
		{"nothing offered", 0, true, 0},
	}
	for _, c := range cases {
		if got := ChooseScheme(c.offered, c.typed); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}

func TestCheckOverride(t *testing.T) {
	good := []Override{
		{},
		{Mode: OverrideAuto},
		{Mode: OverrideDirect},
		{Mode: OverrideManual, Address: "proxy:8080"},
		{Mode: OverrideManual, Address: "a:8080;b:8080"},
		{Mode: OverridePAC, PACURL: "https://cfg.example/proxy.pac"},
	}
	for _, o := range good {
		if m := CheckOverride(o); !m.IsZero() {
			t.Errorf("%+v rejected: %s", o, m)
		}
	}
	bad := []Override{
		{Mode: OverrideManual},
		{Mode: OverrideManual, Address: ";;"},
		{Mode: OverrideManual, Address: "http://user:secret@proxy:8080"},
		{Mode: OverridePAC},
		{Mode: OverridePAC, PACURL: "file:///c:/x.pac"},
		{Mode: OverridePAC, PACURL: "http://u:p@host/x.pac"},
		{Mode: "bogus"},
	}
	for _, o := range bad {
		if m := CheckOverride(o); m.IsZero() {
			t.Errorf("%+v accepted", o)
		}
	}
}
