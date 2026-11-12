// Package proxy works out how this machine reaches the web, following the order
// Windows and browsers use: WPAD if enabled, then a PAC URL, then a fixed proxy.
//
// The decision logic here is platform neutral and tested against a fake
// Discoverer. detect_windows.go supplies the real settings through WinHTTP.
package proxy

import (
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// Source says where a proxy setting came from.
type Source string

const (
	SourceNone    Source = "none"
	SourceWPAD    Source = "wpad"    // discovered, and Windows has auto-detect on
	SourceWPADOff Source = "wpadOff" // discovered, but Windows has auto-detect off
	SourcePAC     Source = "pac"
	SourceManual  Source = "manual"
	SourceWinHTTP Source = "winhttp" // machine-wide, set with netsh winhttp

	// Set in this app's own settings, which override everything above.
	SourceOverrideDirect Source = "overrideDirect"
	SourceOverrideManual Source = "overrideManual"
	SourceOverridePAC    Source = "overridePac"
)

// OverrideMode is the choice in this app's settings.
type OverrideMode string

const (
	OverrideAuto   OverrideMode = "auto"
	OverrideDirect OverrideMode = "direct"
	OverrideManual OverrideMode = "manual"
	OverridePAC    OverrideMode = "pac"
)

// Override replaces detection for this app's own tests. It changes nothing for
// other programs.
type Override struct {
	Mode    OverrideMode
	Address string
	Bypass  string
	PACURL  string
}

// Settings is what's configured on this machine.
type Settings struct {
	AutoDetect    bool
	PACURL        string
	Manual        string
	ManualBypass  string
	WinHTTP       string
	WinHTTPBypass string
	Override      Override
}

// Discoverer performs the slow network parts.
type Discoverer interface {
	// WPAD finds a PAC URL over DHCP and DNS. Finding none is ErrNoWPAD.
	WPAD() (pacURL string, err error)
	// Evaluate runs a PAC file for one URL. It returns WinHTTP's proxy list
	// format, where an empty list means go direct.
	Evaluate(pacURL, targetURL string) (proxies string, err error)
}

// ErrNoWPAD means the network doesn't offer WPAD, which is the normal case.
var ErrNoWPAD = verdict.Err("err.proxy.noWpad")

// Result is the outcome of detection.
type Result struct {
	Source Source
	PACURL string
	// Routes holds, per test URL, the proxies to try in order. Empty means direct.
	Routes map[string][]*url.URL
	// Issue is a configured mechanism that failed. It matters because the machine
	// then falls back to something other than what the admin intended.
	Issue verdict.Msg
}

// Primary returns the proxies in use, or nil for a direct connection.
func (r Result) Primary(urls []string) []*url.URL {
	for _, u := range urls {
		if len(r.Routes[u]) > 0 {
			return r.Routes[u]
		}
	}
	return nil
}

// Resolve applies the precedence to the given test URLs.
func Resolve(s Settings, d Discoverer, urls []string) Result {
	var issue verdict.Msg

	tryPAC := func(pacURL string, src Source) (Result, bool) {
		routes := map[string][]*url.URL{}
		for _, u := range urls {
			list, err := d.Evaluate(pacURL, u)
			if err != nil {
				issue = verdict.M("proxy.issue.pac", "url", pacURL, "detail", verdict.AsMsg(err))
				return Result{}, false
			}
			routes[u] = ParseList(list, schemeOf(u))
		}
		return Result{Source: src, PACURL: pacURL, Routes: routes}, true
	}
	wpad := func(src Source) (Result, bool) {
		pacURL, err := d.WPAD()
		if err != nil {
			return Result{}, false // nearly every network has no WPAD: not an issue
		}
		return tryPAC(pacURL, src)
	}
	fixed := func(list, bypass string, src Source) Result {
		routes := map[string][]*url.URL{}
		for _, u := range urls {
			if !Bypassed(hostOf(u), bypass) {
				routes[u] = ParseList(list, schemeOf(u))
			}
		}
		return Result{Source: src, Routes: routes}
	}

	result := func() Result {
		switch s.Override.Mode {
		case OverrideDirect:
			return Result{Source: SourceOverrideDirect, Routes: map[string][]*url.URL{}}
		case OverrideManual:
			return fixed(s.Override.Address, s.Override.Bypass, SourceOverrideManual)
		case OverridePAC:
			if r, ok := tryPAC(s.Override.PACURL, SourceOverridePAC); ok {
				return r
			}
			// The user asked for this PAC specifically: don't quietly use another
			// mechanism, report it and go direct.
			return Result{Source: SourceOverridePAC, PACURL: s.Override.PACURL, Routes: map[string][]*url.URL{}}
		}
		if s.AutoDetect {
			if r, ok := wpad(SourceWPAD); ok {
				return r
			}
		}
		if s.PACURL != "" {
			if r, ok := tryPAC(s.PACURL, SourcePAC); ok {
				return r
			}
		}
		if s.Manual != "" {
			return fixed(s.Manual, s.ManualBypass, SourceManual)
		}
		if s.WinHTTP != "" {
			return fixed(s.WinHTTP, s.WinHTTPBypass, SourceWinHTTP)
		}
		// Nothing configured. Look anyway, since a network offering WPAD to a
		// machine with auto-detect off is a useful finding in itself.
		if !s.AutoDetect && s.PACURL == "" {
			if r, ok := wpad(SourceWPADOff); ok {
				return r
			}
		}
		return Result{Source: SourceNone, Routes: map[string][]*url.URL{}}
	}()
	result.Issue = issue
	return result
}

// ParseList reads a Windows proxy list for a URL scheme. It accepts all of
// "host:8080", "a:8080;b:8080", "http=a:80;https=b:443", and "http://a:8080",
// separated by semicolons or spaces. The list comes from settings or a PAC file,
// so anything unusable is skipped.
func ParseList(list, scheme string) []*url.URL {
	tokens := strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' })
	var general, specific []*url.URL
	for _, tok := range tokens {
		target := &general
		if name, rest, ok := strings.Cut(tok, "="); ok {
			if !strings.EqualFold(name, scheme) {
				continue
			}
			tok, target = rest, &specific
		}
		if strings.EqualFold(tok, "DIRECT") {
			continue
		}
		if u := parseOne(tok); u != nil {
			*target = append(*target, u)
		}
	}
	if len(specific) > 0 {
		return specific
	}
	// A list naming other schemes only ("ftp=x") says nothing for this scheme,
	// and general stays empty, which means direct.
	return general
}

func parseOne(tok string) *url.URL {
	if !strings.Contains(tok, "://") {
		tok = "http://" + tok
	}
	u, err := url.Parse(tok)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	u.User, u.Path, u.RawQuery = nil, "", ""
	return u
}

// Bypassed applies a Windows bypass list: "*.intern;10.*;<local>".
func Bypassed(host, list string) bool {
	host = strings.ToLower(host)
	for _, tok := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' || r == ',' }) {
		tok = strings.ToLower(tok)
		if tok == "<local>" {
			if !strings.Contains(host, ".") {
				return true
			}
			continue
		}
		if _, rest, ok := strings.Cut(tok, "://"); ok {
			tok = rest
		}
		if h, _, err := net.SplitHostPort(tok); err == nil {
			tok = h
		}
		if ok, err := path.Match(tok, host); err == nil && ok {
			return true
		}
	}
	return false
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "http"
	}
	return u.Scheme
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// LogonLevel says when the logged-on user's Windows credentials may be offered
// to a proxy.
type LogonLevel int

const (
	LogonNever    LogonLevel = iota // only with credentials the user typed
	LogonIntranet                   // Windows decides: its default, intranet only
	LogonAlways
)

// LogonPolicy decides how far to trust a proxy with Windows credentials. An
// answer to NTLM can be cracked offline, so sending it to a machine that merely
// announced itself over WPAD is how rogue-WPAD attacks harvest credentials.
//
//   - Proxies someone chose (manual, PAC, machine-wide, or this app's settings) get
//     the login, as they would in a browser.
//   - WPAD with auto-detect on stays at Windows' own default, the level Microsoft
//     recommends. It may decline, and then the user is asked.
//   - WPAD with auto-detect off is something Windows itself wouldn't use, so it gets
//     nothing unless the user approves that host.
func LogonPolicy(source Source, host string, trusted []string) LogonLevel {
	for _, t := range trusted {
		if strings.EqualFold(t, host) {
			return LogonAlways
		}
	}
	switch source {
	case SourceManual, SourcePAC, SourceWinHTTP, SourceOverrideManual, SourceOverridePAC:
		return LogonAlways
	case SourceWPAD:
		return LogonIntranet
	}
	return LogonNever
}

// Authentication schemes, with WinHTTP's values.
const (
	SchemeBasic     uint32 = 0x1
	SchemeNTLM      uint32 = 0x2
	SchemeDigest    uint32 = 0x8
	SchemeNegotiate uint32 = 0x10
)

// ChooseScheme picks from what a proxy offers, strongest first, or 0 if none will
// do. Windows credentials only work with NTLM and Negotiate. Basic sends the
// password in the clear, so it's allowed only for credentials the user typed, and
// the login dialog says so.
func ChooseScheme(offered uint32, typedCredentials bool) uint32 {
	order := []uint32{SchemeNegotiate, SchemeNTLM}
	if typedCredentials {
		order = append(order, SchemeDigest, SchemeBasic)
	}
	for _, s := range order {
		if offered&s != 0 {
			return s
		}
	}
	return 0
}

// CheckOverride validates settings before they're saved. It returns the zero Msg
// if they're usable.
func CheckOverride(o Override) verdict.Msg {
	switch o.Mode {
	case OverrideAuto, OverrideDirect, "":
		return verdict.Msg{}
	case OverrideManual:
		if strings.Contains(o.Address, "@") {
			return verdict.M("settings.err.credentialsInAddress") // would be saved in clear text
		}
		if len(o.Address) > 512 || len(ParseList(o.Address, "http")) == 0 {
			return verdict.M("settings.err.badAddress")
		}
		return verdict.Msg{}
	case OverridePAC:
		u, err := url.Parse(o.PACURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || len(o.PACURL) > 2048 || u.User != nil {
			return verdict.M("settings.err.badPac")
		}
		return verdict.Msg{}
	}
	return verdict.M("settings.err.badAddress")
}
