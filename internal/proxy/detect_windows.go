package proxy

import (
	"errors"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

const (
	accessNoProxy    = 1
	accessNamedProxy = 3

	autoProxyAutoDetect = 0x1
	autoProxyConfigURL  = 0x2
	detectDHCP          = 0x1
	detectDNS           = 0x2

	errWinHTTPTimeout          = 12002
	errWinHTTPLoginFailure     = 12015
	errWinHTTPBadScript        = 12166
	errWinHTTPCantDownload     = 12167
	errWinHTTPAutodetectFailed = 12180

	// Bounds each slow step. WPAD's DNS and DHCP lookups can otherwise take a
	// long time on networks without it, which is most of them.
	stepTimeout = 6 * time.Second
)

var (
	winhttp = windows.NewLazySystemDLL("winhttp.dll")

	procGetIEConfig    = winhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procGetDefault     = winhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procOpen           = winhttp.NewProc("WinHttpOpen")
	procClose          = winhttp.NewProc("WinHttpCloseHandle")
	procSetTimeouts    = winhttp.NewProc("WinHttpSetTimeouts")
	procGetProxyForURL = winhttp.NewProc("WinHttpGetProxyForUrl")
	procDetectAutoURL  = winhttp.NewProc("WinHttpDetectAutoProxyConfigUrl")

	procGlobalFree = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

// These mirror the WinHTTP structs; Go's alignment matches C's on 64-bit Windows.
type ieProxyConfig struct {
	AutoDetect    int32
	AutoConfigURL *uint16
	Proxy         *uint16
	ProxyBypass   *uint16
}

type autoProxyOptions struct {
	Flags                 uint32
	AutoDetectFlags       uint32
	AutoConfigURL         *uint16
	Reserved1             uintptr
	Reserved2             uint32
	AutoLogonIfChallenged int32
}

type proxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

// take converts a WinHTTP-allocated string and frees it.
func take(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
	return s
}

// ReadSettings reads the current user's proxy settings and the machine-wide
// WinHTTP ones. Both are local and fast.
func ReadSettings() Settings {
	var s Settings
	var ie ieProxyConfig
	if r, _, _ := procGetIEConfig.Call(uintptr(unsafe.Pointer(&ie))); r != 0 {
		s.AutoDetect = ie.AutoDetect != 0
		s.PACURL = take(ie.AutoConfigURL)
		s.Manual = take(ie.Proxy)
		s.ManualBypass = take(ie.ProxyBypass)
	}
	var def proxyInfo
	if r, _, _ := procGetDefault.Call(uintptr(unsafe.Pointer(&def))); r != 0 {
		list, bypass := take(def.Proxy), take(def.ProxyBypass)
		if def.AccessType == accessNamedProxy {
			s.WinHTTP, s.WinHTTPBypass = list, bypass
		}
	}
	return s
}

// discoverer runs WinHTTP's PAC machinery. A PAC file is evaluated by Windows'
// own sandboxed service, never by this process.
type discoverer struct {
	mu      sync.Mutex
	session uintptr
}

// newDiscoverer opens a WinHTTP session. Close releases it.
func newDiscoverer() (*discoverer, error) {
	agent, _ := windows.UTF16PtrFromString("CantSendPackets")
	h, _, err := procOpen.Call(uintptr(unsafe.Pointer(agent)), accessNoProxy, 0, 0, 0)
	if h == 0 {
		return nil, err
	}
	ms := uintptr(stepTimeout.Milliseconds())
	procSetTimeouts.Call(h, ms, ms, ms, ms)
	return &discoverer{session: h}, nil
}

// Close releases the session.
func (d *discoverer) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session != 0 {
		procClose.Call(d.session)
		d.session = 0
	}
}

// bounded abandons a call that overruns. WinHTTP's own timeouts should end it
// soon after, and the goroutine just finishes unobserved.
func bounded[T any](fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(stepTimeout + time.Second):
		var zero T
		return zero, verdict.Err("err.timeout")
	}
}

// WPAD implements Discoverer.
func (d *discoverer) WPAD() (string, error) {
	return bounded(func() (string, error) {
		var pac *uint16
		r, _, err := procDetectAutoURL.Call(detectDHCP|detectDNS, uintptr(unsafe.Pointer(&pac)))
		if r == 0 || pac == nil {
			var errno windows.Errno
			if errors.As(err, &errno) && uint32(errno) != errWinHTTPAutodetectFailed {
				return "", describe(errno)
			}
			return "", ErrNoWPAD
		}
		return take(pac), nil
	})
}

// Evaluate implements Discoverer.
func (d *discoverer) Evaluate(pacURL, targetURL string) (string, error) {
	return bounded(func() (string, error) {
		target, err := windows.UTF16PtrFromString(targetURL)
		if err != nil {
			return "", err
		}
		pac, err := windows.UTF16PtrFromString(pacURL)
		if err != nil {
			return "", err
		}
		opts := autoProxyOptions{Flags: autoProxyConfigURL, AutoConfigURL: pac}
		info, err := d.getProxy(target, &opts)
		var errno windows.Errno
		if errors.As(err, &errno) && uint32(errno) == errWinHTTPLoginFailure {
			// The documented retry: only offer credentials if the PAC server asks.
			opts.AutoLogonIfChallenged = 1
			info, err = d.getProxy(target, &opts)
		}
		if err != nil {
			if errors.As(err, &errno) {
				return "", describe(errno)
			}
			return "", err
		}
		list, bypass := take(info.Proxy), take(info.ProxyBypass)
		_ = bypass // already applied by the PAC evaluation
		if info.AccessType == accessNoProxy {
			return "", nil
		}
		return list, nil
	})
}

func (d *discoverer) getProxy(target *uint16, opts *autoProxyOptions) (proxyInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == 0 {
		return proxyInfo{}, verdict.Err("err.timeout")
	}
	var info proxyInfo
	r, _, err := procGetProxyForURL.Call(d.session, uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return proxyInfo{}, err
	}
	return info, nil
}

func describe(errno windows.Errno) error {
	switch uint32(errno) {
	case errWinHTTPTimeout:
		return verdict.Err("err.timeout")
	case errWinHTTPCantDownload:
		return verdict.Err("err.proxy.pacDownload")
	case errWinHTTPBadScript:
		return verdict.Err("err.proxy.pacScript")
	}
	return verdict.Err("err.proxy.winhttp", "code", uint32(errno))
}

// Detect reads the settings and resolves them for the given test URLs. If WinHTTP
// can't be opened, a fixed proxy still works; only the discovery parts are lost.
func Detect(urls []string, override Override) Result {
	settings := ReadSettings()
	settings.Override = override
	d, err := newDiscoverer()
	if err != nil {
		return Resolve(settings, noDiscovery{}, urls)
	}
	defer d.Close()
	return Resolve(settings, d, urls)
}

type noDiscovery struct{}

func (noDiscovery) WPAD() (string, error) { return "", ErrNoWPAD }
func (noDiscovery) Evaluate(string, string) (string, error) {
	return "", verdict.Err("err.proxy.winhttp", "code", 0)
}
