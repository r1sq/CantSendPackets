package proxy

import (
	"errors"
	"net/url"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// WinHTTP's option and flag values. Its documentation names these but doesn't give
// numbers; they were checked against Wine's independent winhttp.h.
const (
	optionProxy          = 38
	optionAutologon      = 77
	optionRedirectPolicy = 88
	redirectNever        = 0

	autologonMedium = 0
	autologonLow    = 1
	autologonHigh   = 2

	authTargetProxy = 1
	flagSecure      = 0x00800000

	queryStatusCode = 19
	queryFlagNumber = 0x20000000

	errWinHTTPNameNotResolved = 12007
	errWinHTTPCannotConnect   = 12029
	errWinHTTPResendRequest   = 12032
	errWinHTTPSecureFailure   = 12175

	maxFetchBody = 64 * 1024
	// maxSends bounds the challenge and response exchange. NTLM's handshake and the
	// documented "resend" error are the only legitimate reasons to go around again.
	maxSends = 5
)

var (
	procConnect         = winhttp.NewProc("WinHttpConnect")
	procOpenRequest     = winhttp.NewProc("WinHttpOpenRequest")
	procSetOption       = winhttp.NewProc("WinHttpSetOption")
	procSendRequest     = winhttp.NewProc("WinHttpSendRequest")
	procReceiveResponse = winhttp.NewProc("WinHttpReceiveResponse")
	procQueryHeaders    = winhttp.NewProc("WinHttpQueryHeaders")
	procQueryAuth       = winhttp.NewProc("WinHttpQueryAuthSchemes")
	procSetCredentials  = winhttp.NewProc("WinHttpSetCredentials")
	procReadData        = winhttp.NewProc("WinHttpReadData")
)

// ErrCertificate means a TLS certificate failed verification.
var ErrCertificate = errors.New("certificate verification failed")

// FetchOptions describes one request through a proxy.
type FetchOptions struct {
	URL       string
	ProxyHost string
	Level     LogonLevel
	// User and Password are credentials the user typed. Empty means use the Windows
	// login, if Level allows it.
	User, Password string
	Timeout        time.Duration
	// FollowRedirects is for downloads. Connectivity tests leave it off, since a
	// redirect is a finding there. WinHTTP's default policy still refuses to go from
	// HTTPS to plain HTTP.
	FollowRedirects bool
	// MaxBody limits the response. Zero means the small default for web tests.
	MaxBody int
}

// FetchResult is the answer. Status 407 means the proxy refused or wasn't offered
// credentials.
type FetchResult struct {
	Status int
	Body   []byte
	RTT    time.Duration
}

// Fetch performs a GET through a proxy with WinHTTP, answering its login challenge.
//
// The Windows login is the documented auto-logon combined with WinHttpSetCredentials
// given no user name: the same thing libgit2 does for proxies. Credentials only last
// for one send, so they're set again before each one, as Microsoft's sample does.
func Fetch(o FetchOptions) (FetchResult, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return FetchResult{}, err
	}
	port := uint16(80)
	var flags uintptr
	if u.Scheme == "https" {
		port, flags = 443, flagSecure
	}

	agent, _ := windows.UTF16PtrFromString("CantSendPackets")
	session, _, callErr := procOpen.Call(uintptr(unsafe.Pointer(agent)), accessNoProxy, 0, 0, 0)
	if session == 0 {
		return FetchResult{}, describeFetch(callErr, u.Hostname())
	}
	defer procClose.Call(session)
	ms := uintptr(o.Timeout.Milliseconds())
	procSetTimeouts.Call(session, ms, ms, ms, ms)

	host, err := windows.UTF16PtrFromString(u.Hostname())
	if err != nil {
		return FetchResult{}, err
	}
	conn, _, callErr := procConnect.Call(session, uintptr(unsafe.Pointer(host)), uintptr(port), 0)
	if conn == 0 {
		return FetchResult{}, describeFetch(callErr, u.Hostname())
	}
	defer procClose.Call(conn)

	verb, _ := windows.UTF16PtrFromString("GET")
	path, err := windows.UTF16PtrFromString(u.RequestURI())
	if err != nil {
		return FetchResult{}, err
	}
	req, _, callErr := procOpenRequest.Call(conn, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), 0, 0, 0, flags)
	if req == 0 {
		return FetchResult{}, describeFetch(callErr, u.Hostname())
	}
	defer procClose.Call(req)

	proxyName, err := windows.UTF16PtrFromString(o.ProxyHost)
	if err != nil {
		return FetchResult{}, err
	}
	info := proxyInfo{AccessType: accessNamedProxy, Proxy: proxyName}
	if r, _, callErr := procSetOption.Call(req, optionProxy, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		return FetchResult{}, describeFetch(callErr, u.Hostname())
	}
	if !o.FollowRedirects {
		redirect := uint32(redirectNever)
		procSetOption.Call(req, optionRedirectPolicy, uintptr(unsafe.Pointer(&redirect)), 4)
	}
	maxBody := o.MaxBody
	if maxBody == 0 {
		maxBody = maxFetchBody
	}
	// Nothing goes out automatically: credentials are offered below, on purpose.
	autologon := uint32(autologonHigh)
	procSetOption.Call(req, optionAutologon, uintptr(unsafe.Pointer(&autologon)), 4)

	typed := o.User != ""
	var user, password *uint16
	if typed {
		if user, err = windows.UTF16PtrFromString(o.User); err != nil {
			return FetchResult{}, err
		}
		if password, err = windows.UTF16PtrFromString(o.Password); err != nil {
			return FetchResult{}, err
		}
	}

	start := time.Now()
	var scheme uint32
	for send := 0; send < maxSends; send++ {
		if scheme != 0 {
			r, _, callErr := procSetCredentials.Call(req, authTargetProxy, uintptr(scheme),
				uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(password)), 0)
			if r == 0 {
				return FetchResult{}, describeFetch(callErr, u.Hostname())
			}
		}
		if r, _, callErr := procSendRequest.Call(req, 0, 0, 0, 0, 0, 0); r == 0 {
			var errno windows.Errno
			if errors.As(callErr, &errno) && uint32(errno) == errWinHTTPResendRequest {
				continue // documented: go around until a real response arrives
			}
			return FetchResult{}, describeFetch(callErr, u.Hostname())
		}
		if r, _, callErr := procReceiveResponse.Call(req, 0); r == 0 {
			return FetchResult{}, describeFetch(callErr, u.Hostname())
		}
		var status, size uint32 = 0, 4
		r, _, callErr := procQueryHeaders.Call(req, queryStatusCode|queryFlagNumber, 0, uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&size)), 0)
		if r == 0 {
			return FetchResult{}, describeFetch(callErr, u.Hostname())
		}
		if status != 407 {
			body, err := readBody(req, maxBody)
			if err != nil {
				return FetchResult{}, describeFetch(err, u.Hostname())
			}
			return FetchResult{Status: int(status), Body: body, RTT: time.Since(start)}, nil
		}

		// Challenged. A second challenge after answering means the answer was refused.
		if scheme != 0 || (!typed && o.Level == LogonNever) {
			return FetchResult{Status: 407, RTT: time.Since(start)}, nil
		}
		var supported, first, target uint32
		r, _, callErr = procQueryAuth.Call(req, uintptr(unsafe.Pointer(&supported)), uintptr(unsafe.Pointer(&first)), uintptr(unsafe.Pointer(&target)))
		if r == 0 {
			return FetchResult{}, describeFetch(callErr, u.Hostname())
		}
		scheme = ChooseScheme(supported, typed)
		if scheme == 0 {
			return FetchResult{Status: 407, RTT: time.Since(start)}, nil
		}
		if !typed {
			level := uint32(autologonLow)
			if o.Level == LogonIntranet {
				level = autologonMedium
			}
			procSetOption.Call(req, optionAutologon, uintptr(unsafe.Pointer(&level)), 4)
		}
	}
	return FetchResult{Status: 407, RTT: time.Since(start)}, nil
}

func readBody(req uintptr, limit int) ([]byte, error) {
	var body []byte
	buf := make([]byte, 64*1024)
	for len(body) < limit {
		var n uint32
		r, _, callErr := procReadData.Call(req, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			return nil, callErr
		}
		if n == 0 {
			break
		}
		body = append(body, buf[:n]...)
	}
	return body, nil
}

func describeFetch(err error, host string) error {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return err
	}
	switch uint32(errno) {
	case errWinHTTPTimeout:
		return verdict.Err("err.timeout")
	case errWinHTTPNameNotResolved:
		return verdict.Err("err.dnsLookup", "host", host)
	case errWinHTTPCannotConnect:
		return verdict.Err("err.proxy.connect")
	case errWinHTTPSecureFailure:
		return ErrCertificate
	}
	return verdict.Err("err.proxy.winhttp", "code", uint32(errno))
}
