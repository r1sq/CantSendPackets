package update

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// ErrProxyAuth means a proxy wants a login this client can't provide.
var ErrProxyAuth = errors.New("proxy authentication required")

// HTTPOptions configures HTTPGet.
type HTTPOptions struct {
	Proxy *url.URL
	// RootCAs replaces the system's trust store, for tests.
	RootCAs *x509.CertPool
}

// HTTPGet downloads over HTTPS, following redirects (GitHub sends release files to a
// CDN) but never out of HTTPS.
func HTTPGet(ctx context.Context, rawURL string, opt HTTPOptions, max int64) ([]byte, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if opt.Proxy != nil {
		transport.Proxy = http.ProxyURL(opt.Proxy)
	}
	if opt.RootCAs != nil {
		transport.TLSClientConfig.RootCAs = opt.RootCAs
	}
	transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
		if resp.StatusCode == http.StatusProxyAuthRequired {
			return ErrProxyAuth
		}
		return nil
	}
	defer transport.CloseIdleConnections()
	client := http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return verdict.Err("err.update.badResponse")
			}
			if len(via) >= 5 {
				return verdict.Err("err.update.badResponse")
			}
			return nil
		},
	}
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, verdict.Err("err.update.badResponse")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// GitHub's API refuses requests with no User-Agent.
	req.Header.Set("User-Agent", "CantSendPackets")
	req.Header.Set("Accept", "application/vnd.github+json, application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	if err := CheckStatus(resp.StatusCode); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, verdict.Err("err.update.tooLarge")
	}
	return data, nil
}

// CheckStatus turns an HTTP status into an error, or nil for 200.
func CheckStatus(status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusProxyAuthRequired:
		return ErrProxyAuth
	case http.StatusForbidden, http.StatusTooManyRequests:
		return verdict.Err("err.update.rateLimited")
	}
	return verdict.Err("err.httpStatus", "status", status)
}
