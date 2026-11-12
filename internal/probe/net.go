// Package probe holds the individual network measurements.
package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/r1sq/CantSendPackets/internal/monitor"
	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// localUDP returns the source address for a UDP socket, matching the family of
// the destination. Binding it is what makes the check test *this* adapter on a
// multi-homed machine.
func localUDP(src, dst netip.Addr) *net.UDPAddr {
	if !src.IsValid() || src.Is4() != dst.Is4() {
		return nil
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0))
}

// BuildQuery encodes a minimal recursive A query.
func BuildQuery(id uint16, name string) ([]byte, error) {
	q := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(q[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS name %q", name)
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, 1) // A
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	return q, nil
}

var rcodeNames = map[byte]string{1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}

const rcodeNXDomain = 3

// CheckResponse validates a reply to BuildQuery. It deliberately doesn't parse
// answers: the question here is whether the server works. NXDOMAIN counts as
// working, because internal DNS on proxied networks often won't resolve public
// names at all, and that's normal rather than a dead server.
func CheckResponse(resp []byte, id uint16) error {
	if len(resp) < 12 || binary.BigEndian.Uint16(resp) != id || resp[2]&0x80 == 0 {
		return verdict.Err("err.dns.bad")
	}
	rcode := resp[3] & 0x0f
	if rcode == 0 || rcode == rcodeNXDomain {
		return nil
	}
	name, ok := rcodeNames[rcode]
	if !ok {
		name = fmt.Sprintf("%d", rcode)
	}
	return verdict.Err("err.dns.rcode", "rcode", name)
}

// DNS asks one specific server directly rather than using the system resolver,
// which would hide a dead server behind a working one.
func DNS(ctx context.Context, src, server netip.Addr, port int, name string) (time.Duration, error) {
	id := uint16(time.Now().UnixNano())
	q, err := BuildQuery(id, name)
	if err != nil {
		return 0, err
	}
	conn, err := net.DialUDP("udp", localUDP(src, server), net.UDPAddrFromAddrPort(netip.AddrPortFrom(server, uint16(port))))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	start := time.Now()
	if _, err := conn.Write(q); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, verdict.Err("err.dns.noReply")
			}
			return 0, err
		}
		rtt := time.Since(start)
		if n >= 2 && binary.BigEndian.Uint16(buf) != id {
			continue // stray datagram: keep waiting for ours
		}
		return rtt, CheckResponse(buf[:n], id)
	}
}

// WebCheck is a page with a known answer.
type WebCheck struct {
	URL          string
	WantStatus   int
	WantContains string
}

// WebTest fetches a known page, through proxy if one is given. It doesn't follow
// redirects, because a redirect is exactly how a captive portal shows up.
//
// It distinguishes what a user would need to act on: monitor.ErrCaptive when
// something answered but it isn't the real server (portal, content filter, or
// TLS interception this machine doesn't trust), and monitor.ErrProxyAuth when a
// proxy wants a login, which is proof the proxy works but not that the internet
// does.
func WebTest(ctx context.Context, src netip.Addr, check WebCheck, proxy *url.URL) (time.Duration, error) {
	dialer := net.Dialer{}
	if src.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, 0))
	}
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
		// HTTPS goes through CONNECT, whose refusal would otherwise surface as a
		// bare untyped error.
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
			return classifyStatus(resp.StatusCode)
		},
	}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	defer transport.CloseIdleConnections()
	client := http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, check.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "CantSendPackets")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, classifyErr(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	rtt := time.Since(start)
	if err != nil {
		return 0, classifyErr(err)
	}
	return rtt, judge(resp.StatusCode, body, check)
}

// judge decides what an answer means. Both HTTP stacks share it.
func judge(status int, body []byte, check WebCheck) error {
	if status == check.WantStatus && strings.Contains(string(body), check.WantContains) {
		return nil
	}
	if err := classifyStatus(status); err != nil {
		return err
	}
	return monitor.ErrCaptive // a success status, but not the page we asked for
}

// classifyStatus explains a status from a proxy or an interceptor. It returns
// nil for anything that isn't an error status.
func classifyStatus(status int) error {
	switch {
	case status == http.StatusProxyAuthRequired:
		return monitor.ErrProxyAuth
	case status >= 500:
		return verdict.Err("err.httpStatus", "status", status)
	case status >= 400:
		return monitor.ErrCaptive // refused by policy
	}
	return nil
}

// classifyErr turns the common failures into translated text, keeping typed
// errors from above intact. Anything else is shown as the OS or library wrote it.
func classifyErr(err error) error {
	var me *verdict.MsgError
	if errors.As(err, &me) {
		return me
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return monitor.ErrCaptive // someone else's certificate: interception
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return verdict.Err("err.dnsLookup", "host", dnsErr.Name)
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return verdict.Err("err.timeout")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// TCP measures a connection, which is all a proxy can be asked without credentials.
func TCP(ctx context.Context, src netip.Addr, hostport string) (time.Duration, error) {
	dialer := net.Dialer{}
	if src.IsValid() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, 0))
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return 0, classifyErr(err)
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}
