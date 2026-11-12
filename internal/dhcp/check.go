package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// ErrTimeout is returned by Transport.Recv when nothing arrived in time.
var ErrTimeout = errors.New("receive timeout")

// Transport moves DHCP payloads on and off the network. Probe calls it from a
// single goroutine, so implementations need not be concurrency-safe.
type Transport interface {
	Send(payload []byte) error
	Recv(timeout time.Duration) (ServerReply, error)
	Close() error
}

// Method names how offers were collected, which decides what silence means.
type Method string

const (
	MethodCapture Method = "capture" // Npcap: sends from 0.0.0.0, as a real DHCP client does
	MethodSocket  Method = "socket"  // UDP socket: can only send from the adapter's own IP
)

// Server is one distinct DHCP server that answered.
type Server struct {
	ServerID      netip.Addr   `json:"serverId"`
	SourceIP      netip.Addr   `json:"sourceIp"`
	SourceMAC     string       `json:"sourceMac"`
	OfferedIP     netip.Addr   `json:"offeredIp"`
	Mask          netip.Addr   `json:"mask"`
	Routers       []netip.Addr `json:"routers"`
	DNS           []netip.Addr `json:"dns"`
	Domain        string       `json:"domain"`
	LeaseSeconds  uint32       `json:"leaseSeconds"`
	Offers        int          `json:"offers"`
	FirstOfferMs  int64        `json:"firstOfferMs"`
	IsLeaseServer bool         `json:"isLeaseServer"`
}

// ID is the address that identifies the server: its option 54, or failing that
// the address the packet came from.
func (s Server) ID() netip.Addr {
	if s.ServerID.IsValid() {
		return s.ServerID
	}
	return s.SourceIP
}

// Options tune Probe. Zero values mean the defaults.
type Options struct {
	Sends    int
	Interval time.Duration
	Wait     time.Duration
}

func (o *Options) defaults() {
	if o.Sends == 0 {
		o.Sends = 3
	}
	if o.Interval == 0 {
		o.Interval = 1500 * time.Millisecond
	}
	if o.Wait == 0 {
		o.Wait = 6 * time.Second
	}
}

// Probe sends DISCOVERs and gathers offers until Wait elapses. One xid is used
// throughout so duplicates across retries collapse into one server.
func Probe(ctx context.Context, t Transport, mac net.HardwareAddr, xid uint32, opt Options) ([]Server, int, error) {
	opt.defaults()
	discover := BuildDiscover(xid, mac)

	start := time.Now()
	deadline := start.Add(opt.Wait)
	nextSend := start
	sent := 0
	found := map[string]*Server{}

	for time.Now().Before(deadline) && ctx.Err() == nil {
		if sent < opt.Sends && !time.Now().Before(nextSend) {
			if err := t.Send(discover); err != nil {
				if sent == 0 {
					return nil, 0, verdict.Err("err.dhcp.send", "detail", err.Error())
				}
			} else {
				sent++
			}
			nextSend = nextSend.Add(opt.Interval)
		}

		r, err := t.Recv(100 * time.Millisecond)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			return collect(found), sent, verdict.Err("err.dhcp.recv", "detail", err.Error())
		}
		o, err := ParseOffer(r.Payload, xid, mac)
		if err != nil {
			continue
		}

		srv := Server{ServerID: o.ServerID, SourceIP: r.SrcIP, SourceMAC: r.SrcMAC}
		key := srv.ID().String() + "|" + r.SrcMAC
		if existing, ok := found[key]; ok {
			existing.Offers++
			continue
		}
		srv.OfferedIP, srv.Mask, srv.Routers, srv.DNS = o.YourIP, o.Mask, o.Routers, o.DNS
		srv.Domain, srv.LeaseSeconds = o.Domain, o.Lease
		srv.Offers = 1
		srv.FirstOfferMs = time.Since(start).Milliseconds()
		if len(found) < 32 { // a flood of forged offers must not grow without bound
			found[key] = &srv
		}
	}
	return collect(found), sent, ctx.Err()
}

func collect(found map[string]*Server) []Server {
	out := make([]Server, 0, len(found))
	for _, s := range found {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstOfferMs != out[j].FirstOfferMs {
			return out[i].FirstOfferMs < out[j].FirstOfferMs
		}
		return out[i].SourceMAC < out[j].SourceMAC
	})
	return out
}

// Report is the outcome shown to the user.
type Report struct {
	Verdict     verdict.Level `json:"verdict"`
	Headline    verdict.Msg   `json:"headline"`
	Detail      verdict.Msg   `json:"detail"`
	Method      Method        `json:"method"`
	Servers     []Server      `json:"servers"`
	Sent        int           `json:"sent"`
	LeaseServer netip.Addr    `json:"leaseServer"`
}

// Evaluate turns the servers that answered into a verdict. leaseServer is where
// this adapter's current lease came from; the zero Addr means none or static.
func Evaluate(servers []Server, sent int, method Method, leaseServer netip.Addr, probeErr error) Report {
	for i := range servers {
		servers[i].IsLeaseServer = leaseServer.IsValid() && servers[i].ID() == leaseServer
	}
	r := Report{Method: method, Servers: servers, Sent: sent, LeaseServer: leaseServer}
	if servers == nil {
		r.Servers = []Server{}
	}

	ids := map[netip.Addr]bool{}
	macsByID := map[netip.Addr]map[string]bool{}
	for _, s := range servers {
		ids[s.ID()] = true
		if macsByID[s.ID()] == nil {
			macsByID[s.ID()] = map[string]bool{}
		}
		if s.SourceMAC != "" {
			macsByID[s.ID()][s.SourceMAC] = true
		}
	}

	set := func(level verdict.Level, key string, kv ...any) {
		r.Verdict = level
		r.Headline, r.Detail = verdict.Pair(key, kv...)
	}
	switch {
	case probeErr != nil && !errors.Is(probeErr, context.Canceled):
		r.Verdict = verdict.Unknown
		r.Headline = verdict.M("dhcp.failed.h")
		r.Detail = verdict.AsMsg(probeErr)

	case len(ids) >= 2:
		set(verdict.Problem, "dhcp.multiple", "count", len(ids))

	case len(ids) == 1 && anySpoofedID(macsByID):
		set(verdict.Warn, "dhcp.spoofed")

	case len(ids) == 1:
		s := servers[0]
		if leaseServer.IsValid() && s.ID() != leaseServer {
			set(verdict.Warn, "dhcp.otherServer", "server", s.ID(), "lease", leaseServer)
			break
		}
		set(verdict.OK, "dhcp.one", "server", s.ID())

	case method == MethodSocket:
		// Silence means little here. Measured on a real network: a server answered
		// every request from 0.0.0.0 and none from the client's own IP, with the same
		// machine, account and firewall rules.
		set(verdict.Unknown, "dhcp.silentSocket")

	case leaseServer.IsValid():
		set(verdict.Warn, "dhcp.leaseSilent", "lease", leaseServer, "sent", sent)

	default:
		set(verdict.Warn, "dhcp.silent", "sent", sent)
	}
	return r
}

func anySpoofedID(macsByID map[netip.Addr]map[string]bool) bool {
	for _, macs := range macsByID {
		if len(macs) > 1 {
			return true
		}
	}
	return false
}
