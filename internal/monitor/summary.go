package monitor

import "github.com/r1sq/CantSendPackets/internal/verdict"

// Summary is the one-line answer to "what's wrong with my network?".
type Summary struct {
	Verdict  verdict.Level `json:"verdict"`
	Headline verdict.Msg   `json:"headline"`
	Detail   verdict.Msg   `json:"detail"`
}

func sum(level verdict.Level, key string, kv ...any) Summary {
	h, d := verdict.Pair(key, kv...)
	return Summary{level, h, d}
}

// Summarize walks outward along the path. The first layer that fails is reported,
// because everything beyond it would fail too.
//
// The web probes decide whether the internet works, not ping: they're what users
// actually depend on, and they go through the proxy if there is one.
func Summarize(states []State, proxy ProxyState) Summary {
	var gateway, dns, proxies, pings, web []State
	for _, s := range states {
		switch {
		case s.Group == GroupGateway:
			gateway = append(gateway, s)
		case s.Group == GroupDNS:
			dns = append(dns, s)
		case s.Group == GroupProxy:
			proxies = append(proxies, s)
		case s.Group == GroupInternet && s.Kind == "ping":
			pings = append(pings, s)
		case s.Group == GroupInternet:
			web = append(web, s)
		}
	}

	checking := sum(verdict.Unknown, "summary.checking")
	if len(states) == 0 {
		return sum(verdict.Unknown, "summary.nothing")
	}
	if allPending(gateway) && allPending(pings) && allPending(web) {
		return checking
	}

	// Portals usually block ping as well, so these have to come before the
	// reachability checks or they would read as "no internet".
	for _, s := range web {
		if s.Captive {
			return sum(verdict.Warn, "summary.captive")
		}
	}
	for _, s := range web {
		if s.ProxyAuth {
			if proxy.AuthRejected {
				return sum(verdict.Warn, "summary.proxyAuthRejected", "proxy", proxy.Address)
			}
			return sum(verdict.Warn, "summary.proxyAuth", "proxy", proxy.Address)
		}
	}
	// Web probes wait for proxy detection. Until they've reported, a failing ping
	// doesn't mean much.
	if len(web) > 0 && allPending(web) {
		return checking
	}

	gatewayUp := anyAlive(gateway)

	if !anyAlive(web) {
		switch {
		case len(gateway) == 0 && !proxy.Active:
			return sum(verdict.Problem, "summary.noGateway")
		case !gatewayUp && !anyAlive(proxies) && !anyAlive(pings) && !allPending(gateway):
			return sum(verdict.Problem, "summary.gatewayDown")
		case proxy.Active && len(proxies) == 0:
			return checking
		case proxy.Active && !anyAlive(proxies):
			return sum(verdict.Problem, "summary.proxyDown", "proxy", proxy.Address)
		case proxy.Active:
			return sum(verdict.Problem, "summary.proxyNoInternet", "proxy", proxy.Address)
		case anyAlive(pings):
			// Ping gets out but the web doesn't: the classic sign of a required
			// proxy that wasn't found, or a firewall.
			return sum(verdict.Problem, "summary.webBlocked")
		default:
			return sum(verdict.Problem, "summary.upstream")
		}
	}

	if len(dns) == 0 {
		return sum(verdict.Warn, "summary.noDns")
	}
	if !anyAlive(dns) && !allPending(dns) {
		return sum(verdict.Problem, "summary.dnsDown")
	}
	for _, s := range dns {
		if s.Status == StatusDown {
			return sum(verdict.Warn, "summary.oneDnsDown", "addr", s.Addr)
		}
	}
	for _, s := range web {
		if s.Status == StatusDown {
			return sum(verdict.Warn, "summary.webPartial", "label", s.Label, "error", s.Error)
		}
	}
	for _, s := range states {
		if s.Kind != "ping" && s.Kind != "dns" && s.Kind != "tcp" {
			continue // sampled too rarely: one failure would read as heavy loss
		}
		if s.LossPct >= lossWarnPct && s.Status != StatusDown && s.Status != StatusBlocked {
			return sum(verdict.Warn, "summary.loss", "label", s.Label, "addr", s.Addr, "pct", s.LossPct)
		}
	}
	switch {
	case proxy.Active:
		return sum(verdict.OK, "summary.okProxy", "proxy", proxy.Address)
	case !gatewayUp && len(gateway) > 0:
		return sum(verdict.OK, "summary.okNoGatewayReply")
	}
	return sum(verdict.OK, "summary.ok")
}

func anyAlive(states []State) bool {
	for _, s := range states {
		if s.Status == StatusUp || s.Status == StatusDegraded {
			return true
		}
	}
	return false
}

func allPending(states []State) bool {
	for _, s := range states {
		if s.Status != StatusPending {
			return false
		}
	}
	return true
}
