// Package peer lets instances of this app on the same network find each other.
//
// Each instance broadcasts a small hello every few seconds and answers others'
// hellos directly. Both directions matter: if one PC's firewall blocks incoming
// broadcasts, it can still find others from their replies to its own hello, and
// can then start tests towards them.
//
// Everything received is untrusted. Any device can send a hello, and all that
// gains it is a line in a list, whose size is capped and whose text is reduced to
// short printable ASCII.
package peer

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultPort is the UDP port hellos use.
	DefaultPort = 47116

	ProtocolVersion = 1

	maxPacket = 512
	maxPeers  = 64
	maxName   = 48
	idLen     = 32

	// Expiry is how long after its last hello a peer is dropped. It spans several
	// hellos so a few lost broadcasts don't make a peer flicker.
	Expiry = 18 * time.Second

	replyInterval = 2 * time.Second
)

var magic = []byte("CSPK1")

// Hello is what instances exchange.
type Hello struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Proto int    `json:"proto"`
	Reply bool   `json:"reply,omitempty"`
}

// Encode serialises a hello.
func Encode(h Hello) []byte {
	body, _ := json.Marshal(h)
	return append(append([]byte{}, magic...), body...)
}

// Decode parses and cleans a received packet.
func Decode(b []byte) (Hello, bool) {
	if len(b) > maxPacket || !bytes.HasPrefix(b, magic) {
		return Hello{}, false
	}
	var h Hello
	if err := json.Unmarshal(b[len(magic):], &h); err != nil {
		return Hello{}, false
	}
	if len(h.ID) != idLen || strings.Trim(h.ID, "0123456789abcdef") != "" {
		return Hello{}, false
	}
	if h.Port < 1 || h.Port > 65535 {
		return Hello{}, false
	}
	h.Name = sanitize(h.Name)
	return h, true
}

func sanitize(s string) string {
	var out strings.Builder
	for _, r := range s {
		if out.Len() == maxName {
			break
		}
		if r >= 0x20 && r < 0x7f {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// Peer is another instance.
type Peer struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	IP   netip.Addr `json:"ip"`
	Port int        `json:"port"`
	// Compatible is false for an instance whose test protocol differs.
	Compatible bool `json:"compatible"`

	lastSeen  time.Time
	lastReply time.Time
}

// Table tracks known peers. It isn't safe for concurrent use.
type Table struct {
	self  string
	peers map[string]*Peer
	// own is this PC's addresses. Another instance on the same PC, such as a
	// second window or another user's session, isn't a peer: a speed test to it
	// would never leave the machine.
	own map[netip.Addr]bool
}

// SetOwn records this PC's addresses and drops any peer listed from one of them.
// It reports whether the list changed.
func (t *Table) SetOwn(ips []netip.Addr) (changed bool) {
	t.own = make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		t.own[ip] = true
	}
	for id, p := range t.peers {
		if t.own[p.IP] {
			delete(t.peers, id)
			changed = true
		}
	}
	return changed
}

// NewTable creates a table that ignores its own instance's ID.
func NewTable(self string) *Table {
	return &Table{self: self, peers: map[string]*Peer{}}
}

// Observe records a hello. It reports whether the list changed, and whether the
// sender should get a reply. Replies are rate limited per peer, so a stream of
// forged hellos can't be used to make this instance send a stream of packets.
func (t *Table) Observe(h Hello, ip netip.Addr, now time.Time) (changed, reply bool) {
	if h.ID == t.self || t.own[ip] {
		return false, false
	}
	p := t.peers[h.ID]
	if p == nil {
		if len(t.peers) >= maxPeers {
			t.expire(now)
			if len(t.peers) >= maxPeers {
				return false, false
			}
		}
		p = &Peer{ID: h.ID}
		t.peers[h.ID] = p
		changed = true
	}
	if p.Name != h.Name || p.IP != ip || p.Port != h.Port {
		changed = true
	}
	p.Name, p.IP, p.Port = h.Name, ip, h.Port
	p.Compatible = h.Proto == ProtocolVersion
	p.lastSeen = now
	if !h.Reply && now.Sub(p.lastReply) >= replyInterval {
		p.lastReply = now
		reply = true
	}
	return changed, reply
}

func (t *Table) expire(now time.Time) (changed bool) {
	for id, p := range t.peers {
		if now.Sub(p.lastSeen) > Expiry {
			delete(t.peers, id)
			changed = true
		}
	}
	return changed
}

// Expire drops peers not heard from recently and reports whether any were.
func (t *Table) Expire(now time.Time) bool { return t.expire(now) }

// List returns peers in a stable order.
func (t *Table) List() []Peer {
	out := make([]Peer, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Find returns a peer by ID.
func (t *Table) Find(id string) (Peer, bool) {
	p, ok := t.peers[id]
	if !ok {
		return Peer{}, false
	}
	return *p, true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10") // also used by overlay VPNs

// AllowedSource says whether a source address may use this service. Private
// ranges pass, so sites reached over a routed VLAN or VPN work through a manually
// entered address. A public source doesn't, unless it's on a subnet of this PC,
// because that's what a forwarded port from the internet would look like.
func AllowedSource(ip netip.Addr, local []netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() || cgnat.Contains(ip) {
		return true
	}
	for _, p := range local {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
