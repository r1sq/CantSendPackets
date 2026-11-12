package loop

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"time"
)

// maxTracked bounds memory during a storm of unique frames.
const maxTracked = 100_000

// Repeat is a frame seen over and over.
type Repeat struct {
	SourceMAC string `json:"sourceMac"`
	EtherType string `json:"etherType"`
	Count     int    `json:"count"`
	PeakPerS  int    `json:"peakPerSecond"`
}

// Talker is a source of multi-destination frames.
type Talker struct {
	SourceMAC string `json:"sourceMac"`
	Frames    int    `json:"frames"`
}

type frameStat struct {
	src, etherType string
	count          int
	second         int64
	inSecond       int
	peak           int
}

// analyzer accumulates everything learned from captured frames.
type analyzer struct {
	nonce     [nonceLen]byte
	frames    int
	stats     map[uint64]*frameStat
	sources   map[string]int
	broadcast map[uint16]int
	control   map[uint16]int
}

func newAnalyzer(nonce [nonceLen]byte) *analyzer {
	return &analyzer{
		nonce:     nonce,
		stats:     map[uint64]*frameStat{},
		sources:   map[string]int{},
		broadcast: map[uint16]int{},
		control:   map[uint16]int{},
	}
}

// observe takes one captured frame. It runs for every frame in a storm, so it
// stays allocation-light for frames it has seen already.
func (a *analyzer) observe(at time.Time, f []byte) {
	if len(f) < 14 {
		return
	}
	if dst, seq, ok := probeID(f, a.nonce); ok {
		// Probes are counted apart: their repeats are the echo test's job.
		switch {
		case bytes.Equal(dst, broadcastMAC):
			a.broadcast[seq]++
		case bytes.Equal(dst, controlMAC):
			a.control[seq]++
		}
		return
	}
	a.frames++
	h := fnv.New64a()
	h.Write(f)
	key := h.Sum64()

	st := a.stats[key]
	if st == nil {
		if len(a.stats) >= maxTracked {
			return
		}
		src := net.HardwareAddr(f[6:12]).String()
		st = &frameStat{src: src, etherType: fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(f[12:]))}
		a.stats[key] = st
	}
	st.count++
	if sec := at.Unix(); sec != st.second {
		st.second, st.inSecond = sec, 0
	}
	st.inSecond++
	if st.inSecond > st.peak {
		st.peak = st.inSecond
	}
	if len(a.sources) < maxTracked || a.sources[st.src] > 0 {
		a.sources[st.src]++
	}
}

// echo summarises the probe counts. See Echo for what the fields mean.
func (a *analyzer) echo(sent int) *Echo {
	maxCopies := 0
	for _, n := range a.broadcast {
		if n > maxCopies {
			maxCopies = n
		}
	}
	maxControl := 0
	for _, n := range a.control {
		if n > maxControl {
			maxControl = n
		}
	}
	// Baseline is how many copies we'd see with no loop at all. It's capped
	// because a dumb switch forwards the control frame too; in a real loop the
	// control count is then huge and must not excuse the broadcast copies.
	baseline := min(maxControl, 2)
	extra := max(maxCopies-baseline, 0)
	return &Echo{Sent: sent, MaxCopies: maxCopies, ControlCopies: maxControl, Baseline: baseline, Extra: extra}
}

func (a *analyzer) topRepeats(limit int) []Repeat {
	out := []Repeat{}
	for _, st := range a.stats {
		if st.peak >= RepeatWarnPerS {
			out = append(out, Repeat{SourceMAC: st.src, EtherType: st.etherType, Count: st.count, PeakPerS: st.peak})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PeakPerS != out[j].PeakPerS {
			return out[i].PeakPerS > out[j].PeakPerS
		}
		return out[i].SourceMAC < out[j].SourceMAC
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (a *analyzer) topTalkers(limit int) []Talker {
	out := make([]Talker, 0, len(a.sources))
	for src, n := range a.sources {
		out = append(out, Talker{SourceMAC: src, Frames: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Frames != out[j].Frames {
			return out[i].Frames > out[j].Frames
		}
		return out[i].SourceMAC < out[j].SourceMAC
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
