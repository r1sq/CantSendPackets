package speed_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/r1sq/CantSendPackets/internal/peer"
	"github.com/r1sq/CantSendPackets/internal/speed"
)

// instance is what one running app does: an endpoint that's already listening,
// announced through discovery.
type instance struct {
	server *speed.Server
	peers  *peer.Service
}

func start(t *testing.T, ctx context.Context, self, other netip.Addr) instance {
	t.Helper()
	srv, err := speed.ListenAddr(net.JoinHostPort(self.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	svc := peer.Start(ctx, peer.Config{
		Name: self.String(), SpeedPort: srv.Port(), Port: 47398, NoWildcard: true, Interval: 40 * time.Millisecond,
		Locals: func() []peer.Local { return []peer.Local{{IP: self, Targets: []netip.Addr{other}}} },
	})
	return instance{srv, svc}
}

func await(t *testing.T, i instance) peer.Peer {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if list := i.peers.Peers(); len(list) == 1 {
			return list[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("instances didn't find each other")
	return peer.Peer{}
}

// The feature as a whole: two instances find each other with no configuration, and
// then either side can start a test against the other's endpoint.
func TestTwoInstancesFindAndTestEachOther(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs the whole 127.0.0.0/8 range on loopback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := start(t, ctx, netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("127.0.0.5"))
	b := start(t, ctx, netip.MustParseAddr("127.0.0.5"), netip.MustParseAddr("127.0.0.4"))

	for name, pair := range map[string][2]instance{"A tests B": {a, b}, "B tests A": {b, a}} {
		found := await(t, pair[0])
		if found.Port != pair[1].server.Port() || !found.Compatible {
			t.Fatalf("%s: discovered %+v", name, found)
		}
		res, err := speed.Run(ctx, fmt.Sprintf("%s:%d", found.IP, found.Port), speed.Options{Streams: 2, Seconds: 2}, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.DownMbps <= 0 || res.UpMbps <= 0 {
			t.Errorf("%s: %+v", name, res)
		}
		time.Sleep(150 * time.Millisecond)
	}
}
