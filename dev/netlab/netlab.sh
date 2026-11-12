#!/usr/bin/env bash
# Runs the Linux checks against a small network built in isolated namespaces: a
# switch (bridge), a client, a DHCP server, a rogue DHCP server, and optionally a
# loop cable. Nothing touches the real network, and no root is needed: it runs in
# a user namespace (unshare -r), where it may create interfaces and raw sockets.
#
#	dev/netlab/netlab.sh            from the repository root
#
# NETLAB_OUT=dir keeps each check's JSON and fakenet's logs there.
# Exits non-zero if any check doesn't reach its expected verdict.
set -euo pipefail

if [ "${NETLAB_INNER:-}" != 1 ]; then
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	go build -o "$work/cspcheck" ./cmd/cspcheck
	go build -o "$work/fakenet" ./dev/fakenet
	NETLAB_INNER=1 NETLAB_BIN="$work" unshare --user --map-root-user --net --mount --propagation private bash "$0"
	exit $?
fi

bin=$NETLAB_BIN
out=${NETLAB_OUT:-$bin/results}
mkdir -p "$out"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

# --- the network
mount -t tmpfs tmpfs /run # a private /run, so ip netns can keep its handles there
mkdir -p /run/netns
ip link set lo up
ip link add br0 type bridge stp_state 0
ip link set br0 up
host() { # host NAME IFACE ADDR
	ip netns add "$1"
	ip -n "$1" link set lo up
	ip link add "$2" type veth peer name "$2p"
	ip link set "$2" netns "$1"
	ip link set "$2p" master br0 up
	ip -n "$1" addr add "$3/24" dev "$2"
	ip -n "$1" link set "$2" up
}
host client c0 10.99.0.10
host srv s0 10.99.0.1
host rogue r0 10.99.0.66
ip -n client route add default via 10.99.0.1
# Servers need a route to send to 255.255.255.255, as real ones have.
for ns in srv rogue; do ip -n "$ns" route add default dev "${ns:0:1}0"; done
client_mac=$(ip -n client -br link show c0 | awk '{print $3}')
sleep 1 # let the bridge ports reach forwarding

bg() { # bg NETNS fakenet-args... : run fakenet in the background
	local ns=$1
	shift
	ip netns exec "$ns" "$bin/fakenet" "$@" >"$out/fakenet-$ns-$1.log" 2>&1 &
	pids+=($!)
}
stop() { cleanup; pids=(); }

failures=0
check() { # check NAME EXPECT JQ-PATH cspcheck-args...
	local name=$1 expect=$2 path=$3
	shift 3
	ip netns exec client "$bin/cspcheck" "$@" >"$out/$name.json" 2>"$out/$name.err" || true
	local got
	got=$(jq -r "$path | \"\(.verdict) \(.headline.key)\"" "$out/$name.json" 2>/dev/null || echo "no output")
	if [[ "$got" == $expect ]]; then
		printf 'ok    %-28s %s\n' "$name" "$got"
	else
		printf 'FAIL  %-28s %s (want %s)\n' "$name" "$got" "$expect"
		failures=$((failures + 1))
	fi
	jq -c "$path | {method: (.method | if type == \"object\" then .key else . end), servers: [.servers[]? | .serverId], echo, rate: .rate.medianPps, repeats: [.repeats[]? | .sourceMac]} | with_entries(select(.value != null and .value != []))" "$out/$name.json" 2>/dev/null | sed 's/^/        /' || true
}

echo "== DHCP"
bg srv dhcp -ip 10.99.0.1 -only "$client_mac" -for 60s
sleep 0.5
check dhcp-one-capture "ok dhcp.one.h" .dhcp -checks dhcp
check dhcp-one-socket "ok dhcp.one.h" .dhcp -checks dhcp -dhcp-socket
bg rogue dhcp -ip 10.99.0.66 -only "$client_mac" -for 60s
sleep 0.5
check dhcp-rogue-capture "problem dhcp.multiple.h" .dhcp -checks dhcp
check dhcp-rogue-socket "problem dhcp.multiple.h" .dhcp -checks dhcp -dhcp-socket
stop

echo "== Loop"
# A real network always carries a few broadcasts; a silent one reads as counters
# that don't work.
bg rogue storm -ip 10.99.0.66 -pps 5 -for 60s
sleep 1
check loop-none-capture "ok loop.clean.h" .loop -checks loop
check loop-none-counters "ok loop.passiveClean.h" .loop -checks loop -no-capture
stop

# Two more bridge ports, joined outside the bridge by fakenet: a real loop, but
# one that drops whatever exceeds 1500 frames/s each way.
ip link add x0 type veth peer name x1
ip link add y0 type veth peer name y1
for i in x0 y0; do ip link set "$i" master br0 up; done
for i in x1 y1; do ip link set "$i" up; done
sleep 1
# The cable runs in the switch's own namespace, where x1 and y1 are.
"$bin/fakenet" loopcable -a x1 -b y1 -pps 1500 -for 60s >"$out/fakenet-loopcable.log" 2>&1 &
pids+=($!)
# Probes first, on a quiet loop: background broadcasts multiply until they fill
# the cable's limit, and then the cable drops the probes too.
check loop-real-capture "problem loop.echo.h" .loop -checks loop
# Without capture nothing is probed: the loop shows through the background
# broadcasts it multiplies, as on a real network.
bg rogue storm -ip 10.99.0.66 -pps 5 -for 60s
sleep 2
check loop-real-counters "problem loop.storm.h" .loop -checks loop -no-capture
stop
ip link del x0
ip link del y0

echo "== Storm without a loop"
bg rogue storm -ip 10.99.0.66 -pps 1500 -for 30s
sleep 2
check storm-capture "problem loop.stormNoEcho.h" .loop -checks loop
check storm-counters "problem loop.storm.h" .loop -checks loop -no-capture
stop

echo "== Discovery and speed test"
# srv runs an endpoint. A second copy on the client itself must not be listed:
# a test to it would never leave the machine.
ip netns exec srv "$bin/cspcheck" -serve 40s >"$out/serve-srv.json" 2>&1 &
pids+=($!)
ip netns exec client "$bin/cspcheck" -serve 40s >"$out/serve-client-other.json" 2>&1 &
pids+=($!)
sleep 1
ip netns exec client "$bin/cspcheck" -serve 30s -speedtest >"$out/speedtest.json" 2>"$out/speedtest.err" || true
got=$(jq -r '"peers=\([.peers[].ip] | join(",")) down=\(.speedTest.result.downMbps // 0 | floor) up=\(.speedTest.result.upMbps // 0 | floor) error=\(.speedTest.error // "")"' "$out/speedtest.json" 2>/dev/null || echo "no output")
if [[ "$got" =~ ^peers=10\.99\.0\.1\ down=[1-9][0-9]*\ up=[1-9][0-9]*\ error=$ ]]; then
	printf 'ok    %-28s %s\n' speedtest "$got"
else
	printf 'FAIL  %-28s %s (want only 10.99.0.1, with results both ways)\n' speedtest "$got"
	failures=$((failures + 1))
fi
stop

echo
if [ "$failures" -gt 0 ]; then
	echo "$failures check(s) failed; outputs were in $out"
	exit 1
fi
echo "all checks reached their expected verdicts"
