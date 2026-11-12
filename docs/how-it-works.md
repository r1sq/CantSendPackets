# How the checks work

## Connectivity

Latency and loss to the gateway (ping and ARP), each DNS server, the proxy if there is one, and
the internet. The internet verdict comes from web tests through the detected proxy, not from ping:
an HTTPS request to Cloudflare and to Google, and Microsoft's connectivity test over HTTP. Ping is
still measured, but if it fails while the web works it shows as blocked rather than as a fault.
See [Proxies](proxies.md) for how the proxy is found.

## Npcap

Everything runs without [Npcap](https://npcap.com/#download), and the DHCP check often works fine
too, but Npcap makes two checks stronger. Its licence doesn't allow bundling it, so install it
yourself; the app detects it. The free licence covers up to 5 machines.

| | Without Npcap | With Npcap |
|---|---|---|
| Loop check | Broadcast rate from adapter counters: finds storms, can't confirm a loop | Also sends tagged frames and counts how many return, and spots repeating frames |
| DHCP check | UDP socket, which can only send from the adapter's own IP. Some servers don't answer that, so silence is reported as *unknown*, not "clear" | Sends from `0.0.0.0` like a real DHCP client, shows server MACs, and works on an adapter with no lease |

## What the checks send

- **Loop check:** 3 pairs of 60-byte frames (EtherType `0x88B5`). On a real loop those frames
  circulate along with all the other traffic.
- **DHCP check:** 3 DHCPDISCOVERs using the adapter's real MAC. It never sends DHCPREQUEST, so no
  lease is taken, though a server may briefly hold an address for its offer. An IDS or
  DHCP-snooping alarm might notice this.
- **Connectivity:** pings to the gateway, 1.1.1.1 and 8.8.8.8, DNS lookups of
  `www.msftconnecttest.com`, a TCP connection to the proxy, and every 15 to 30 seconds a request to
  `www.cloudflare.com/cdn-cgi/trace`, `www.google.com/generate_204` and
  `www.msftconnecttest.com/connecttest.txt`.
- **Proxy detection:** WPAD lookups and fetching the PAC file, which Windows' own service evaluates.
- **Discovery:** the hellos described under [Speed test](speed-test.md), unless turned off.
- **Updates:** a request to `api.github.com` for the latest release, unless turned off.

## Limits

- A check only sees this adapter's segment and VLAN. A loop elsewhere, or one spanning tree has
  already blocked, won't show.
- A second DHCP server that stays silent during the check can't be detected. Failover pairs also
  show up as two servers.
- Ping and gateway tests are IPv4 only. IPv6 DNS servers are tested.
- A transparent proxy can't be told apart from a direct connection.
- A DNS server answering NXDOMAIN counts as working, because internal DNS on proxied networks often
  doesn't resolve public names.
- Rate thresholds (300 and 1000 packets/s) are rules of thumb for a client port.

## Without the window

`cspcheck.exe`, in each release, runs the same checks and prints JSON. `-checks` picks which to
run, for instance leaving out `dhcp` on a network with deployment servers, and `-serve` runs
discovery and the speed test endpoint.
