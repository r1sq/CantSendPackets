# CantSendPackets

[![CI](https://github.com/r1sq/CantSendPackets/actions/workflows/ci.yml/badge.svg)](https://github.com/r1sq/CantSendPackets/actions/workflows/ci.yml)

A small Windows app that answers "what's wrong with this network?". Start it on the PC with
the problem and it tells you, in plain language, where the path breaks and what to look at.

![CantSendPackets showing a healthy connection, its loop and DHCP checks](docs/screenshots/overview.png)

The interface is German by default ([screenshot](docs/screenshots/overview-de.png)), with
English one click away in the title bar.

## What it checks

- **Connectivity:** live latency and loss to the gateway, each DNS server, the proxy
  if there is one, and the internet, with a plain-language verdict on where the path
  breaks.
- **Network loops:** detects broadcast storms and, with Npcap, tests for a loop directly.
- **Rogue DHCP:** lists every DHCP server that answers, and flags any beyond the one
  your lease came from.
- **Speed test:** instances on a network find each other, and either can measure the
  connection to another, with no server to set up.
- **Proxies:** finds the proxy the way Windows does (WPAD, PAC, manual), tests through it,
  and handles proxy logins.

| A loop | A second DHCP server |
|---|---|
| ![Loop check reporting a network loop, with repeating frames](docs/screenshots/loop.png) | ![DHCP check listing two servers, one of them not the source of this lease](docs/screenshots/rogue-dhcp.png) |

## Getting it

Download `CantSendPackets-windows-amd64.exe` (or `-arm64` for ARM PCs) from the
[latest release](https://github.com/r1sq/CantSendPackets/releases/latest) and run it.
There is no installer, and it doesn't need admin rights. Keep it in a folder you can write to,
such as Downloads or a USB stick, so it can update itself.

It needs Windows 10 or 11 with WebView2, which Windows 11 and current Windows 10 include.

The executables aren't code-signed, so on first start Windows SmartScreen says it protected
your PC. Choose *More info*, then *Run anyway*. Each release lists every file's SHA-256 in its
`release.json` if you want to check your download.

## Npcap is optional

Everything runs without it, and the DHCP check often works fine too, but Npcap makes two checks stronger. Its licence
doesn't allow bundling it, so install it yourself from <https://npcap.com/#download>;
the app detects it. The free licence covers up to 5 machines.

| | Without Npcap | With Npcap |
|---|---|---|
| Loop check | Broadcast rate from adapter counters: finds storms, can't confirm a loop | Also sends tagged frames and counts how many return, and spots repeating frames |
| DHCP check | UDP socket, which can only send from the adapter's own IP. Some servers don't answer that, so silence is reported as *unknown*, not "clear" | Sends from `0.0.0.0` like a real DHCP client, shows server MACs, and works on an adapter with no lease |

## Proxies

Proxy settings are detected through WinHTTP in the order Windows and browsers use:

1. WPAD (DHCP option 252, then DNS), if automatic detection is on
2. The configured PAC file
3. The manual proxy
4. The machine-wide WinHTTP proxy (`netsh winhttp`)
5. If nothing is configured, WPAD anyway, labelled as off in Windows

The internet verdict comes from web tests that go through the detected proxy, not
from ping: an HTTPS request to Cloudflare and to Google, and Microsoft's connectivity
test over HTTP. Ping is still measured, but if it fails while the web works it shows
as blocked rather than as a fault. A PAC file that can't be used is reported, because
the machine is then not using the proxy its admin intended.

Detection re-runs when the adapter changes or from the refresh button. Settings can
replace it for this app's tests with no proxy, a fixed proxy, or a PAC file. Other
programs aren't affected. SOCKS proxies aren't supported.

### Proxy logins

A proxy that asks for a login is answered through WinHTTP, with the Windows login where
that's appropriate. An NTLM answer can be cracked offline, and getting one is the point
of a rogue WPAD server, so how far a proxy is trusted depends on how it was found:

| Proxy came from | Windows login |
|---|---|
| Manual, PAC, `netsh winhttp`, or this app's settings | Used automatically |
| WPAD, with automatic detection on in Windows | Windows' intranet-only default; asks if that declines |
| WPAD, with automatic detection off | Not used unless you approve that proxy |

![The proxy login dialog, offering the Windows account or typed credentials](docs/screenshots/proxy-login.png)

When a login is still needed, a button offers the Windows account (approval is remembered
for that proxy) or your own credentials. Typed passwords stay in memory until you quit
and are never saved. Windows logins only use Negotiate or NTLM. Typed credentials can also
use Digest, or Basic if that's all the proxy offers, which sends the password unencrypted.

Logged-in requests can't choose a source address, so they follow the routing table rather
than the selected adapter.

## Speed test

<img src="docs/screenshots/speedtest.png" width="480" alt="Speed test card with a result against another PC, and two more PCs found">

There's no bundled iperf: ESnet publishes no Windows binaries, and third-party ones are
Cygwin builds. The test is a small native implementation with nothing extra to ship.

It runs 4 TCP connections for 6 seconds each way and leaves out the first second, so TCP
slow start doesn't skew the figure. Upload is measured at the receiving end. It saturates the link
while it runs, so other traffic will notice.

- **Discovery:** a hello on UDP 47116 every 5 seconds from physical adapters, carrying the
  PC name and test port, and answered directly. If broadcasts don't reach (another VLAN),
  search by IP.
- **Endpoint:** TCP 47116, or any free port if that's taken.
- **Firewall:** Windows asks on first start. Without that permission, other PCs can't find
  or test this one, but it can still find and test them.

Any device that can reach the port can start a test and make this PC send data, as there's
no login between instances. So the endpoint allows one test at a time, at most 30 seconds
and 8 connections, and only from private addresses or this PC's own subnets. The window
shows when someone is testing. Both the announcements and the endpoint can be turned off
in Settings, which is worth doing on networks you don't trust.

## Updates

Release builds look for a newer release on GitHub 10 seconds after starting and then
daily, through the same proxy settings as everything else. This can be turned off in
Settings. Installing always takes a click: the file is downloaded, verified and swapped in,
and the app restarts. Development builds never update themselves.

A self-updater runs what it downloads, so each release has a manifest listing its version
and every file's SHA-256, signed with Ed25519. The public key is built into the app. A
changed file, another key, or an old release republished under a new tag are all refused.
The signing key lives in GitHub as an Actions secret, so someone with admin access to the
repository could still publish a signed release. Add required reviewers to the `release`
environment to make that take a second person.

The app can only replace itself in a folder its user can write to. In Program Files it says
so and leaves things as they are.

## Releasing

One-time setup, on a machine you trust:

    go run ./dev/release keygen ~/csp-release.key    # writes the public key into the tree
    git add internal/update/release_key.pub          # and commit it

Add the private key file's contents to the repository as the Actions secret
`RELEASE_SIGNING_KEY`, then keep it somewhere safe, offline. If it's lost, installed copies can't
accept updates signed with a new one, and everyone has to download the next version by hand.

Versions follow semver. `VERSION` holds the version the source is at, and every change on
`main` bumps it and adds a `CHANGELOG.md` entry; the rules for which part to bump are there.
Builds show it in the status bar, as `v1.2.3-dev` unless they're a release.

To release the version `main` is at:

    make tag                     # tags HEAD as v<VERSION>, if CHANGELOG.md has an entry for it
    git push origin v1.2.3

The workflow tests, builds for amd64 and arm64, signs, and publishes. It refuses to publish
if the tag doesn't match `VERSION`, or if the secret doesn't match the committed public key.

## What the checks send

- **Loop check:** 3 pairs of 60-byte frames (EtherType `0x88B5`). On a real loop those
  frames circulate along with all the other traffic.
- **DHCP check:** 3 DHCPDISCOVERs using the adapter's real MAC. It never sends
  DHCPREQUEST, so no lease is taken, though a server may briefly hold an address for
  its offer. An IDS or DHCP-snooping alarm might notice this.
- **Connectivity:** pings to the gateway, 1.1.1.1 and 8.8.8.8, DNS lookups of
  `www.msftconnecttest.com`, a TCP connection to the proxy, and every 15 to 30 seconds
  a request to `www.cloudflare.com/cdn-cgi/trace`, `www.google.com/generate_204` and
  `www.msftconnecttest.com/connecttest.txt`.
- **Proxy detection:** WPAD lookups and fetching the PAC file, which Windows' own
  service evaluates.
- **Discovery:** the hellos described under Speed test, unless turned off.
- **Updates:** a request to `api.github.com` for the latest release, unless turned off.

## Limits

- A check only sees this adapter's segment and VLAN. A loop elsewhere, or one spanning
  tree has already blocked, won't show.
- A second DHCP server that stays silent during the check can't be detected. Failover
  pairs also show up as two servers.
- Ping and gateway tests are IPv4 only. IPv6 DNS servers are tested.
- A transparent proxy can't be told apart from a direct connection.
- A DNS server answering NXDOMAIN counts as working, because internal DNS on proxied
  networks often doesn't resolve public names.
- Rate thresholds (300 and 1000 packets/s) are rules of thumb for a client port.

## Building

Needs Go only. There is no npm, cgo or Wails CLI; the frontend is plain HTML, CSS and
JS embedded as-is. It cross-compiles from any OS.

    make test      # vet and unit tests
    make windows   # build/CantSendPackets.exe and build/cspcheck.exe
    make preview   # the UI in a browser, with mock data
    make screenshots   # regenerate docs/screenshots from the preview (needs Node 22+ and Chromium)

`cspcheck.exe` runs the same checks without the GUI and prints JSON, which is useful
for debugging the tool itself. `-checks` picks which to run, for instance leaving out `dhcp`
on a network with deployment servers, and `-serve` runs discovery and the speed test endpoint.

## Layout

| Path | |
|---|---|
| `internal/dhcp`, `internal/loop`, `internal/monitor`, `internal/proxy` | The checks and their verdicts. Platform neutral and unit tested against simulated networks |
| `internal/peer`, `internal/speed` | Discovery and the speed test. Tested end to end over real sockets |
| `internal/settings` | The settings file, in the user's config folder |
| `internal/update`, `dev/release` | Verifying and installing releases, and signing them |
| `.github/workflows` | CI, and publishing releases from tags |
| `internal/probe`, `internal/adapter`, `internal/npcap`, `internal/diag` | Windows API and Npcap bindings, and the wiring |
| `frontend/i18n.js` | All text, in German and English. The backend only sends keys, and a test fails if one lacks a translation |
| `app.go`, `main.go`, `frontend/` | The Wails app |
| `dev/preview` | Browser preview. Its mock data sits outside `frontend/` so it can't ship |
| `dev/fakenet` | Makes trouble on a test network on purpose: a DHCP responder for one MAC, a broadcast storm, loop echoes. Capped, and never leases anything |
| `dev/screenshots` | Drives the preview in headless Chromium to produce the README screenshots |
| `dev/genres` | Generates the `.syso` icon and manifest using only the standard library |

Everything the UI displays may come from a hostile device on the network, so the
frontend builds the DOM with `textContent` only, under a strict CSP.

## Licence

CantSendPackets is free software under the [GNU General Public License v3.0 or later](LICENSE).
You may use, change and share it. If you distribute a changed version, you have to publish its
source under the same licence.

Npcap is a separate product under its own licence and isn't part of this project.
