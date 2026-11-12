# Building and contributing

Issues and pull requests are welcome. Contributions are under the project's licence,
[GPL-3.0-or-later](LICENSE).

## Building

Needs Go only. There is no npm, cgo or Wails CLI; the frontend is plain HTML, CSS and JS embedded
as-is. It cross-compiles from any OS.

    make test          # vet and unit tests
    make windows       # build/CantSendPackets.exe and build/cspcheck.exe
    make preview       # the UI in a browser, with mock data
    make linux         # build/cspcheck-linux-amd64 and -arm64
    make netlab        # the Linux checks against a simulated network (needs user namespaces)
    make screenshots   # regenerate docs/screenshots from the preview (needs Node 22+ and Chromium)

`cspcheck` runs the checks without the GUI and prints JSON, which is useful for debugging the
tool itself. `-no-capture` and `-dhcp-socket` make it take the paths used without Npcap or root,
to compare.

`make netlab` builds a small network out of namespaces, a bridge and veth pairs: a client, a DHCP
server, a rogue one, and a loop through a rate-limited cable. It checks that every check reaches
the verdict it should, with and without raw capture. It needs no root, and CI runs it.

## Layout

| Path | |
|---|---|
| `internal/dhcp`, `internal/loop`, `internal/monitor`, `internal/proxy` | The checks and their verdicts. Platform neutral and unit tested against simulated networks |
| `internal/peer`, `internal/speed` | Discovery and the speed test. Tested end to end over real sockets |
| `internal/settings` | The settings file, in the user's config folder |
| `internal/update`, `dev/release` | Verifying and installing releases, and signing them |
| `.github/workflows` | CI, and publishing releases from tags |
| `internal/probe`, `internal/adapter`, `internal/npcap`, `internal/rawcap`, `internal/diag` | Windows and Linux system access, Npcap and AF_PACKET capture, and the wiring. `diag` is shared; only capture and ping availability differ per platform |
| `frontend/i18n.js` | All text, in German and English. The backend only sends keys, and a test fails if one lacks a translation |
| `app.go`, `main.go`, `frontend/` | The Wails app |
| `dev/preview` | Browser preview. Its mock data sits outside `frontend/` so it can't ship |
| `dev/fakenet` | Makes trouble on a test network on purpose: a DHCP responder for one MAC, a broadcast storm, loop echoes, and on Linux a rate-limited loop cable. Capped, and never leases anything |
| `dev/netlab` | The simulated network `make netlab` runs |
| `dev/screenshots` | Drives the preview in headless Chromium to produce the screenshots |
| `dev/genres` | Generates the `.syso` icon and manifest using only the standard library |

Everything the UI displays may come from a hostile device on the network, so the frontend builds
the DOM with `textContent` only, under a strict CSP.

## Versions

Versions follow semver. `VERSION` holds the version the source is at, and every change on `main`
bumps it and adds a [CHANGELOG.md](CHANGELOG.md) entry; the rules for which part to bump are there.
Builds show it in the status bar, as `v1.2.3-dev` unless they're a release.

## Releasing

One-time setup, on a machine you trust:

    go run ./dev/release keygen ~/csp-release.key    # writes the public key into the tree
    git add internal/update/release_key.pub          # and commit it

Add the private key file's contents as the secret `RELEASE_SIGNING_KEY` of the `release`
environment, then keep it somewhere safe, offline. If it's lost, installed copies can't accept
updates signed with a new one, and everyone has to download the next version by hand.

To release the version `main` is at:

    make tag                     # tags HEAD as v<VERSION>, if CHANGELOG.md has an entry for it
    git push origin v1.2.3

The workflow tests, builds for amd64 and arm64, signs, and publishes. It refuses to publish if the
tag doesn't match `VERSION`, or if the secret doesn't match the committed public key.
