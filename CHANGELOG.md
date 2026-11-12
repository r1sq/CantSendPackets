# Changelog

Versions follow [Semantic Versioning](https://semver.org). The version the source is at is in
`VERSION`, and every build shows it in the status bar: release builds as `v1.2.3`, anything
else as `v1.2.3-dev`.

## How versions go up

Every change that lands on `main` bumps `VERSION` and gets an entry here, in the same commit or
merge. Several changes merged together share one bump. A release is a tag of a version that's
already on `main` (`make tag`), so not every version has to be released.

| Bump | When | Examples |
|---|---|---|
| Major | Something that worked stops working for users or other instances | The speed test or discovery protocol changes (`peer.ProtocolVersion`), older settings files can't be read, `cspcheck` JSON or flags change incompatibly, a Windows version is dropped |
| Minor | Something new | A new check, setting, language or `cspcheck` option |
| Patch | Something better that does the same job | Bug fixes, clearer wording, layout, performance |

Before 1.0.0, breaking changes bump the minor version instead of the major one.

## [0.2.0] - 2026-11-12

### Added
- The app for Linux (amd64 and arm64), with the same window, checks, speed test and updates. The
  loop and DHCP checks ask for the administrator password through polkit and run just that
  check as root. See `docs/linux.md`.
- `cspcheck` for Linux (amd64 and arm64): connectivity, loop and DHCP checks, discovery and the
  speed test endpoint, with raw capture through AF_PACKET when run as root or with
  CAP_NET_RAW.
- `cspcheck -no-capture`, to run the checks as without Npcap or root.
- `make netlab`: the Linux checks against a simulated network with a rogue DHCP server and a real
  loop, run in CI.

### Changed
- `cspcheck`'s JSON reports capture as `"capture"` instead of `"npcap"`, since on Linux it isn't
  Npcap.

## [0.1.2] - 2026-11-12

### Fixed
- A second copy on the same PC, such as an older version left running, no longer shows up in the
  speed test list. Searching for one of this PC's own addresses says so.
- Starting the app while it's already open brings the open window forward instead of starting a
  second copy. Other users on the same PC still get their own.

### Changed
- The README is a short landing page; the details moved to `docs/` and `CONTRIBUTING.md`.

## [0.1.1] - 2026-11-12

### Changed
- Builds run on Ubuntu 24.04 instead of whatever `ubuntu-latest` currently is, so a release
  doesn't change its build environment unannounced.

## [0.1.0] - 2026-11-12

First versioned state.

### Added
- Connectivity monitor for the gateway, DNS servers, proxy and internet, with a plain-language
  verdict on where the path breaks.
- Loop check: broadcast rate from adapter counters, plus echo probes and repeated-frame analysis
  with Npcap.
- DHCP check that lists every server answering and flags any beyond the lease's own.
- Proxy detection through WinHTTP (WPAD, PAC, manual, `netsh winhttp`), tests through the proxy,
  proxy logins with the Windows account or typed credentials, and a proxy override in Settings.
- Speed test between instances, which find each other by broadcast or by IP.
- Signed updates from GitHub releases.
- German interface, with English available.
- `cspcheck`, the checks without the GUI, printing JSON.
- The status bar shows the version and links to the GitHub repository.
