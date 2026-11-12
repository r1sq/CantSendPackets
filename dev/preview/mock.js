"use strict";
// Stands in for the Go backend in the browser preview. See main.go.
(() => {
  const params = new URLSearchParams(location.search);
  const scenario = params.get("scenario") ?? "healthy";
  const autorun = params.has("autorun");
  let seed = 7;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const series = (base, spread, n = 60, failEvery = 0) =>
    Array.from({ length: n }, (_, i) => (failEvery && i % failEvery === failEvery - 1 ? -1 : +(base + rnd() * spread).toFixed(1)));
  const m = (key, args) => ({ key, args });
  const pair = (key, args) => ({ headline: m(`${key}.h`, args), detail: m(`${key}.d`, args) });

  const adapter = {
    index: 12, name: "Ethernet", description: "Intel(R) Ethernet", kind: "Ethernet", mac: "a4:bb:6d:12:34:56", speedMbps: 1000, mtu: 1500,
    dhcpEnabled: true, dhcpServer: "192.168.1.1", ipv4: ["192.168.1.42"], ipv6: [], gateways: ["192.168.1.1"], dns: ["192.168.1.1", "9.9.9.9"], dnsSuffix: "lan",
  };
  const wifi = { ...adapter, index: 18, name: "Wi-Fi", kind: "Wi-Fi", speedMbps: 866, ipv4: ["192.168.1.77"], mac: "3c:58:c2:aa:bb:cc" };

  const row = (id, group, label, addr, kind, hist, extra = {}) => {
    const ok = hist.filter((v) => v >= 0);
    const fails = hist.length - ok.length;
    const recent = hist.slice(-3);
    const status = recent.every((v) => v < 0) ? "down" : recent.some((v) => v < 0) || fails / hist.length >= 0.05 ? "degraded" : "up";
    return { id, group, label, addr, kind, viaProxy: false, status, lastMs: hist.at(-1), avgMs: ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : 0,
      lossPct: 100 * fails / hist.length, error: recent.at(-1) < 0 ? m("err.timeout") : m(""), captive: false, proxyAuth: false, advisory: false, history: hist,
      intervalSec: { http: 30, https: 15, arp: 10, dns: 3, tcp: 5 }[kind] ?? 2, ...extra };
  };
  const down = (n = 60) => Array(n).fill(-1);
  const blockedPing = (id, label, addr) => row(id, "internet", label, addr, "ping", down(), { status: "blocked", advisory: true, error: m("err.pingBlocked") });

  const lan = () => [
    row("gw", "gateway", m("target.gateway"), "192.168.1.1", "ping", series(0, 2)),
    row("arp", "gateway", m("target.gatewayArp"), "192.168.1.1", "arp", series(1, 2, 12)),
    row("d1", "dns", m("target.dns", { n: 1 }), "192.168.1.1", "dns", series(2, 6)),
    row("d2", "dns", m("target.dns", { n: 2 }), "9.9.9.9", "dns", series(12, 10)),
  ];
  const webs = (extra = {}) => [
    row("cfw", "internet", m("target.cloudflareWeb"), "www.cloudflare.com", "https", series(40, 40, 8), extra),
    row("gw2", "internet", m("target.googleWeb"), "www.google.com", "https", series(45, 40, 8), extra),
    row("ms", "internet", m("target.microsoftWeb"), "www.msftconnecttest.com", "http", series(40, 40, 4), extra),
  ];
  const pings = () => [
    row("cf", "internet", m("target.cloudflarePing"), "1.1.1.1", "ping", series(9, 6)),
    row("g", "internet", m("target.googlePing"), "8.8.8.8", "ping", series(11, 9)),
  ];
  const direct = { detecting: false, active: false, address: "", source: "none", pacUrl: "", issue: m("") };
  const viaWpad = { detecting: false, active: true, address: "proxy.firma.intern:8080", source: "wpad", pacUrl: "http://wpad.firma.intern/wpad.dat", issue: m("") };

  const authed = { ...viaWpad, source: "pac", authRequired: true, authMethod: "windows" };
  const proxyTarget = (hist) => row("proxy", "proxy", m("target.proxy"), viaWpad.address, "tcp", hist);
  const snapshots = {
    healthy: () => ({ summary: { verdict: "ok", ...pair("summary.ok") }, proxy: direct, targets: [...lan(), ...webs(), ...pings()] }),
    proxy: () => ({ summary: { verdict: "ok", ...pair("summary.okProxy", { proxy: viaWpad.address }) }, proxy: viaWpad, targets: [
      ...lan(), proxyTarget(series(1, 2, 24)), ...webs({ viaProxy: true }),
      blockedPing("cf", m("target.cloudflarePing"), "1.1.1.1"), blockedPing("g", m("target.googlePing"), "8.8.8.8"),
    ] }),
    proxywin: () => ({ summary: { verdict: "ok", ...pair("summary.okProxy", { proxy: authed.address }) }, proxy: authed, targets: [
      ...lan(), proxyTarget(series(1, 2, 24)), ...webs({ viaProxy: true }),
      blockedPing("cf", m("target.cloudflarePing"), "1.1.1.1"), blockedPing("g", m("target.googlePing"), "8.8.8.8"),
    ] }),
    proxyauth: () => ({ summary: { verdict: "warn", ...pair("summary.proxyAuth", { proxy: viaWpad.address }) }, proxy: { ...viaWpad, authRequired: true }, targets: [
      ...lan(), proxyTarget(series(1, 2, 24)),
      ...webs({ viaProxy: true }).map((x) => ({ ...x, status: "down", lastMs: -1, avgMs: 0, lossPct: 100, history: down(8), proxyAuth: true, error: m("err.proxyAuth") })),
      ...pings().map((x) => ({ ...x, status: "down", lastMs: -1, avgMs: 0, lossPct: 100, history: down(), advisory: true, error: m("err.timeout") })),
    ] }),
    proxydown: () => ({ summary: { verdict: "problem", ...pair("summary.proxyDown", { proxy: viaWpad.address }) }, proxy: { ...viaWpad, source: "pac", pacUrl: "http://cfg/proxy.pac" }, targets: [
      ...lan(), { ...proxyTarget(down(24)), error: m("err.timeout") },
      ...webs({ viaProxy: true }).map((x) => ({ ...x, status: "down", lastMs: -1, avgMs: 0, lossPct: 100, history: down(8), error: m("err.timeout") })),
    ] }),
    pacbroken: () => ({ summary: { verdict: "problem", ...pair("summary.webBlocked") }, proxy: { ...direct, issue: m("proxy.issue.pac", { url: "http://cfg/proxy.pac", detail: m("err.proxy.pacDownload") }) }, targets: [
      ...lan(), ...webs().map((x) => ({ ...x, status: "down", lastMs: -1, avgMs: 0, lossPct: 100, history: down(8), error: m("err.timeout") })), ...pings(),
    ] }),
    down: () => ({ summary: { verdict: "problem", ...pair("summary.upstream") }, proxy: direct, targets: [
      row("gw", "gateway", m("target.gateway"), "192.168.1.1", "ping", series(0, 2)),
      row("d1", "dns", m("target.dns", { n: 1 }), "192.168.1.1", "dns", [...series(3, 6, 30), ...down(30)], { error: m("err.dns.noReply") }),
      ...webs().map((x) => ({ ...x, status: "down", lastMs: -1, avgMs: 0, lossPct: 100, history: down(8), error: m("err.timeout") })),
      row("cf", "internet", m("target.cloudflarePing"), "1.1.1.1", "ping", [...series(9, 6, 30), ...down(30)]),
    ] }),
  };
  for (const name of ["rogue", "basic", "loop", "nopeers", "hidden", "update", "updatefail", "devbuild"]) snapshots[name] = snapshots.healthy;

  const server = (id, mac, offered, extra = {}) => ({ serverId: id, sourceIp: id, sourceMac: mac, offeredIp: offered, mask: "255.255.255.0", routers: [id], dns: [id], domain: "lan", leaseSeconds: 86400, offers: 3, firstOfferMs: 12, isLeaseServer: false, ...extra });
  const oneServer = { verdict: "ok", ...pair("dhcp.one", { server: "192.168.1.1" }), method: "capture", sent: 3, leaseServer: "192.168.1.1", servers: [server("192.168.1.1", "e4:8d:8c:01:02:03", "192.168.1.42", { isLeaseServer: true })] };
  const dhcp = {
    rogue: { verdict: "problem", ...pair("dhcp.multiple", { count: 2 }), method: "capture", sent: 3, leaseServer: "192.168.1.1", servers: [
      server("192.168.1.1", "e4:8d:8c:01:02:03", "192.168.1.42", { isLeaseServer: true }),
      server("192.168.8.1", "00:0c:43:66:66:66", "192.168.8.103", { domain: params.has("hostile") ? "<img src=x onerror=alert(1)>" : "fritz.box", dns: ["192.168.8.1", "8.8.8.8"], leaseSeconds: 43200 }),
    ] },
    basic: { verdict: "unknown", ...pair("dhcp.silentSocket"), method: "socket", sent: 3, leaseServer: "192.168.1.1", servers: [] },
  };

  const cleanLoop = { verdict: "ok", ...pair("loop.clean", { sent: 3, seconds: 8.02 }), notes: [], method: m("loop.method.active"), durationSec: 8.02,
    echo: { sent: 3, maxCopies: 1, controlCopies: 1, baseline: 1, extra: 0 }, rate: { available: true, avgPps: 14.2, medianPps: 12, peakPps: 31, broadcastKBps: 1.4, samplesPps: [] }, repeats: [], talkers: [], frames: 1124 };
  const loops = {
    loop: { verdict: "problem", ...pair("loop.echo", { extra: 214 }), notes: [], method: m("loop.method.active"), durationSec: 8.01,
      echo: { sent: 3, maxCopies: 215, controlCopies: 1, baseline: 1, extra: 214 }, rate: { available: true, avgPps: 8420, medianPps: 8390.4, peakPps: 9712, broadcastKBps: 1880, samplesPps: [] },
      repeats: [{ sourceMac: "e4:8d:8c:01:02:03", etherType: "0x0806", count: 3120, peakPerSecond: 402 }, { sourceMac: "00:11:32:aa:bb:cc", etherType: "0x0800", count: 1877, peakPerSecond: 390 }], talkers: [], frames: 67322 },
    basic: { verdict: "ok", ...pair("loop.passiveClean", { rate: 12 }), notes: [m("loop.note.noNpcap")], method: m("loop.method.counters"), durationSec: 8.01,
      echo: null, rate: { available: true, avgPps: 14.2, medianPps: 12, peakPps: 31, broadcastKBps: 1.4, samplesPps: [] }, repeats: [], talkers: [], frames: 0 },
  };

  const peerList = scenario === "nopeers" || scenario === "basic" ? [] : [
    { id: "a".repeat(32), name: "BUERO-PC-2", ip: "192.168.1.77", port: 47116, compatible: true },
    { id: "b".repeat(32), name: params.has("hostile") ? "<b>LAPTOP</b>" : "LAPTOP-7", ip: "192.168.1.91", port: 47116, compatible: true },
    { id: "c".repeat(32), name: "ALT-PC", ip: "192.168.1.40", port: 47116, compatible: false },
  ];
  let mockSettings = { proxyMode: "auto", proxyAddress: "", proxyBypass: "", pacUrl: "", trustedProxies: [], discoverable: scenario !== "hidden", checkUpdates: true };
  const peerStatus = () => mockSettings.discoverable
    ? { visible: true, name: "DIESER-PC", port: 47116, peers: peerList, error: m("") }
    : { visible: false, name: "DIESER-PC", port: 0, peers: [], error: m("") };
  const samples = (base, spread) => Array.from({ length: 24 }, (_, i) => Math.max(0, base * Math.min(1, (i + 1) / 3) + rnd() * spread));
  let speedAbort = null;
  let updateStatus = {
    current: scenario === "devbuild" ? "v0.1.0-dev" : "v0.1.0", enabled: scenario !== "devbuild", checking: false, installing: false, upToDate: false,
    available: scenario === "update" || scenario === "updatefail" ? "v0.2.0" : "", error: m(""),
  };
  const setUpdate = (patch) => { updateStatus = { ...updateStatus, ...patch }; listeners.update?.(updateStatus); };

  const listeners = {};
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  window.runtime = {
    EventsOn: (name, fn) => { listeners[name] = fn; },
    __emit: (name, data) => listeners[name]?.(data),
    WindowMinimise() {}, WindowToggleMaximise() {}, Quit() {},
  };
  window.go = { main: { App: {
    Npcap: async () => (scenario === "basic" ? { available: false, version: "" } : { available: true, version: "Npcap version 1.80, based on libpcap version 1.10.5" }),
    Adapters: async () => [adapter, wifi],
    StartMonitor: async (index) => {
      const emit = () => listeners.monitor?.({ adapterIndex: index, ...snapshots[scenario]() });
      emit();
      clearInterval(window.__mockTimer);
      window.__mockTimer = setInterval(emit, 1000);
    },
    RunLoopCheck: async () => { await wait(autorun ? 10 : 8000); return loops[scenario] ?? cleanLoop; },
    RunDHCPCheck: async () => { await wait(autorun ? 10 : 6000); return dhcp[scenario] ?? oneServer; },
    OpenNpcapPage() {}, OpenRepoPage() { window.__repoOpened = true; },
    UpdateStatus: async () => updateStatus,
    CheckForUpdate: () => {
      setUpdate({ checking: true, error: m("") });
      setTimeout(() => setUpdate({ checking: false, upToDate: true }), 200);
    },
    OpenReleasePage() { window.__releasePage = true; },
    InstallUpdate: () => {
      setUpdate({ installing: true, error: m("") });
      if (scenario === "updatefail") setTimeout(() => setUpdate({ installing: false, error: m("err.update.badHash") }), 200);
    },
    Settings: async () => mockSettings,
    SaveSettings: async (s) => {
      if (s.proxyMode === "manual" && !s.proxyAddress) return m("settings.err.badAddress");
      if (s.proxyAddress.includes("@")) return m("settings.err.credentialsInAddress");
      if (s.proxyMode === "pac" && !/^https?:\/\//.test(s.pacUrl)) return m("settings.err.badPac");
      mockSettings = s;
      listeners.peers?.(peerStatus());
      window.__saved = s;
      return m("");
    },
    SetProxyCredentials: async (host, user) => { window.__login = { host, user }; },
    ClearProxyCredentials: async () => {},
    TrustProxy: async (host) => { window.__trusted = host; return m(""); },
    PeerStatus: async () => peerStatus(),
    ProbePeer: async (ip) => (/^\d+\.\d+\.\d+\.\d+$/.test(ip) ? m("") : m("err.peer.badAddress")),
    CancelSpeedTest: () => speedAbort?.(),
    RunSpeedTest: (id) => new Promise((resolve) => {
      if (id === "b".repeat(32)) return setTimeout(() => resolve({ error: m("err.speed.connect", { addr: "192.168.1.91:47116" }) }), 300);
      const total = params.has("fastspeed") ? 8 : 48;
      let i = 0;
      const timer = setInterval(() => {
        const fraction = ++i / total;
        listeners["speed-progress"]?.({ peerId: id, direction: fraction <= 0.5 ? "download" : "upload", mbps: 900 + rnd() * 60, fraction });
        if (i >= total) {
          clearInterval(timer);
          resolve({ result: { downMbps: 941.3, upMbps: 936.2, connectMs: 0.8, streams: 4, seconds: 6, downSamples: samples(930, 30), upSamples: samples(925, 30) }, error: m("") });
        }
      }, 60);
      speedAbort = () => { clearInterval(timer); resolve({ cancelled: true, error: m("") }); };
    }),
  } } };
  if (autorun) addEventListener("load", () => setTimeout(() => {
    document.getElementById("run-loop")?.click();
    document.getElementById("run-dhcp")?.click();
  }, 150));
})();
