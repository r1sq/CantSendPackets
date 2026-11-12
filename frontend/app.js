"use strict";

// Everything shown here originates on the network: a rogue DHCP server chooses its
// own domain name, for instance. So the DOM is only ever built with textContent
// through h(), never innerHTML, and icon paths below are static constants.

const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  ok: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM8 12.5l3 3 5-6",
  warn: "M12 3.5 2.5 20h19L12 3.5zM12 10v4.5M12 17.5v.01",
  problem: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM15 9l-6 6M9 9l6 6",
  unknown: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.5 9.5a2.5 2.5 0 1 1 3.6 2.2c-.7.4-1.1 1-1.1 1.8M12 16.8v.01",
  refresh: "M20 11a8 8 0 0 0-14-4.5L4 8.5M4 4v4.5h4.5M4 13a8 8 0 0 0 14 4.5l2-2M20 20v-4.5h-4.5",
  min: "M5 12h14",
  max: "M5 5h14v14H5z",
  close: "M6 6l12 12M18 6 6 18",
  settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
};
const STATUS_VERDICT = { up: "ok", degraded: "warn", down: "problem", pending: "unknown", blocked: "unknown" };
const KIND_LABEL = { ping: "Ping", arp: "ARP", dns: "DNS", tcp: "TCP", http: "HTTP", https: "HTTPS" };
const GROUPS = [["gateway", "group.gateway"], ["dns", "group.dns"], ["proxy", "group.proxy"], ["internet", "group.internet"]];
const WINDOW = 60;
const LANG_KEY = "csp.lang";
const DEFAULT_LANG = "de";

// ---------------------------------------------------------------- language

function storedLang() {
  try {
    const v = localStorage.getItem(LANG_KEY);
    return v && MESSAGES[v] ? v : DEFAULT_LANG;
  } catch {
    return DEFAULT_LANG;
  }
}

const state = {
  lang: storedLang(),
  platform: "windows", // replaced from the backend at start; picks text variants and controls
  api: null,
  adapters: [],
  selected: null,   // adapter index
  signature: "",    // config of the monitored adapter, to spot a replug or new lease
  runToken: { loop: 0, dhcp: 0 },
  reports: { loop: null, dhcp: null }, // kept to re-render when the language changes
  running: { loop: false, dhcp: false },
  lastRun: { loop: null, dhcp: null },
  rows: new Map(),
  snapshot: null,
  hero: { verdict: "unknown", headline: { key: "ui.starting" }, detail: null },
  npcap: null,
  peers: { visible: false, name: "", port: 0, peers: [], error: null },
  update: null,
  speed: { runningId: null, direction: null, mbps: 0, fraction: 0, results: {}, errors: {}, incoming: null, manualMsg: null },
};

const fmtNumber = (v, digits = 0) => new Intl.NumberFormat(state.lang, { maximumFractionDigits: digits }).format(v);

// t renders a catalog key, or a {key, args} message from the backend. Numbers are
// formatted for the language, and an argument may itself be a message.
function t(msg, args) {
  if (!msg) return "";
  const key = typeof msg === "string" ? msg : msg.key;
  if (!key) return "";
  const values = (typeof msg === "string" ? args : msg.args) ?? {};
  // A text can have a variant for a platform, such as "footer.basic.linux".
  const variant = state.platform === "windows" ? null : `${key}.${state.platform}`;
  const template = (variant && (MESSAGES[state.lang][variant] ?? MESSAGES.en[variant]))
    ?? MESSAGES[state.lang][key] ?? MESSAGES.en[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (whole, name) => {
    const v = values[name];
    if (v == null) return whole;
    if (typeof v === "number") return fmtNumber(v);
    if (typeof v === "object") return t(v);
    return String(v);
  });
}

function applyStaticText() {
  document.documentElement.lang = state.lang;
  for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of document.querySelectorAll("[data-i18n-label]")) {
    el.setAttribute("aria-label", t(el.dataset.i18nLabel));
    el.title = t(el.dataset.i18nLabel);
  }
  for (const lang of ["de", "en"]) $(`lang-${lang}`).setAttribute("aria-pressed", String(state.lang === lang));
}

function setLanguage(lang) {
  state.lang = lang;
  try { localStorage.setItem(LANG_KEY, lang); } catch { /* still applies for this session */ }
  applyStaticText();
  renderHero();
  renderCurrentFacts();
  clearTargets();
  if (state.snapshot) onSnapshot(state.snapshot);
  else renderPath(null);
  for (const key of Object.keys(CHECKS)) renderCheck(key);
  renderSpeedCard();
  renderStatusBar();
}

// ---------------------------------------------------------------- DOM helpers

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (k === "on") for (const [e, f] of Object.entries(v)) el.addEventListener(e, f);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const c of children) if (c != null) el.append(c);
  return el;
}

function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...children);
  return el;
}

function icon(name, label) {
  const el = svg("svg", { class: "icon", viewBox: "0 0 24 24" }, svg("path", { d: ICONS[name] }));
  if (label) { el.setAttribute("role", "img"); el.setAttribute("aria-label", label); }
  else el.setAttribute("aria-hidden", "true");
  return el;
}

function verdictIcon(v, label) {
  const el = icon(v, label ?? t(`verdict.${v}`));
  el.classList.add(`v-${v}`);
  return el;
}

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- formatting

function fmtMs(v, kind) {
  if (v == null || v < 0) return "–";
  if (kind === "ping" && v < 1) return "<1 ms"; // Windows reports whole milliseconds
  return `${fmtNumber(v, v < 10 ? 1 : 0)} ms`;
}
function fmtRate(v) { return fmtNumber(v, v >= 100 ? 0 : 1); }
function fmtAgo(s) {
  if (s < 1) return t("time.now");
  if (s < 60) return t("time.seconds", { s: Math.round(s) });
  const m = Math.floor(s / 60);
  const rest = Math.round(s % 60);
  return rest ? t("time.minutesSeconds", { m, s: rest }) : t("time.minutes", { m });
}
function fmtLease(s) {
  if (!s) return "";
  const unit = (n, one, many) => {
    const v = +n.toFixed(1);
    return v === 1 ? t(one) : t(many, { n: fmtNumber(v, 1) });
  };
  if (s >= 86400) return unit(s / 86400, "unit.day", "unit.days");
  if (s >= 3600) return unit(s / 3600, "unit.hour", "unit.hours");
  return t("unit.min", { n: Math.round(s / 60) });
}
function fmtSpeed(mbps) {
  if (!mbps) return "";
  return mbps >= 1000 ? `${fmtNumber(mbps / 1000, 1)} Gbit/s` : `${fmtNumber(mbps)} Mbit/s`;
}
const list = (a) => (a ?? []).filter(Boolean);

// ---------------------------------------------------------------- adapters

function adapterLabel(a) {
  const ip = list(a.ipv4)[0];
  return ip ? `${a.name}  ·  ${ip}` : a.name;
}

function renderAdapters() {
  const sel = $("adapter");
  sel.replaceChildren(...state.adapters.map((a) => h("option", { value: String(a.index), textContent: adapterLabel(a) })));
  if (state.selected != null) sel.value = String(state.selected);
}

function proxyFact(p) {
  if (!p || p.detecting) return { text: t("fact.detecting"), title: "" };
  if (!p.active) return { text: t(p.source === "overrideDirect" ? "fact.noProxyForced" : "fact.noProxy"), title: "" };
  const parts = [t(`proxy.source.${p.source}`)];
  if (p.authMethod) parts.push(t(`proxy.auth.${p.authMethod}`));
  return { text: `${p.address} (${parts.join(", ")})`, title: p.pacUrl || "" };
}

function kindLabel(kind) {
  if (kind === "Ethernet") return t("fact.ethernet");
  if (kind === "Wi-Fi") return t("fact.wifi");
  return t("fact.other");
}

function renderFacts(a) {
  // An address outside APIPA means there is a lease even when Windows can't name
  // its server, as while it rebinds.
  const leased = list(a.ipv4).some((ip) => !ip.startsWith("169.254."));
  const dhcp = a.dhcpEnabled ? (a.dhcpServer || t(leased ? "fact.serverUnknown" : "fact.noLease")) : t("fact.static");
  const proxy = proxyFact(state.snapshot?.proxy);
  const facts = [
    ["fact.ipv4", list(a.ipv4).join(", ") || t("fact.none")],
    ["fact.gateway", list(a.gateways).join(", ") || t("fact.none")],
    ["fact.dns", list(a.dns).join(", ") || t("fact.none")],
    ["fact.dhcp", dhcp],
    ["fact.proxy", proxy.text, proxy.title],
    ["fact.mac", a.mac || t("fact.none")],
    ["fact.link", [kindLabel(a.kind), fmtSpeed(a.speedMbps)].filter(Boolean).join(" · ")],
  ];
  $("facts").replaceChildren(...facts.map(([k, v, title]) =>
    h("div", {}, h("dt", { textContent: t(k) }), h("dd", { textContent: v, title: title ?? "" }))));
}

function renderCurrentFacts() {
  const a = state.adapters.find((x) => x.index === state.selected);
  if (a) renderFacts(a);
}

function signature(a) {
  return JSON.stringify([a.index, a.ipv4, a.gateways, a.dns, a.dhcpServer]);
}

async function loadAdapters({ keepSelection = true } = {}) {
  let adapters;
  try {
    adapters = await state.api.Adapters();
  } catch (err) {
    showHero("problem", "ui.listFailed", { key: "err.raw", args: { text: String(err) } });
    return;
  }
  state.adapters = adapters ?? [];
  if (state.adapters.length === 0) {
    state.selected = null;
    state.signature = "";
    state.snapshot = null;
    renderAdapters();
    $("facts").replaceChildren();
    clearTargets();
    renderPath(null);
    renderProxyNote(null);
    showHeroKey("problem", "ui.noAdapters");
    setChecksEnabled(false);
    return;
  }
  const still = keepSelection && state.adapters.find((a) => a.index === state.selected);
  const current = still || state.adapters[0];
  state.selected = current.index;
  renderAdapters();
  setChecksEnabled(true);

  const sig = signature(current);
  if (sig !== state.signature) {
    state.signature = sig;
    state.snapshot = null;
    renderFacts(current);
    await startMonitor(current.index);
  } else {
    renderFacts(current);
  }
}

async function startMonitor(index) {
  clearTargets();
  renderProxyNote(null);
  showHeroKey("unknown", "summary.checking");
  renderPath(null);
  try {
    await state.api.StartMonitor(index);
  } catch (err) {
    showHero("problem", "ui.monitorFailed", { key: "err.raw", args: { text: String(err) } });
  }
}

function selectAdapter(index) {
  state.selected = index;
  state.signature = "";
  // Results from the previous adapter would now be misleading.
  resetChecks();
  loadAdapters();
}

// ---------------------------------------------------------------- verdict band

function showHero(verdict, headline, detail) {
  state.hero = { verdict, headline, detail };
  renderHero();
}

function showHeroKey(verdict, key) {
  showHero(verdict, `${key}.h`, `${key}.d`);
}

function renderHero() {
  const { verdict, headline, detail } = state.hero;
  $("hero").dataset.verdict = verdict;
  $("hero-icon").replaceChildren(verdictIcon(verdict));
  $("hero-headline").textContent = t(headline);
  $("hero-detail").textContent = t(detail);
}

// A proxy login or a filter means the test couldn't finish rather than that
// something is broken, so it reads as a warning, matching the verdict above.
function targetVerdict(target) {
  return target.proxyAuth || target.captive ? "warn" : STATUS_VERDICT[target.status];
}

function webMembers(targets) {
  return targets.filter((x) => x.group === "internet" && x.kind !== "ping");
}

function groupStatus(targets, group) {
  let members = targets.filter((x) => x.group === group);
  if (members.length === 0) return "none";
  // The web tests decide whether the internet works, as they do for the verdict.
  // Ping only stands in until they've reported.
  if (group === "internet") {
    const web = webMembers(targets);
    if (web.some((x) => x.status !== "pending")) members = web;
  }
  const has = (s) => members.some((x) => x.status === s);
  if (group === "gateway" || group === "internet") {
    // One live path is enough: a router may ignore ping but answer ARP, and the
    // web may work while ping is blocked.
    if (has("up")) return "up";
    if (has("degraded")) return "degraded";
    if (has("down")) return "down";
    return "pending";
  }
  if (has("down")) return has("up") || has("degraded") ? "degraded" : "down";
  if (has("degraded")) return "degraded";
  return has("up") ? "up" : "pending";
}

function renderPath(targets) {
  const all = targets ?? [];
  const nodes = [[t("path.pc"), all.length ? "ok" : "unknown", ""]];
  for (const [group, labelKey] of GROUPS) {
    const s = groupStatus(all, group);
    if (s === "none" && group === "proxy") continue; // only on the path if there is one
    const name = group === "dns" ? t("path.dns") : t(labelKey);
    const intercepted = group === "internet" ? webMembers(all).find((x) => x.proxyAuth || x.captive) : null;
    if (s === "none") nodes.push([name, "unknown", t("path.notConfigured")]);
    else if (intercepted && s !== "up" && s !== "degraded") nodes.push([name, "warn", t(intercepted.error)]);
    else nodes.push([name, STATUS_VERDICT[s], t(`status.${s}`)]);
  }
  $("path").replaceChildren(...nodes.map(([name, v, desc], i) => {
    const prevOK = i > 0 && nodes[i - 1][1] === "ok" && v === "ok";
    return h("li", { "data-link": prevOK ? "ok" : "" },
      verdictIcon(v, `${name}: ${desc || t(`verdict.${v}`)}`),
      h("span", { textContent: name }));
  }));
}

function renderProxyNote(p) {
  const el = $("conn-note");
  let text = "";
  if (p?.issue?.key) text = t(p.issue);
  else if (p?.active && p.source === "wpadOff") text = t("proxy.note.wpadOff");
  el.textContent = text;
  el.hidden = !text;
}

// ---------------------------------------------------------------- connectivity

function clearTargets() {
  state.rows.clear();
  $("targets").replaceChildren();
  hideTooltip();
}

function buildRows(targets) {
  clearTargets();
  const nodes = [];
  for (const [group, labelKey] of GROUPS) {
    const members = targets.filter((x) => x.group === group);
    if (members.length === 0) continue;
    nodes.push(h("div", { class: "group-label", textContent: t(labelKey) }));
    for (const target of members) nodes.push(buildRow(target));
  }
  $("targets").replaceChildren(...nodes);
}

function buildRow(target) {
  const statusSlot = h("span", {});
  const sub = h("div", { class: "sub" });
  const chart = buildSpark();
  const now = h("div", { class: "col-num now" });
  const avg = h("div", { class: "col-num muted" });
  const loss = h("div", { class: "col-num muted" });
  const row = h("div", { class: "target" },
    statusSlot,
    h("div", { class: "who" }, h("div", { class: "label", textContent: t(target.label) }), sub),
    chart.el, now, avg, loss);
  state.rows.set(target.id, { row, statusSlot, sub, chart, now, avg, loss, lastStatus: null });
  return row;
}

function buildSpark() {
  const baseline = svg("line", { class: "baseline", x1: 0, y1: 29, x2: 100, y2: 29, "vector-effect": "non-scaling-stroke" });
  const series = svg("path", { class: "series" });
  const fails = svg("path", { class: "fail" });
  const cross = svg("line", { class: "cross", y1: 0, y2: 30, visibility: "hidden" });
  const el = svg("svg", { class: "spark", viewBox: "0 0 100 30", preserveAspectRatio: "none" }, baseline, series, fails, cross);
  const chart = { el, series, fails, cross, target: null, hoverX: null };
  el.addEventListener("pointermove", (e) => { chart.hoverX = e; showSparkTip(chart, e); });
  el.addEventListener("pointerleave", () => { chart.hoverX = null; cross.setAttribute("visibility", "hidden"); hideTooltip(); });
  return chart;
}

const sampleX = (i, len, window = WINDOW) => 100 - (len - 1 - i) * (100 / (window - 1));

function drawSpark(chart, target) {
  chart.target = target;
  const hist = target.history ?? [];
  // A floor on the scale stops sub-millisecond jitter filling the whole chart.
  const top = Math.max(5, ...hist) * 1.15;
  const y = (v) => 27 - (v / top) * 25;
  let line = "";
  let failMarks = "";
  let open = false;
  hist.forEach((v, i) => {
    const x = sampleX(i, hist.length, target.window).toFixed(2);
    if (v < 0) {
      failMarks += `M${x} 23V29`;
      open = false;
      return;
    }
    const py = y(v).toFixed(2);
    // A zero-length segment renders as a dot through the round line cap, so a
    // sample isolated between failures still shows.
    line += open ? `L${x} ${py}` : `M${x} ${py}h0.01`;
    open = true;
  });
  chart.series.setAttribute("d", line);
  chart.fails.setAttribute("d", failMarks);
  chart.el.setAttribute("aria-label", target.ariaLabel ?? t("ui.history", { label: t(target.label) }));
  if (chart.hoverX) showSparkTip(chart, chart.hoverX);
}

function showSparkTip(chart, e) {
  const target = chart.target;
  const hist = target?.history ?? [];
  if (hist.length === 0) return;
  const rect = chart.el.getBoundingClientRect();
  const frac = (e.clientX - rect.left) / rect.width;
  const window_ = target.window ?? WINDOW;
  const step = Math.round((1 - frac) * (window_ - 1));
  const i = Math.min(hist.length - 1, Math.max(0, hist.length - 1 - step));
  const x = sampleX(i, hist.length, window_);
  chart.cross.setAttribute("x1", x);
  chart.cross.setAttribute("x2", x);
  chart.cross.setAttribute("visibility", "visible");
  const v = hist[i];
  const ago = (hist.length - 1 - i) * (target.intervalSec || 1);
  const tip = $("tooltip");
  tip.replaceChildren(h("strong", { textContent: v < 0 ? t("chart.noReply") : (target.format ?? ((n) => fmtMs(n, target.kind)))(v) }), h("span", { textContent: fmtAgo(ago) }));
  tip.hidden = false;
  const box = tip.getBoundingClientRect();
  const px = rect.left + (x / 100) * rect.width;
  tip.style.left = `${Math.max(6, Math.min(innerWidth - box.width - 6, px - box.width / 2))}px`;
  tip.style.top = `${rect.top - box.height - 6}px`;
}

function hideTooltip() { $("tooltip").hidden = true; }

function updateRow(target) {
  const r = state.rows.get(target.id);
  if (!r) return;
  const shown = `${target.status}|${targetVerdict(target)}`;
  if (r.lastStatus !== shown) {
    const label = target.error?.key && targetVerdict(target) === "warn" ? t(target.error) : t(`status.${target.status}`);
    r.statusSlot.replaceChildren(verdictIcon(targetVerdict(target), label));
    r.row.dataset.status = target.status;
    r.lastStatus = shown;
  }
  const kind = KIND_LABEL[target.kind] ?? target.kind;
  const how = target.viaProxy ? t("row.viaProxy", { kind }) : kind;
  const failing = target.status === "down" || target.status === "degraded" || target.status === "blocked";
  const text = failing && target.error?.key ? `${target.addr} · ${t(target.error)}` : `${target.addr} · ${how}`;
  r.sub.textContent = text;
  r.sub.title = text;
  const pending = target.status === "pending";
  const blocked = target.status === "blocked";
  r.now.textContent = pending ? "–" : fmtMs(target.lastMs, target.kind);
  r.avg.textContent = (target.history ?? []).some((v) => v >= 0) ? fmtMs(target.avgMs, target.kind) : "–";
  // Loss on a deliberately blocked ping would read as a fault it isn't.
  r.loss.textContent = pending || blocked ? "–" : `${fmtNumber(target.lossPct)} %`;
  drawSpark(r.chart, target);
}

let lastFactsKey = "";

function onSnapshot(snap) {
  if (snap.adapterIndex !== state.selected) return; // late event from the previous adapter
  state.snapshot = snap;
  const targets = snap.targets ?? [];
  const known = targets.length === state.rows.size && targets.every((x) => state.rows.has(x.id));
  if (!known) buildRows(targets);
  targets.forEach(updateRow);
  showHero(snap.summary.verdict, snap.summary.headline, snap.summary.detail);
  renderPath(targets);
  renderProxyNote(snap.proxy);
  // Offered once a login is what stands in the way, not just because one exists.
  $("hero-action").hidden = !targets.some((x) => x.proxyAuth);
  const factsKey = `${state.lang}|${JSON.stringify(snap.proxy)}`;
  if (factsKey !== lastFactsKey) { // rebuilding every tick would drop text selection
    lastFactsKey = factsKey;
    renderCurrentFacts();
  }
}

// ---------------------------------------------------------------- checks

const CHECKS = {
  loop: {
    titleKey: "check.loop.title",
    blurbKey: "check.loop.blurb",
    seconds: 8,
    run: (i) => state.api.RunLoopCheck(i),
    render: renderLoopResult,
  },
  dhcp: {
    titleKey: "check.dhcp.title",
    blurbKey: "check.dhcp.blurb",
    seconds: 6,
    run: (i) => state.api.RunDHCPCheck(i),
    render: renderDhcpResult,
  },
};

function runningBody(c) {
  const bar = h("i", {});
  bar.style.setProperty("--dur", `${c.seconds}s`);
  return [h("p", { class: "blurb", textContent: t("check.testing", { seconds: c.seconds }) }), h("div", { class: "progress", role: "progressbar" }, bar)];
}

// renderCheck draws a card from state, so a language change can redraw it.
function renderCheck(key) {
  const c = CHECKS[key];
  const running = state.running[key];
  const existing = $(`run-${key}`);
  if (running && existing) {
    // Mid-run, only the words change: rebuilding would restart the progress bar.
    existing.textContent = t("check.running");
    $(`${key}-title`).textContent = t(c.titleKey);
    const text = $(`body-${key}`).querySelector(".blurb");
    if (text) text.textContent = t("check.testing", { seconds: c.seconds });
    renderLoopWarning();
    return;
  }
  const report = state.reports[key];
  const label = running ? "check.running" : report ? "check.again" : "check.run";
  const button = h("button", { class: "run-btn", id: `run-${key}`, textContent: t(label), disabled: running || (existing?.disabled ?? false), on: { click: () => runCheck(key) } });
  if (state.lastRun[key]) button.title = t("check.lastRun", { time: state.lastRun[key] });

  let content;
  if (running) content = runningBody(c);
  else if (report?.failed) content = [resultHead("unknown", "check.failed", { key: "err.raw", args: { text: report.failed } })];
  else if (report) content = c.render(report);
  else content = [h("p", { class: "blurb", textContent: t(c.blurbKey) })];

  const head = h("div", { class: "check-head" }, h("h2", { id: `${key}-title`, textContent: t(c.titleKey) }), button);
  const body = h("div", { class: "check-body", id: `body-${key}` }, ...content);
  if (key === "loop") {
    $("check-loop").replaceChildren(head, h("div", { id: "loop-warning" }), body);
    renderLoopWarning();
  } else {
    $(`check-${key}`).replaceChildren(head, body);
  }
}

// Shown before any run as well as after one: without Npcap a green result means much
// less, and that's worth knowing before relying on it. Nothing shows until Npcap's
// status is known, so a machine that has it never sees the warning flash up.
function renderLoopWarning() {
  const slot = $("loop-warning");
  if (!slot) return;
  if (!state.npcap || state.npcap.available) {
    slot.replaceChildren();
    return;
  }
  slot.replaceChildren(h("div", { class: "check-warning", role: "note" },
    verdictIcon("warn"),
    h("p", {},
      h("span", { textContent: `${t("check.loop.noNpcap")} ` }),
      // On Linux there's nothing to install: the check asks for the password.
      state.platform === "windows"
        ? h("button", { class: "link-btn", textContent: t("footer.getNpcap"), on: { click: () => state.api.OpenNpcapPage() } })
        : null)));
}

function resetChecks() {
  for (const key of Object.keys(CHECKS)) {
    state.runToken[key]++;
    state.reports[key] = null;
    state.lastRun[key] = null;
    state.running[key] = false;
    redrawCheck(key);
  }
}

function setChecksEnabled(on) {
  for (const key of Object.keys(CHECKS)) {
    if (!state.running[key]) $(`run-${key}`).disabled = !on;
  }
}

function redrawCheck(key) {
  $(`check-${key}`).replaceChildren(); // also drops the old button, so state decides
  renderCheck(key);
}

async function runCheck(key) {
  const c = CHECKS[key];
  const token = ++state.runToken[key];
  state.running[key] = true;
  state.reports[key] = null;
  redrawCheck(key);

  let report;
  try {
    report = await c.run(state.selected);
  } catch (err) {
    report = { failed: String(err) };
  }
  if (token !== state.runToken[key]) return; // adapter changed while this was running
  state.running[key] = false;
  state.reports[key] = report;
  state.lastRun[key] = new Date().toLocaleTimeString(state.lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  redrawCheck(key);
}

function resultHead(verdict, headline, detail) {
  return h("div", {},
    h("div", { class: "result-head" }, verdictIcon(verdict), h("h3", { textContent: t(headline) })),
    h("p", { class: "result-detail", textContent: t(detail) }));
}

function stats(pairs) {
  return h("dl", { class: "stats" }, ...pairs.map(([k, v]) => h("div", {}, h("dt", { textContent: t(k) }), h("dd", { textContent: v }))));
}

function renderLoopResult(r) {
  const out = [resultHead(r.verdict, r.headline, r.detail)];
  const pairs = [];
  if (r.rate?.available) {
    pairs.push(["stat.rate", t("stat.pps", { n: fmtRate(r.rate.medianPps) })]);
    pairs.push(["stat.peak", t("stat.pps", { n: fmtRate(r.rate.peakPps) })]);
  }
  if (r.echo) {
    pairs.push(["stat.echoes", t("stat.extra", { n: r.echo.extra })]);
    pairs.push(["stat.frames", fmtNumber(r.frames)]);
  }
  if (pairs.length) out.push(stats(pairs));

  const repeats = r.repeats ?? [];
  if (repeats.length) {
    out.push(h("div", { class: "subhead", textContent: t("stat.repeating") }));
    out.push(h("ul", { class: "pairs" }, ...repeats.map((x) => h("li", {},
      h("span", { class: "mono selectable", textContent: x.sourceMac }),
      h("span", { class: "val", textContent: `${t("stat.perSecond", { n: x.peakPerSecond })} · ${x.etherType}` })))));
  } else if (r.verdict !== "ok" && (r.talkers ?? []).length) {
    out.push(h("div", { class: "subhead", textContent: t("stat.talkers") }));
    out.push(h("ul", { class: "pairs" }, ...r.talkers.slice(0, 3).map((x) => h("li", {},
      h("span", { class: "mono selectable", textContent: x.sourceMac }),
      h("span", { class: "val", textContent: t("stat.frameCount", { n: x.frames }) })))));
  }
  for (const n of r.notes ?? []) {
    if (n.key === "loop.note.noNpcap" || n.key === "loop.note.noRawAccess") continue; // the card's warning already says this
    out.push(h("p", { class: "note", textContent: t(n) }));
  }
  out.push(h("p", { class: "method", textContent: t("stat.method", { method: t(r.method), seconds: Math.round(r.durationSec) }) }));
  return out;
}

function renderServer(s, leaseKnown) {
  const rows = [
    ["server.mac", s.sourceMac],
    ["server.offers", s.offeredIp],
    ["server.gateway", list(s.routers).join(", ")],
    ["server.dns", list(s.dns).join(", ")],
    ["server.domain", s.domain],
    ["server.lease", fmtLease(s.leaseSeconds)],
  ].filter(([, v]) => v);
  const id = s.serverId || s.sourceIp;
  const relayed = s.sourceIp && s.serverId && s.sourceIp !== s.serverId;
  if (relayed) rows.unshift(["server.sentBy", s.sourceIp]);
  return h("div", { class: "server" },
    h("div", { class: "server-head" },
      h("span", { class: "server-id", textContent: id }),
      s.isLeaseServer
        ? h("span", { class: "tag", textContent: t("server.yours") })
        : leaseKnown ? h("span", { class: "tag suspect", textContent: t("server.notYours") }) : null),
    h("dl", { class: "kv" }, ...rows.flatMap(([k, v]) => [h("dt", { textContent: t(k) }), h("dd", { textContent: v })])));
}

function renderDhcpResult(r) {
  const out = [resultHead(r.verdict, r.headline, r.detail)];
  // The server you didn't get your lease from is the one worth reading first.
  const servers = [...(r.servers ?? [])].sort((a, b) => a.isLeaseServer - b.isLeaseServer);
  for (const s of servers) out.push(renderServer(s, Boolean(r.leaseServer)));
  const method = t(r.method === "capture" ? "server.capture" : "server.socket");
  out.push(h("p", { class: "method", textContent: t("server.method", { method, n: r.sent }) }));
  return out;
}

// ---------------------------------------------------------------- speed test

function fmtMbps(v) {
  if (v >= 1000) return `${fmtNumber(v / 1000, 2)} Gbit/s`;
  return `${fmtNumber(v, v < 10 ? 1 : 0)} Mbit/s`;
}

function speedChart(direction, samples, seconds) {
  const chart = buildSpark();
  const label = t(direction === "download" ? "speed.download" : "speed.upload");
  drawSpark(chart, {
    history: samples ?? [], kind: "speed", label: "", ariaLabel: t("speed.chart", { direction: label }),
    format: fmtMbps, intervalSec: 0.25, window: Math.max(2, Math.round(seconds * 4)),
  });
  return chart.el;
}

function renderSpeedResult(result) {
  const side = (key, direction, mbps, samples) => h("div", { class: "speed-result" },
    h("dt", { textContent: t(key) }), h("dd", { textContent: fmtMbps(mbps) }), speedChart(direction, samples, result.seconds));
  return h("div", {},
    h("dl", { class: "speed-results" },
      side("speed.download", "download", result.downMbps, result.downSamples),
      side("speed.upload", "upload", result.upMbps, result.upSamples)),
    h("p", { class: "speed-foot", textContent: `${t("speed.detail", { streams: result.streams, seconds: result.seconds })} · ${t("speed.connect")} ${fmtMs(result.connectMs, "tcp")}` }));
}

function renderPeer(p) {
  const running = state.speed.runningId === p.id;
  const busy = state.speed.runningId != null;
  const action = !p.compatible
    ? h("span", { class: "tag", textContent: t("speed.incompatible") })
    : running
      ? h("button", { class: "run-btn", textContent: t("speed.stop"), on: { click: () => state.api.CancelSpeedTest() } })
      : h("button", { class: "run-btn", textContent: t("speed.start"), disabled: busy, on: { click: () => runSpeedTest(p.id) } });
  const out = h("div", { class: "peer" },
    h("div", { class: "peer-head" },
      h("div", { class: "peer-who" },
        h("div", { class: "peer-name", textContent: p.name || "?", title: p.name || "" }),
        h("div", { class: "peer-ip", textContent: `${p.ip}:${p.port}` })),
      action));
  if (running) {
    const direction = state.speed.direction === "upload" ? "speed.upload" : "speed.download";
    const bar = h("i", { id: "speed-bar", class: "live" });
    out.append(h("div", { class: "peer-live" },
      h("div", { class: "figures" },
        h("span", { id: "speed-direction", textContent: t(direction) }),
        h("strong", { id: "speed-rate", textContent: state.speed.direction ? fmtMbps(state.speed.mbps) : "–" })),
      h("div", { class: "progress" }, bar)));
    bar.style.width = `${Math.round(state.speed.fraction * 100)}%`;
  } else if (state.speed.errors[p.id]) {
    out.append(h("div", { class: "speed-error" }, verdictIcon("warn"), h("span", { textContent: t(state.speed.errors[p.id]) })));
  } else if (state.speed.results[p.id]) {
    out.append(renderSpeedResult(state.speed.results[p.id]));
  }
  return out;
}

// Draws everything except the manual-entry row, which is left alone so a list
// update can't take the cursor out of the field or wipe what's being typed.
function renderSpeedList() {
  const el = $("speed-list");
  if (!el) return;
  const st = state.peers;
  const nodes = [];
  if (st.error?.key) nodes.push(h("div", { class: "speed-error" }, verdictIcon("warn"), h("span", { textContent: t(st.error) })));
  if (state.speed.incoming) nodes.push(h("p", { class: "speed-incoming", textContent: t("speed.incoming", { from: state.speed.incoming }) }));
  const peers = st.peers ?? [];
  if (peers.length) nodes.push(...peers.map(renderPeer));
  else if (st.visible) nodes.push(h("p", { class: "blurb", textContent: t("speed.none") }));
  el.replaceChildren(...nodes);
  $("speed-status").textContent = st.visible ? t("speed.visibleAs", { name: st.name }) : t("speed.hidden");
}

function renderSpeedCard() {
  const manualInput = h("input", { type: "text", id: "manual-ip", placeholder: "192.168.20.5", spellcheck: false, on: { keydown: (e) => { if (e.key === "Enter") probeManual(); } } });
  const previous = $("manual-ip")?.value;
  if (previous) manualInput.value = previous;
  const manual = h("div", { class: "manual" },
    h("label", { htmlFor: "manual-ip", textContent: t("speed.manual") }),
    h("div", { class: "manual-row" }, manualInput, h("button", { class: "run-btn", textContent: t("speed.manualFind"), on: { click: probeManual } })),
    h("p", { class: "manual-msg", id: "manual-msg", textContent: t(state.speed.manualMsg) }));
  $("speed-card").replaceChildren(
    h("div", { class: "check-head" },
      h("h2", { id: "speed-title", textContent: t("speed.title") }),
      h("span", { class: "speed-status", id: "speed-status" })),
    h("div", { class: "check-body" }, h("div", { id: "speed-list" }), manual));
  renderSpeedList();
}

async function probeManual() {
  const ip = $("manual-ip").value.trim();
  const err = await state.api.ProbePeer(ip);
  state.speed.manualMsg = err?.key ? err : { key: "speed.manualSent", args: { ip } };
  $("manual-msg").textContent = t(state.speed.manualMsg);
}

async function runSpeedTest(id) {
  const speed = state.speed;
  Object.assign(speed, { runningId: id, direction: null, mbps: 0, fraction: 0 });
  delete speed.errors[id];
  delete speed.results[id];
  renderSpeedList();
  let outcome;
  try {
    outcome = await state.api.RunSpeedTest(id);
  } catch (err) {
    outcome = { error: { key: "err.raw", args: { text: String(err) } } };
  }
  speed.runningId = null;
  if (outcome.error?.key) speed.errors[id] = outcome.error;
  else if (!outcome.cancelled) speed.results[id] = outcome.result;
  renderSpeedList();
}

// Live figures update in place, since the list rebuilds would restart the bar's
// transition several times a second.
function onSpeedProgress(p) {
  const speed = state.speed;
  if (p.peerId !== speed.runningId) return;
  Object.assign(speed, { direction: p.direction, mbps: p.mbps, fraction: p.fraction });
  const rate = $("speed-rate");
  if (!rate) return;
  rate.textContent = fmtMbps(p.mbps);
  $("speed-direction").textContent = t(p.direction === "upload" ? "speed.upload" : "speed.download");
  $("speed-bar").style.width = `${Math.round(p.fraction * 100)}%`;
}

function onPeers(status) {
  state.peers = status;
  renderSpeedList();
}

function onSpeedIncoming(s) {
  state.speed.incoming = s.active ? s.from : null;
  renderSpeedList();
}

// ---------------------------------------------------------------- dialogs

function field(labelKey, input) {
  input.id ||= `f-${labelKey}`;
  return h("div", { class: "field" }, h("label", { htmlFor: input.id, textContent: t(labelKey) }), input);
}

function dialogError(msg) {
  return h("div", { class: "error" }, verdictIcon("warn"), h("span", { textContent: t(msg) }));
}

async function openSettings() {
  const dialog = $("settings-dialog");
  const current = await state.api.Settings();
  const modes = ["auto", "direct", "manual", "pac"];
  const address = h("input", { type: "text", value: current.proxyAddress ?? "", spellcheck: false, placeholder: "proxy.firma.intern:8080" });
  const bypass = h("input", { type: "text", value: current.proxyBypass ?? "", spellcheck: false });
  const pacUrl = h("input", { type: "text", value: current.pacUrl ?? "", spellcheck: false, placeholder: "http://proxy.firma.intern/proxy.pac" });
  const manualFields = h("div", {}, field("settings.address", address), field("settings.bypass", bypass));
  const pacFields = h("div", {}, field("settings.pacUrl", pacUrl));
  const discoverable = h("input", { type: "checkbox", id: "s-discoverable", checked: current.discoverable });
  const checkUpdates = h("input", { type: "checkbox", id: "s-updates", checked: current.checkUpdates });
  const errorSlot = h("div", {});

  const selectedMode = () => dialog.querySelector('input[name="proxy-mode"]:checked')?.value ?? "auto";
  const sync = () => {
    manualFields.hidden = selectedMode() !== "manual";
    pacFields.hidden = selectedMode() !== "pac";
  };
  const save = async (e) => {
    e.preventDefault();
    const err = await state.api.SaveSettings({
      ...current, proxyMode: selectedMode(), proxyAddress: address.value.trim(), proxyBypass: bypass.value.trim(),
      pacUrl: pacUrl.value.trim(), discoverable: discoverable.checked, checkUpdates: checkUpdates.checked,
    });
    if (err?.key) {
      errorSlot.replaceChildren(dialogError(err));
      return;
    }
    dialog.close();
    restartMonitor();
  };

  dialog.replaceChildren(h("form", { method: "dialog", on: { submit: save } },
    h("h2", { textContent: t("settings.title") }),
    h("h3", { textContent: t("settings.proxy") }),
    ...modes.map((m) => h("label", { class: "choice" },
      h("input", { type: "radio", name: "proxy-mode", value: m, checked: (current.proxyMode || "auto") === m, on: { change: sync } }),
      h("span", { textContent: t(`settings.mode.${m}`) }))),
    manualFields, pacFields,
    h("p", { class: "hint", textContent: t("settings.proxyHint") }),
    h("h3", { textContent: t("settings.discovery") }),
    h("label", { class: "choice", htmlFor: "s-discoverable" }, discoverable, h("span", { textContent: t("settings.discoverable") })),
    h("p", { class: "hint", textContent: t("settings.discoverableHint") }),
    h("h3", { textContent: t("settings.updates") }),
    state.update?.enabled
      ? h("div", {},
          h("label", { class: "choice", htmlFor: "s-updates" }, checkUpdates, h("span", { textContent: t("settings.checkUpdates") })),
          h("div", { class: "update-row" },
            h("span", { class: "hint", textContent: t("settings.version", { version: state.update.current }) }),
            h("button", { class: "run-btn", type: "button", textContent: t("settings.checkNow"), on: { click: () => state.api.CheckForUpdate() } })),
          h("p", { class: "hint", id: "settings-update-state" }))
      : h("p", { class: "hint", textContent: t("settings.devBuild") }),
    errorSlot,
    h("div", { class: "actions" },
      h("button", { class: "run-btn", type: "button", textContent: t("ui.cancel"), on: { click: () => dialog.close() } }),
      h("button", { class: "run-btn primary", type: "submit", textContent: t("ui.save") }))));
  sync();
  renderUpdateSettings();
  dialog.showModal();
}

function openLogin() {
  const dialog = $("login-dialog");
  const p = state.snapshot?.proxy;
  if (!p) return;
  const user = h("input", { type: "text", spellcheck: false, autocomplete: "off" });
  const password = h("input", { type: "password", autocomplete: "off" });
  const errorSlot = h("div", {});
  const done = () => {
    password.value = "";
    dialog.close();
    restartMonitor();
  };
  const useWindows = async () => {
    state.api.ClearProxyCredentials();
    const err = await state.api.TrustProxy(p.address);
    if (err?.key) errorSlot.replaceChildren(dialogError(err));
    else done();
  };
  const submit = async (e) => {
    e.preventDefault();
    if (!user.value) return;
    await state.api.SetProxyCredentials(p.address, user.value, password.value);
    done();
  };
  dialog.replaceChildren(h("form", { method: "dialog", on: { submit } },
    h("h2", { textContent: t("login.title") }),
    h("p", { textContent: t("login.intro", { proxy: p.address }) }),
    p.authRejected ? dialogError({ key: "summary.proxyAuthRejected.d", args: { proxy: p.address } }) : null,
    // Only Windows can answer a proxy with the account the user is logged in with.
    state.platform !== "windows" ? null
      : p.windowsLoginOffered
        ? dialogError("login.windowsFailed")
        : h("div", { class: "field" },
            h("button", { class: "run-btn", type: "button", textContent: t("login.useWindows"), on: { click: useWindows } }),
            h("p", { class: "hint", textContent: t("login.windowsHint") })),
    state.platform !== "windows" ? null : h("p", { class: "divider", textContent: t("login.orTyped") }),
    field("login.user", user),
    field("login.password", password),
    h("p", { class: "hint", textContent: t("login.typedHint") }),
    errorSlot,
    h("div", { class: "actions" },
      h("button", { class: "run-btn", type: "button", textContent: t("ui.cancel"), on: { click: () => { password.value = ""; dialog.close(); } } }),
      h("button", { class: "run-btn primary", type: "submit", textContent: t("login.submit") }))));
  dialog.showModal();
}

// ---------------------------------------------------------------- shell

function renderStatusBar() {
  const npcap = state.npcap ?? { available: false };
  const left = npcap.available
    ? [verdictIcon("ok", t("verdict.ok")), h("span", { class: "primary", textContent: t("footer.full", { version: npcap.version }) })]
    : [verdictIcon("unknown", t("verdict.unknown")),
       h("span", { class: "primary", textContent: t("footer.basic") }),
       state.platform === "windows"
         ? h("button", { class: "link-btn", textContent: t("footer.getNpcap"), on: { click: () => state.api.OpenNpcapPage() } })
         : null].filter(Boolean);
  const about = h("span", { class: "about" },
    ...(state.update?.current ? [h("span", { textContent: `${state.update.current} ·` })] : []),
    h("button", { class: "link-btn", textContent: "github.com/r1sq/CantSendPackets", on: { click: () => state.api.OpenRepoPage() } }));
  $("statusbar").replaceChildren(...left, renderUpdateSlot(), about);
}

// In the status bar: visible without being in the way, and only when there's
// something to act on or to report.
function renderUpdateSlot() {
  const u = state.update;
  const slot = h("span", { class: "update-slot", id: "update-slot" });
  if (!u) return slot;
  if (u.installing) {
    slot.append(h("span", { textContent: t("update.installing") }));
  } else if (u.available) {
    slot.append(
      verdictIcon("warn", t("update.available", { version: u.available })),
      h("span", { textContent: t("update.available", { version: u.available }) }),
      h("button", { class: "link-btn", textContent: t("update.notes"), on: { click: () => state.api.OpenReleasePage() } }),
      h("button", { class: "update-btn", textContent: t("update.install"), on: { click: () => state.api.InstallUpdate() } }));
  }
  if (u.error?.key && !$("settings-dialog").open) {
    slot.append(verdictIcon("warn"), h("span", { class: "update-error", textContent: t(u.error), title: t(u.error) }));
  }
  return slot;
}

function onUpdate(status) {
  state.update = status;
  renderStatusBar();
  renderUpdateSettings();
}

function renderUpdateSettings() {
  const el = $("settings-update-state");
  if (!el) return;
  const u = state.update;
  let text = "";
  if (u?.error?.key) text = t(u.error);
  else if (u?.checking) text = t("update.checking");
  else if (u?.available) text = t("update.available", { version: u.available });
  else if (u?.upToDate) text = t("update.upToDate");
  el.textContent = text;
}

async function loadNpcap() {
  try { state.npcap = await state.api.Npcap(); } catch { state.npcap = null; }
  renderStatusBar();
  renderLoopWarning();
}

function wireShell() {
  const rt = window.runtime;
  $("refresh").append(icon("refresh"));
  $("win-min").append(icon("min"));
  $("win-max").append(icon("max"));
  $("win-close").append(icon("close"));
  $("win-min").addEventListener("click", () => rt.WindowMinimise());
  $("win-max").addEventListener("click", () => rt.WindowToggleMaximise());
  $("win-close").addEventListener("click", () => rt.Quit());
  $("lang-de").addEventListener("click", () => setLanguage("de"));
  $("lang-en").addEventListener("click", () => setLanguage("en"));
  $("adapter").addEventListener("change", (e) => selectAdapter(Number(e.target.value)));
  $("settings").append(icon("settings"));
  $("settings").addEventListener("click", openSettings);
  $("hero-action").addEventListener("click", openLogin);
  $("refresh").addEventListener("click", () => {
    restartMonitor();
    loadNpcap();
  });
  rt.EventsOn("monitor", onSnapshot);
  rt.EventsOn("peers", onPeers);
  rt.EventsOn("speed-progress", onSpeedProgress);
  rt.EventsOn("speed-incoming", onSpeedIncoming);
  rt.EventsOn("update", onUpdate);
}

function restartMonitor() {
  state.signature = ""; // forces a restart, which re-runs proxy detection
  $("hero-action").hidden = true;
  loadAdapters();
}

function fatal(message) {
  document.body.replaceChildren(h("div", { class: "fatal" }, h("h1", { textContent: t("ui.startFailed") }), h("p", { textContent: message })));
}

async function boot() {
  const deadline = Date.now() + 5000;
  while (!(window.go?.main?.App && window.runtime)) {
    if (Date.now() > deadline) return fatal(t("ui.noBackend"));
    await new Promise((r) => setTimeout(r, 25));
  }
  state.api = window.go.main.App;
  try { state.platform = await state.api.Platform(); } catch { /* an older backend is Windows */ }
  document.documentElement.dataset.platform = state.platform;
  wireShell();
  applyStaticText();
  renderStatusBar();
  resetChecks();
  renderSpeedCard();
  renderPath(null);
  renderHero();
  await loadAdapters({ keepSelection: false });
  try { onPeers(await state.api.PeerStatus()); } catch { /* the card stays empty */ }
  try { onUpdate(await state.api.UpdateStatus()); } catch { /* no update line */ }
  loadNpcap();
  // Catches a replugged cable or a new lease; the signature check means this only
  // restarts monitoring if something actually changed.
  setInterval(() => loadAdapters(), 15000);
}

boot().catch((err) => fatal(String(err)));
