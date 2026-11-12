// Regenerates the README screenshots in docs/screenshots from the browser preview,
// so they show mock data, never a real network.
//
//	node dev/screenshots/shoot.mjs        (from the repo root; or: make screenshots)
//
// Needs Node 22 or later (for its built-in WebSocket) and a Chromium-based browser,
// found on PATH or given as CHROME=/path/to/chrome. No npm packages.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

const out = "docs/screenshots";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  for (const name of ["chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]) {
    try {
      return execFileSync("which", [name], { encoding: "utf8" }).trim();
    } catch {}
  }
  throw new Error("no Chromium found; set CHROME=/path/to/chrome");
}

// Built rather than `go run`, which would leave the server running when killed.
// The preview picks a free port and logs its URL.
const work = mkdtempSync(join(tmpdir(), "csp-shots-"));
const previewBin = join(work, "preview");
execFileSync("go", ["build", "-o", previewBin, "./dev/preview"], { stdio: "inherit" });
const preview = spawn(previewBin, [], { stdio: ["ignore", "ignore", "pipe"] });
const base = await new Promise((resolve, reject) => {
  createInterface({ input: preview.stderr }).on("line", (line) => {
    const m = line.match(/(http:\/\/[^/\s]+\/)/);
    if (m) resolve(m[1]);
  });
  preview.on("exit", (code) => reject(new Error(`preview exited (${code})`)));
});

const profile = join(work, "profile");
const chrome = spawn(findChrome(), ["--headless", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--hide-scrollbars", "--font-render-hinting=none", "about:blank"], { stdio: "ignore" });

let port;
for (let i = 0; i < 100 && !port; i++) {
  await sleep(100);
  const f = join(profile, "DevToolsActivePort");
  if (existsSync(f)) port = readFileSync(f, "utf8").split("\n")[0];
}
if (!port) throw new Error("browser didn't start");
const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const ws = new WebSocket(pages.find((p) => p.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));

let seq = 0;
const pending = new Map();
ws.addEventListener("message", (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
});
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++seq;
  pending.set(id, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result)));
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.value;
const click = async (expr) => {
  if (!(await evaluate(`(() => { const el = ${expr}; if (!el) return false; el.click(); return true; })()`))) throw new Error(`nothing to click: ${expr}`);
};
const button = (text) => `[...document.querySelectorAll("button")].find((b) => b.textContent.trim() === ${JSON.stringify(text)})`;

await send("Page.enable");
await send("Runtime.enable");

// card: crop to that element. height: a taller window, so a long card isn't cut off.
async function shot(name, { lang = "en", query, steps = async () => {}, settle = 600, card = null, height = 760 }) {
  await send("Emulation.setDeviceMetricsOverride", { width: 1120, height, deviceScaleFactor: 2, mobile: false });
  await send("Page.navigate", { url: base });
  await sleep(300);
  await evaluate(`localStorage.setItem("csp.lang", ${JSON.stringify(lang)})`);
  await send("Page.navigate", { url: `${base}?${query}` });
  await sleep(1200);
  await steps();
  await sleep(settle);
  let clip;
  if (card) {
    const r = await evaluate(`(() => { const b = document.getElementById(${JSON.stringify(card)}).getBoundingClientRect(); return { x: b.x, y: b.y, width: b.width, height: b.height }; })()`);
    clip = { x: r.x - 12, y: r.y - 12, width: r.width + 24, height: r.height + 24, scale: 1 };
  }
  const { data } = await send("Page.captureScreenshot", { format: "png", ...(clip && { clip }) });
  writeFileSync(join(out, `${name}.png`), Buffer.from(data, "base64"));
  console.log(`wrote ${out}/${name}.png`);
}

try {
  // A few seconds of monitoring first, so the sparklines have something to show.
  await shot("overview", { query: "scenario=healthy&autorun", settle: 4000 });
  await shot("overview-de", { lang: "de", query: "scenario=healthy&autorun", settle: 4000 });
  await shot("loop", { query: "scenario=loop&autorun", card: "check-loop", height: 1500, settle: 4000 });
  await shot("rogue-dhcp", { query: "scenario=rogue&autorun", card: "check-dhcp", height: 1500, settle: 4000 });
  await shot("speedtest", {
    query: "scenario=healthy&autorun&fastspeed", card: "speed-card", height: 1500,
    steps: async () => { await sleep(1000); await click(button("Speed test")); await sleep(2500); },
  });
  // Linux without root: the texts that explain the password prompt.
  await shot("linux", { lang: "de", query: "scenario=basic&platform=linux&autorun", settle: 4000 });
  await shot("proxy-login", {
    query: "scenario=proxyauth",
    steps: async () => { await sleep(3000); await click(`document.getElementById("hero-action")`); },
  });
} finally {
  ws.close();
  chrome.kill();
  preview.kill();
  await sleep(300);
  rmSync(work, { recursive: true, force: true });
}
