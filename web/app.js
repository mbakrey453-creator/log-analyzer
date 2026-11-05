"use strict";

const $ = (id) => document.getElementById(id);

/* ---------- API ---------- */

async function api(action, payload) {
  const res = await fetch(`/api/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok || !data || data.ok !== true) {
    throw new Error((data && data.error) || `Request failed (HTTP ${res.status})`);
  }
  return data;
}

async function getStats() {
  const res = await fetch("/api/stats", { cache: "no-store" });
  const data = await res.json();
  if (!res.ok || data.ok !== true) throw new Error("stats request failed");
  return data;
}

/* ---------- feed ---------- */

function appendLines(lines) {
  const feed = $("feed");
  const frag = document.createDocumentFragment();
  for (const ln of lines) {
    const div = document.createElement("div");
    div.className = `line tag-${ln.tag || "info"}`;
    div.textContent = ln.text;
    frag.appendChild(div);
  }
  feed.appendChild(frag);
  feed.scrollTop = feed.scrollHeight;
}

function feedWelcome() {
  appendLines([
    {
      text: "Ready. Generate virtual attacks or load a sample log, then click Process Queue.",
      tag: "info",
    },
  ]);
}

/* ---------- stats + side panels ---------- */

const lastRender = { window: null, blocked: null, stack: null };

function setChip(id, value, warn) {
  const el = $(id);
  el.textContent = String(value);
  el.parentElement.classList.toggle("warn", Boolean(warn));
}

function renderStats(data) {
  const s = data.stats;
  setChip("chipQueue", s.queue, s.queue > 0);
  setChip("chipHistory", s.history);
  setChip("chipWindow", `${s.window_count}/${s.window_n}`);
  setChip("chipBlocked", s.blocked, s.blocked > 0);
  setChip("chipStack", s.stack);
  setChip("chipThreshold", s.threshold);

  $("windowNote").textContent = `${s.window_count} / ${s.window_n}`;
  $("blockedNote").textContent = String(s.blocked);

  renderWindow(data.window);
  renderBlocked(data.blocked);
  renderStack(data.stack);

  const waiting = s.queue > 0;
  $("btnProcess").classList.toggle("pulse", waiting);
  $("btnProcess").title = waiting
    ? `${s.queue} line(s) waiting in the Queue`
    : "Queue is empty";
}

function renderWindow(events) {
  const sig = JSON.stringify(events);
  if (sig === lastRender.window) return;
  lastRender.window = sig;
  const view = $("windowView");
  view.textContent = "";
  if (!events.length) {
    const div = document.createElement("div");
    div.className = "line tag-info";
    div.textContent = "(window empty)";
    view.appendChild(div);
    return;
  }
  const frag = document.createDocumentFragment();
  events.forEach((ev, i) => {
    const div = document.createElement("div");
    div.className = `line tag-${ev.tag}`;
    div.textContent = `${String(i + 1).padStart(3, " ")}. ${ev.text}`;
    frag.appendChild(div);
  });
  view.appendChild(frag);
}

function renderBlocked(ips) {
  const sig = JSON.stringify(ips);
  if (sig === lastRender.blocked) return;
  lastRender.blocked = sig;
  const list = $("blockedList");
  list.textContent = "";
  if (!ips.length) {
    const div = document.createElement("div");
    div.className = "empty";
    div.textContent = "(none blocked)";
    list.appendChild(div);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const ip of ips) {
    const row = document.createElement("div");
    row.className = "ip-row";
    const dot = document.createElement("span");
    dot.className = "dot";
    const txt = document.createElement("span");
    txt.textContent = ip;
    row.append(dot, txt);
    frag.appendChild(row);
  }
  list.appendChild(frag);
}

function renderStack(records) {
  const sig = JSON.stringify(records);
  if (sig === lastRender.stack) return;
  lastRender.stack = sig;
  const list = $("stackList");
  list.textContent = "";
  if (!records.length) {
    const div = document.createElement("div");
    div.className = "empty";
    div.textContent = "(empty)";
    list.appendChild(div);
    return;
  }
  const frag = document.createDocumentFragment();
  records.forEach((rec, i) => {
    const row = document.createElement("div");
    row.className = "stack-row";
    const idx = document.createElement("span");
    idx.className = "idx";
    idx.textContent = String(i + 1).padStart(2, "0");
    const body = document.createElement("span");
    body.className = "rec";
    const ip = document.createElement("span");
    ip.className = "ip";
    ip.textContent = rec.ip;
    body.append(ip, document.createTextNode(` — ${rec.reason}`));
    row.append(idx, body);
    frag.appendChild(row);
  });
  list.appendChild(frag);
}

/* ---------- toast ---------- */

let toastTimer = null;
function toast(message, kind) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error", kind === "error");
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

/* ---------- actions ---------- */

async function run(action, payload, opts) {
  const btn = opts && opts.button;
  if (btn) btn.disabled = true;
  try {
    const data = await api(action, payload);
    if (data.lines) appendLines(data.lines);
    if (data.stats) renderStats(data.stats);
    if (opts && opts.done) opts.done(data);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function onFilePicked(ev) {
  const file = ev.target.files && ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  file
    .text()
    .then((content) => run("load", { filename: file.name, content }))
    .catch((err) => toast(`Could not read ${file.name}: ${err.message}`, "error"));
}

function bind() {
  /* virtual attempts: slider <-> number sync */
  const range = $("attemptsRange");
  const num = $("attempts");
  range.addEventListener("input", () => {
    num.value = range.value;
  });
  num.addEventListener("input", () => {
    const v = Math.max(10, Math.min(500, parseInt(num.value, 10) || 10));
    range.value = String(v);
  });

  /* data source */
  $("btnGenerate").addEventListener("click", () =>
    run("generate", {
      count: parseInt(num.value, 10) || 50,
      attacker: $("burstIp").value.trim(),
    })
  );
  $("btnBurst").addEventListener("click", () =>
    run("burst", { ip: $("burstIp").value.trim() })
  );
  $("btnLoad").addEventListener("click", () => $("fileInput").click());
  $("fileInput").addEventListener("change", onFilePicked);

  /* processing */
  $("btnProcess").addEventListener("click", () =>
    run("process", {}, {
      done: (d) =>
        toast(
          `Processed ${d.processed} line(s) · ${d.blocks} new block(s)`,
          d.blocks > 0 ? "error" : undefined
        ),
    })
  );

  /* inspection */
  $("btnHistory").addEventListener("click", () => run("history"));
  $("btnLastN").addEventListener("click", () => run("last_n"));
  $("btnBlocked").addEventListener("click", () => run("blocked"));

  /* maintenance */
  $("btnUndo").addEventListener("click", () => run("undo"));
  $("btnClear").addEventListener("click", () => {
    if (!window.confirm("Reset queue, history, window, and undo stack?")) return;
    $("feed").textContent = "";
    run("clear");
  });

  /* detection settings: debounced auto-apply */
  let cfgTimer = null;
  const applyConfig = () => {
    clearTimeout(cfgTimer);
    cfgTimer = setTimeout(async () => {
      const n = parseInt($("windowN").value, 10);
      const t = parseInt($("threshold").value, 10);
      if (!Number.isFinite(n) || !Number.isFinite(t)) return;
      try {
        const data = await api("config", { n, threshold: t });
        const s = data.stats.stats;
        $("hintN").textContent = String(s.window_n);
        $("hintThreshold").textContent = String(s.threshold);
        renderStats(data.stats);
        toast(`Settings applied: window N=${s.window_n}, threshold=${s.threshold}`);
      } catch (err) {
        toast(err.message, "error");
      }
    }, 450);
  };
  $("windowN").addEventListener("input", applyConfig);
  $("threshold").addEventListener("input", applyConfig);

  /* feed */
  $("btnClearFeed").addEventListener("click", () => {
    $("feed").textContent = "";
  });
}

/* ---------- polling ---------- */

function markOnline(ok) {
  const dot = $("connDot");
  dot.classList.remove("wait");
  dot.classList.toggle("off", !ok);
}

async function poll() {
  try {
    const data = await getStats();
    renderStats(data);
    markOnline(true);
  } catch {
    markOnline(false);
  }
}

/* ---------- init ---------- */

async function init() {
  bind();
  feedWelcome();
  try {
    const data = await getStats();
    renderStats(data);
    $("windowN").value = data.stats.window_n;
    $("threshold").value = data.stats.threshold;
    $("hintN").textContent = String(data.stats.window_n);
    $("hintThreshold").textContent = String(data.stats.threshold);
    markOnline(true);
  } catch (err) {
    markOnline(false);
    toast("Cannot reach the analyzer server.", "error");
  }
  setInterval(poll, 1500);
}

document.addEventListener("DOMContentLoaded", init);
