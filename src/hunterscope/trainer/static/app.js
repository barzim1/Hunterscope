"use strict";
// Everything below renders log content with textContent / text nodes only. Never use innerHTML here:
// scenario logs are untrusted input by design.

const SEV = { critical: "KRYTYCZNY", high: "WYSOKI", medium: "ŚREDNI", low: "NISKI", info: "INFO" };
const VERDICT_HELP = {
  tp: "Realny incydent, który wymaga reakcji.",
  btp: "Detekcja zasadna, ale aktywność autoryzowana lub zgodna z procedurą.",
  fp: "Detekcja błędna: nic złego się nie dzieje.",
};
const OUTCOME_TEXT = {
  correct: "Poprawny werdykt",
  partial: "Werdykt częściowo trafiony: oba zamykają zgłoszenie, ale znaczą co innego",
  wrong: "Błędny werdykt",
};
const LOOKUP_LABEL = { asset: "Zasób (CMDB)", user: "Użytkownik / HR", change: "Kalendarz zmian", ti: "Threat intel" };

const S = {
  meta: null,
  view: "alert",
  cases: { alert: null, shift: null },
  opts: { difficulty: 0, category: "", weak: false, n: 8 },
  shift: null,
  stats: null,
};
let C = null; // the case shown in the current view

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null) continue;
    if (k.startsWith("aria-")) { el.setAttribute(k, String(v)); continue; }
    if (v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k !== "list" && k in el) el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function store(key, value) {
  try {
    if (value === undefined) return JSON.parse(localStorage.getItem(key));
    localStorage.setItem(key, JSON.stringify(value));
  } catch { /* storage may be blocked; the UI works without it */ }
  return null;
}

const fmtTime = (ts) => ts.slice(11, 19);
const fmtDate = (ts) => ts.slice(0, 10);
const sevPill = (s) => h("span", { class: `pill sev-${s}` }, SEV[s] || s);
const srcBadge = (s) => h("span", { class: `src src-${s}` }, S.meta.sources[s] || s);

// ---------------------------------------------------------------------------------------------------------------
// entity helpers (pivoting)
// ---------------------------------------------------------------------------------------------------------------
const RE_IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const RE_HASH = /\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40})\b/;
const RE_B64 = /[A-Za-z0-9+/]{40,}={0,2}/;

function entities(scn) {
  const hosts = new Set(), users = new Set(), indicators = new Set();
  for (const e of scn.events) {
    if (e.host) hosts.add(e.host);
    if (e.user) users.add(e.user.split("\\").pop().split("@")[0]);
    for (const [k, v] of Object.entries(e.fields)) {
      if (!v || v === "-") continue;
      if (/^(IpAddress|SourceIp|DestinationIp|ClientIp|SenderIp)$/.test(k) && RE_IP.test(v)) indicators.add(v);
      if (/^(DestinationHostname|HostUrl)$/.test(k)) indicators.add(v.replace(/^[a-z]+:\/\//, "").split("/")[0]);
      if (k === "Url") { try { indicators.add(new URL(v).hostname); } catch { /* not a URL */ } }
      if (k === "QueryName") indicators.add(v.split(".").slice(-3).join("."));
      if (k === "Contents") { const m = v.match(/HostUrl=https?:\/\/([^/\s]+)/); if (m) indicators.add(m[1]); }
      const hm = String(v).match(RE_HASH);
      if (hm && /Hash|SHA/i.test(k)) indicators.add(hm[1].toLowerCase());
    }
  }
  return { hosts: [...hosts].sort(), users: [...users].sort(), indicators: [...indicators].slice(0, 60) };
}

function lookupsFor(value) {
  const v = value.trim();
  const out = [];
  if (!v || v === "-") return out;
  const ents = C.ents;
  if (RE_IP.test(v) || RE_HASH.test(v) || /^(https?:\/\/)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/.*)?$/i.test(v)) out.push(["ti", "Threat intel"]);
  const bare = v.split("\\").pop().split("@")[0];
  if (ents.hosts.some((x) => x.toLowerCase() === v.toLowerCase())) { out.push(["asset", "Zasób (CMDB)"], ["change", "Kalendarz zmian"]); }
  if (ents.users.some((x) => x.toLowerCase() === bare.toLowerCase())) out.push(["user", "Użytkownik / HR"]);
  if (RE_IP.test(v)) out.push(["change", "Kalendarz zmian"]);
  return out;
}

let menuEl = null;
function closeMenu() { if (menuEl) { menuEl.remove(); menuEl = null; } }
document.addEventListener("click", closeMenu);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });

function valueMenu(evt, value) {
  evt.stopPropagation();
  closeMenu();
  const items = [["Filtruj logi po tej wartości", () => { C.filters.text = `"${value}"`; C.filters.around = null; showTab("logs"); }]];
  for (const [kind, label] of lookupsFor(value)) items.push([`Sprawdź: ${label}`, () => runLookup(kind, value)]);
  items.push(["Kopiuj", () => navigator.clipboard && navigator.clipboard.writeText(value).catch(() => {})]);
  menuEl = h("div", { class: "menu", role: "menu" }, items.map(([label, fn]) => h("button", { role: "menuitem", onclick: (e) => { e.stopPropagation(); closeMenu(); fn(); } }, label)));
  document.body.append(menuEl);
  const r = menuEl.getBoundingClientRect();
  menuEl.style.left = `${Math.min(evt.clientX, window.innerWidth - r.width - 8)}px`;
  menuEl.style.top = `${Math.min(evt.clientY, window.innerHeight - r.height - 8)}px`;
}

// ---------------------------------------------------------------------------------------------------------------
// case state
// ---------------------------------------------------------------------------------------------------------------
function newCase(scn, shiftIndex = null, debrief = null) {
  for (const e of scn.events) e._s = `${e.summary} ${e.host} ${e.user} ${e.source} ${e.raw}`.toLowerCase();
  const c = {
    scn, shiftIndex, debrief, tab: "logs", selected: null, evidence: new Set(), lookups: new Map(), hints: [],
    form: { verdict: "", actions: new Set(), text: "" }, filters: { text: "", sources: new Set(), around: null },
    startedAt: Date.now(), ents: entities(scn), tools: { input: "", enc: "utf-16le" }, onSelect: null, timerEl: null, submitting: false,
  };
  return c;
}

setInterval(() => {
  if (C && C.timerEl && !C.debrief) {
    const s = Math.floor((Date.now() - C.startedAt) / 1000);
    C.timerEl.textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }
}, 1000);

function toggleEvidence(id) {
  if (C.evidence.has(id)) C.evidence.delete(id); else C.evidence.add(id);
  for (const b of document.querySelectorAll(`[data-star="${id}"]`)) b.setAttribute("aria-pressed", C.evidence.has(id));
  refreshDecision();
}

function selectEvent(id) {
  C.selected = id;
  if (C.onSelect) C.onSelect();
}

// ---------------------------------------------------------------------------------------------------------------
// navigation
// ---------------------------------------------------------------------------------------------------------------
const VIEWS = [["alert", "Alert"], ["shift", "Nocna zmiana"], ["stats", "Statystyki"], ["help", "Jak to działa"]];

function renderNav() {
  document.getElementById("nav").replaceChildren(...VIEWS.map(([id, label]) =>
    h("button", { "aria-current": S.view === id, onclick: () => { S.view = id; render(); } }, label)));
}

function render() {
  closeMenu();
  C = S.cases[S.view] || null;
  renderNav();
  const app = document.getElementById("app");
  const views = { alert: viewAlert, shift: viewShift, stats: viewStats, help: viewHelp };
  app.replaceChildren(views[S.view]());
}

function errorBox(msg) { return h("div", { class: "callout", role: "alert" }, msg); }

// ---------------------------------------------------------------------------------------------------------------
// practice view
// ---------------------------------------------------------------------------------------------------------------
function optionControls(withN = false) {
  const sel = (id, opts, cur, onchange) => h("select", { id, "aria-label": id, onchange: (e) => onchange(e.target.value) },
    opts.map(([v, l]) => h("option", { value: v, selected: String(v) === String(cur) }, l)));
  return h("div", { class: "row" },
    h("label", {}, "Poziom: ", sel("lvl", [[0, "losowy"], [1, "1 – wyraźny"], [2, "2 – typowy"], [3, "3 – trudny"]], S.opts.difficulty, (v) => { S.opts.difficulty = +v; store("opts", S.opts); })),
    !withN && h("label", {}, "Kategoria: ", sel("cat", [["", "wszystkie"], ...S.meta.categories.map((c) => [c, c])], S.opts.category, (v) => { S.opts.category = v; store("opts", S.opts); })),
    !withN && h("label", { class: "row" }, h("input", { type: "checkbox", checked: S.opts.weak, onchange: (e) => { S.opts.weak = e.target.checked; store("opts", S.opts); } }), "Ćwicz słabe punkty"),
    withN && h("label", {}, "Liczba alertów: ", sel("n", [[6, "6"], [8, "8"], [10, "10"], [12, "12"]], S.opts.n, (v) => { S.opts.n = +v; store("opts", S.opts); })));
}

async function startPractice(extra = {}) {
  try {
    const scn = await api("/api/new", { difficulty: S.opts.difficulty, category: S.opts.category, weak: S.opts.weak, ...extra });
    S.cases.alert = newCase(scn);
    render();
    window.scrollTo(0, 0);
  } catch (e) { document.getElementById("app").prepend(errorBox(e.message)); }
}

function viewAlert() {
  const bar = h("div", { class: "card row spread" }, optionControls(), h("button", { class: "btn primary", onclick: () => startPractice() }, "Nowy alert"));
  if (!C) {
    return h("div", {}, bar, h("div", { class: "card empty" },
      h("h2", {}, "Oceń alert jak na zmianie"),
      h("p", { class: "muted" }, "Dostajesz alert z logami. Sam musisz zdecydować: True Positive, Benign True Positive czy False Positive. Wszystko, co powiedziałby Ci analityk L2, poznasz dopiero po werdykcie."),
      h("p", {}, h("button", { class: "btn primary", onclick: () => startPractice() }, "Zacznij pierwszy alert"))));
  }
  return h("div", {}, bar, caseView());
}

// ---------------------------------------------------------------------------------------------------------------
// the case
// ---------------------------------------------------------------------------------------------------------------
function alertBanner() {
  const a = C.scn.alert;
  const ev = C.scn.events.find((e) => e.id === a.trigger_event);
  const pivot = (v) => h("span", { class: "chip", title: "Filtruj logi", onclick: () => { C.filters.text = `"${v}"`; C.filters.around = null; showTab("logs"); } }, v);
  return h("div", { class: `card alert sev-${a.severity}-b` },
    h("div", { class: "row" }, sevPill(a.severity), h("span", { class: "muted" }, a.source), h("span", { class: "muted" }, `${fmtDate(a.ts)} ${fmtTime(a.ts)} ${S.meta.tz}`),
      C.scn.difficulty && h("span", { class: "muted" }, `· poziom ${C.scn.difficulty}`)),
    h("h2", {}, a.rule),
    h("p", {}, a.description),
    h("div", { class: "row" }, a.host && h("span", {}, "Host: ", pivot(a.host)), a.user && h("span", {}, "Użytkownik: ", pivot(a.user.split("\\").pop()))),
    ev && h("details", { class: "detail" }, h("summary", {}, "Zdarzenie, które wywołało alert"),
      h("dl", { class: "kv" }, Object.entries(ev.fields).filter(([, v]) => v !== "").flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, h("span", { class: "val", onclick: (e) => valueMenu(e, String(v)) }, v))]))));
}

function caseView() {
  const root = h("div", {});
  root.append(alertBanner());
  if (C.debrief) root.append(debriefCard());
  const tabs = [["logs", `Logi (${C.scn.events.length})`], ["tree", "Drzewo procesów"]];
  if (C.scn.file) tabs.push(["file", "Plik"]);
  tabs.push(["context", "Kontekst"], ["tools", "Narzędzia"]);
  const strip = h("div", { class: "tabs", role: "tablist" }, tabs.map(([id, label]) =>
    h("button", { role: "tab", dataset: { tab: id }, "aria-selected": C.tab === id, onclick: () => showTab(id) }, label)));
  C.contentEl = h("div", {});
  const main = h("div", { class: "card" }, strip, C.contentEl);
  const layout = h("div", { class: C.debrief ? "" : "grid" }, main, !C.debrief && decisionPanel());
  root.append(layout);
  fillTab();
  return root;
}

function showTab(id) {
  C.tab = id;
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-selected", b.dataset.tab === id);
  fillTab();
}

function fillTab() {
  C.onSelect = null;
  const builders = { logs: tabLogs, tree: tabTree, file: tabFile, context: tabContext, tools: tabTools };
  C.contentEl.replaceChildren(builders[C.tab]());
  if (C.onSelect && C.selected) C.onSelect();
}

// --- logs ------------------------------------------------------------------------------------------------------
function parseSearch(text) {
  const terms = [];
  const re = /(-?)"([^"]*)"|(-?)(\S+)/g;
  let m;
  while ((m = re.exec(text))) terms.push({ neg: (m[1] || m[3]) === "-", s: (m[2] ?? m[4]).toLowerCase() });
  return terms;
}

function tabLogs() {
  const f = C.filters;
  const search = h("input", { type: "text", value: f.text, placeholder: 'Szukaj, np. powershell -chrome  lub  "10.20.31.5"', "aria-label": "Szukaj w logach" });
  const counter = h("span", { class: "muted" });
  const around = h("span", {});
  const tbody = h("tbody", {});
  const detail = h("div", {});
  const sources = [...new Set(C.scn.events.map((e) => e.source))];
  const srcBar = h("div", { class: "srcfilter row" }, sources.map((s) => h("button", {
    "aria-pressed": f.sources.has(s), onclick: (e) => { f.sources.has(s) ? f.sources.delete(s) : f.sources.add(s); e.currentTarget.setAttribute("aria-pressed", f.sources.has(s)); paint(); },
  }, S.meta.sources[s] || s)));
  const reveal = new Map();
  if (C.debrief) {
    C.debrief.key_events.forEach((k) => reveal.set(k.id, "key"));
    C.debrief.herrings.forEach((k) => reveal.set(k.id, "herring"));
  }

  function visible() {
    const terms = parseSearch(f.text);
    return C.scn.events.filter((e) => {
      if (f.sources.size && !f.sources.has(e.source)) return false;
      if (f.around && Math.abs(Date.parse(e.ts) - f.around.ms) > f.around.min * 60000) return false;
      return terms.every((t) => e._s.includes(t.s) !== t.neg);
    });
  }
  function paint() {
    const rows = visible();
    tbody.replaceChildren(...rows.map(rowFor));
    counter.textContent = `Pokazano ${rows.length} z ${C.scn.events.length}`;
    around.replaceChildren(...(f.around ? [h("span", { class: "chip", onclick: () => { f.around = null; paint(); } }, `±${f.around.min} min wokół ${fmtTime(f.around.ts)} ✕`)] : []));
  }
  function rowFor(e) {
    const r = reveal.get(e.id);
    return h("tr", {
      class: `ev${e.id === C.scn.alert.trigger_event ? " trigger" : ""}${e.id === C.selected ? " sel" : ""}`, tabindex: 0, dataset: { id: e.id },
      onclick: () => selectEvent(e.id), onkeydown: (k) => { if (k.key === "Enter") selectEvent(e.id); },
    },
      h("td", {}, h("button", { class: "star", dataset: { star: e.id }, "aria-pressed": C.evidence.has(e.id), "aria-label": "Oznacz jako dowód", title: "Oznacz jako dowód",
        onclick: (k) => { k.stopPropagation(); toggleEvidence(e.id); } }, "★")),
      h("td", { class: "t" }, fmtTime(e.ts)), h("td", {}, srcBadge(e.source)), h("td", { class: "ent" }, e.host || e.user || ""),
      h("td", { class: "sum" }, e.summary, r === "key" && h("span", { class: "reveal-key" }, "KLUCZOWE"), r === "herring" && h("span", { class: "reveal-herring" }, "ZMYŁKA")));
  }
  search.addEventListener("input", () => { f.text = search.value; paint(); });
  C.onSelect = () => {
    for (const tr of tbody.children) tr.classList.toggle("sel", tr.dataset.id === C.selected);
    const e = C.scn.events.find((x) => x.id === C.selected);
    detail.replaceChildren(e ? detailPanel(e, { onAround: (ev) => { f.around = { ms: Date.parse(ev.ts), min: 10, ts: ev.ts }; paint(); } }) : "");
  };
  paint();
  return h("div", {},
    h("div", { class: "filters" }, search, srcBar, h("button", { class: "btn small", onclick: () => { f.text = ""; f.sources.clear(); f.around = null; showTab("logs"); } }, "Wyczyść")),
    h("div", { class: "row spread" }, counter, around),
    h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["★", "Czas", "Źródło", "Host / użytkownik", "Zdarzenie"].map((t) => h("th", {}, t)))), tbody)),
    detail);
}

function detailPanel(e, { onAround } = {}) {
  const b64 = Object.values(e.fields).map((v) => String(v).match(RE_B64)).filter((m) => m && !/^[0-9a-fA-F]+$/.test(m[0])).sort((a, b) => b[0].length - a[0].length)[0];
  const rev = C.debrief && (C.debrief.key_events.find((k) => k.id === e.id) || C.debrief.herrings.find((k) => k.id === e.id));
  const isKey = C.debrief && C.debrief.key_events.some((k) => k.id === e.id);
  return h("div", { class: "detail" },
    h("div", { class: "row spread" },
      h("div", { class: "row" }, srcBadge(e.source), h("strong", {}, e.id), h("span", { class: "muted mono" }, `${fmtDate(e.ts)} ${fmtTime(e.ts)}`)),
      h("div", { class: "row" },
        onAround && h("button", { class: "btn small", onclick: () => onAround(e) }, "±10 min wokół"),
        b64 && h("button", { class: "btn small", onclick: () => { C.tools.input = b64[0]; showTab("tools"); } }, "Dekoduj Base64"),
        h("button", { class: "btn small", dataset: { star: e.id }, "aria-pressed": C.evidence.has(e.id), onclick: () => toggleEvidence(e.id) }, "★ Dowód"))),
    h("dl", { class: "kv" }, Object.entries(e.fields).filter(([, v]) => v !== "").flatMap(([k, v]) =>
      [h("dt", {}, k), h("dd", {}, h("span", { class: "val", onclick: (ev) => valueMenu(ev, String(v)) }, v))])),
    h("h4", {}, "Surowy log"),
    h("pre", {}, e.raw),
    rev && h("div", { class: `note-box${isKey ? "" : " herring"}` }, h("strong", {}, isKey ? "Dlaczego to ważne: " : "Dlaczego to zmyłka: "), rev.note));
}

// --- process tree ----------------------------------------------------------------------------------------------
function tabTree() {
  const nodes = C.scn.tree;
  if (!nodes.length) return h("p", { class: "muted" }, "Brak zdarzeń tworzenia procesów (Sysmon 1) w tym scenariuszu.");
  const detail = h("div", {});
  const hosts = [...new Set(nodes.map((n) => n.host))];
  const out = [];
  for (const host of hosts) {
    const list = nodes.filter((n) => n.host === host);
    const pids = new Set(list.map((n) => n.pid));
    const kids = (pid) => list.filter((n) => n.ppid === pid && n.pid !== pid);
    const draw = (n, depth = 0) => {
      const exe = n.image.split("\\").pop();
      const btn = h("button", { class: "node", dataset: { id: n.id }, onclick: () => selectEvent(n.id) },
        h("span", { class: "img" }, exe), h("span", { class: "muted" }, ` ${fmtTime(n.ts)} · ${n.user.split("\\").pop()} · PID ${n.pid}`),
        n.signed === "Yes" ? h("span", { class: "badge ok" }, "podpisany") : h("span", { class: "badge no" }, "niepodpisany"),
        n.integrity && n.integrity !== "Medium" && h("span", { class: "badge no" }, n.integrity),
        h("span", { class: "cmd" }, n.cmd), h("span", { class: "cmd" }, n.image));
      const children = depth < 12 ? kids(n.pid) : [];
      return h("li", {}, btn, children.length ? h("ul", {}, children.map((c) => draw(c, depth + 1))) : null);
    };
    const roots = list.filter((n) => !pids.has(n.ppid) || n.ppid === n.pid);
    out.push(h("h4", {}, `Host ${host}`), h("div", { class: "tree" }, h("ul", {}, roots.map((r) => draw(r)))));
  }
  C.onSelect = () => {
    for (const b of document.querySelectorAll(".node")) b.classList.toggle("sel", b.dataset.id === C.selected);
    const e = C.scn.events.find((x) => x.id === C.selected);
    detail.replaceChildren(e ? detailPanel(e) : "");
  };
  return h("div", {}, h("p", { class: "muted" }, "Drzewo z zdarzeń Sysmon 1. Kliknij proces, aby zobaczyć pełne zdarzenie. Zwróć uwagę na rodzica, podpis i ścieżkę."), out, detail);
}

// --- file ------------------------------------------------------------------------------------------------------
function tabFile() {
  const f = C.scn.file;
  const rows = [["Nazwa", f.name], ["Ścieżka", f.path], ["Rozmiar", f.size], ["SHA-256", f.sha256], ["Typ", f.type], ["Podpis", f.signature],
    ["Mark-of-the-Web", f.mark_of_the_web], ["Występowanie w organizacji", f.org_prevalence], ["Wynik sandboxa (symulacja)", f.sandbox_verdict]];
  return h("div", {},
    h("dl", { class: "kv" }, rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, h("span", { class: "val", onclick: (e) => valueMenu(e, String(v)) }, v))])),
    h("h4", {}, "Zachowanie w sandboxie"), h("ul", { class: "plain" }, f.behaviors.map((b) => h("li", {}, b))));
}

// --- context lookups -------------------------------------------------------------------------------------------
async function runLookup(kind, value) {
  const v = value.trim();
  if (!v) return;
  try {
    const result = await api("/api/lookup", { token: C.scn.token, kind, value: v });
    C.lookups.delete(`${kind}:${v.toLowerCase()}`);
    C.lookups.set(`${kind}:${v.toLowerCase()}`, { kind, value: v, result });
    showTab("context");
  } catch (e) { window.alert(e.message); }
}

function tabContext() {
  const ents = C.ents;
  const lists = { asset: ents.hosts, user: ents.users, change: [...ents.hosts, ...ents.indicators.filter((i) => RE_IP.test(i))], ti: ents.indicators };
  const form = (kind, hint) => {
    const listId = `dl-${kind}`;
    const input = h("input", { type: "text", list: listId, placeholder: hint, "aria-label": LOOKUP_LABEL[kind] });
    return h("form", { class: "card", onsubmit: (e) => { e.preventDefault(); runLookup(kind, input.value); } },
      h("h4", {}, LOOKUP_LABEL[kind]), input, h("datalist", { id: listId }, lists[kind].map((x) => h("option", { value: x }))),
      h("button", { class: "btn small", type: "submit" }, "Sprawdź"));
  };
  const history = [...C.lookups.values()].reverse();
  return h("div", {},
    h("p", { class: "muted" }, "Brak wpisu to też informacja. Każde sprawdzenie liczy się do oceny dochodzenia. Możesz też kliknąć dowolną wartość w logach."),
    h("div", { class: "lookups" }, form("asset", "np. nazwa hosta"), form("user", "np. login"), form("change", "host lub IP"), form("ti", "IP, domena, URL lub hash")),
    history.length ? history.map((i) => resultCard(i)) : h("p", { class: "muted" }, "Jeszcze nic nie sprawdzałeś."));
}

function resultCard(item) {
  const r = item.result;
  return h("div", { class: `rec${r.found ? "" : " miss"}` }, h("h4", {}, `${r.title}: ${item.value}`),
    r.found ? r.records.map((rec) => h("dl", { class: "kv" }, rec.flatMap(([k, v]) => [h("dt", {}, k), h("dd", { class: "sans" }, v)]))) : h("p", { class: "muted" }, r.message));
}

// --- tools -----------------------------------------------------------------------------------------------------
function entropy(s) {
  if (!s) return 0;
  const counts = {};
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  return -Object.values(counts).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0);
}

function tabTools() {
  const t = C.tools;
  const out = h("pre", {});
  const input = h("textarea", { "aria-label": "Tekst do przetworzenia", placeholder: "Wklej Base64 (np. wartość po -enc), tekst z %-kodowaniem, nazwę z DNS lub czas UTC…" }, t.input);
  const enc = h("select", { "aria-label": "Kodowanie" }, [["utf-16le", "UTF-16LE (PowerShell -enc)"], ["utf-8", "UTF-8"]].map(([v, l]) => h("option", { value: v, selected: v === t.enc }, l)));
  const run = (fn) => { t.input = input.value; t.enc = enc.value; try { out.textContent = fn(input.value.trim()); } catch (e) { out.textContent = `Błąd: ${e.message}`; } };
  const b64 = (s) => { const bin = atob(s.replace(/\s+/g, "")); const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0)); return new TextDecoder(enc.value).decode(bytes); };
  const utc = (s) => {
    const d = new Date(/z$|[+-]\d\d:?\d\d$/i.test(s) ? s : `${s.replace(" ", "T")}Z`);
    if (isNaN(d)) throw new Error("niepoprawny czas, użyj np. 2026-02-03T01:14:00Z");
    const cet = new Date(d.getTime() + 3600_000).toISOString().replace("T", " ").slice(0, 19);
    return `UTC: ${d.toISOString().replace("T", " ").slice(0, 19)}\nCET (UTC+1): ${cet}`;
  };
  const buttons = [
    ["Dekoduj Base64", () => run(b64)], ["Dekoduj %-kodowanie URL", () => run((s) => decodeURIComponent(s))],
    ["UTC → CET", () => run(utc)], ["Długość i entropia", () => run((s) => `Długość: ${s.length} znaków\nEntropia Shannona: ${entropy(s).toFixed(2)} bit/znak\n(tekst ≈ 3,5–4,5; losowy base32 ≈ 4,5–5; heks ≈ 3,5–4)`)],
  ];
  if (t.input && RE_B64.test(t.input)) run(b64);
  return h("div", {}, h("p", { class: "muted" }, "Lokalne narzędzia w stylu CyberChef. Nic nie opuszcza przeglądarki."),
    input, h("div", { class: "row" }, enc, buttons.map(([l, fn]) => h("button", { class: "btn small", onclick: fn }, l))), out);
}

// --- decision --------------------------------------------------------------------------------------------------
function decisionPanel() {
  const f = C.form;
  const counter = h("span", { class: "muted" });
  C.submitBtn = h("button", { class: "btn primary", onclick: submit }, "Zatwierdź werdykt");
  C.chipsEl = h("div", { class: "evchips" });
  C.hintsEl = h("div", {});
  C.timerEl = h("span", { class: "timer" }, "00:00");
  const area = h("textarea", { placeholder: "Co widziałeś, co to oznacza, co zrobiłeś. Pisz tak, jakby miała to czytać następna zmiana.", "aria-label": "Uzasadnienie", value: f.text,
    oninput: (e) => { f.text = e.target.value; counter.textContent = `${f.text.trim().length} znaków (min. 20)`; refreshDecision(); } });
  counter.textContent = `${f.text.trim().length} znaków (min. 20)`;
  C.hintBtn = h("button", { class: "btn small", onclick: revealHint }, "Podpowiedź (−5 pkt)");
  const panel = h("aside", { class: "card decision" },
    h("div", { class: "row spread" }, h("h3", {}, "Twoja decyzja"), C.timerEl),
    h("div", {}, Object.entries(S.meta.verdicts).map(([id, label]) => h("label", { class: "verdict" },
      h("input", { type: "radio", name: "verdict", value: id, checked: f.verdict === id, onchange: () => { f.verdict = id; refreshDecision(); } }),
      h("strong", {}, `${id.toUpperCase()} · ${label}`), h("small", {}, VERDICT_HELP[id])))),
    h("h4", {}, "Akcje"),
    Object.entries(S.meta.actions).map(([id, label]) => h("label", { class: "check" },
      h("input", { type: "checkbox", checked: f.actions.has(id), onchange: (e) => { e.target.checked ? f.actions.add(id) : f.actions.delete(id); } }), label)),
    h("h4", {}, "Kluczowe dowody (★ w logach)"), C.chipsEl,
    h("h4", {}, "Uzasadnienie"), area, counter,
    h("div", { class: "row spread" }, C.hintBtn, C.submitBtn), C.hintsEl, h("div", { id: "submit-error" }));
  refreshDecision();
  return panel;
}

function refreshDecision() {
  if (!C.chipsEl) return;
  C.chipsEl.replaceChildren(...[...C.evidence].sort().map((id) => {
    const e = C.scn.events.find((x) => x.id === id);
    return h("span", { class: "chip", title: e.summary, onclick: () => { toggleEvidence(id); } }, `${id} ✕`);
  }));
  if (!C.evidence.size) C.chipsEl.replaceChildren(h("span", { class: "muted" }, "Jeszcze nic nie oznaczono."));
  C.submitBtn.disabled = !(C.form.verdict && C.form.text.trim().length >= 20) || C.submitting;
  C.hintBtn.disabled = C.hints.length >= 3;
  C.hintsEl.replaceChildren(...C.hints.map((t, i) => h("div", { class: "hint" }, h("strong", {}, `Podpowiedź ${i + 1}: `), t)));
}

async function revealHint() {
  try {
    const r = await api("/api/hint", { token: C.scn.token, level: C.hints.length + 1 });
    C.hints.push(r.hint);
    refreshDecision();
  } catch (e) { window.alert(e.message); }
}

async function submit() {
  C.submitting = true;
  refreshDecision();
  try {
    const d = await api("/api/submit", {
      token: C.scn.token, verdict: C.form.verdict, actions: [...C.form.actions], evidence: [...C.evidence],
      lookups: [...C.lookups.values()].map((x) => `${x.kind}:${x.value}`), hints: C.hints.length,
      seconds: Math.round((Date.now() - C.startedAt) / 1000), justification: C.form.text, shift_id: C.shiftIndex !== null && S.shift ? S.shift.id : null,
    });
    C.debrief = d;
    C.seconds = Math.round((Date.now() - C.startedAt) / 1000);
    if (C.shiftIndex !== null && S.shift) {
      const it = S.shift.items[C.shiftIndex];
      it.debrief = d; it.status = d.result.outcome; it.score = d.result.score; it.seconds = C.seconds; it.justification = C.form.text;
      it.verdict = C.form.verdict;
    }
    render();
    window.scrollTo(0, 0);
  } catch (e) {
    C.submitting = false;
    refreshDecision();
    document.getElementById("submit-error").replaceChildren(errorBox(e.message));
  }
}

// ---------------------------------------------------------------------------------------------------------------
// debrief
// ---------------------------------------------------------------------------------------------------------------
function bar(label, value, max) {
  const fill = h("i", {});
  fill.style.width = `${Math.max(0, Math.min(100, (value / max) * 100))}%`;
  return [h("span", {}, label), h("div", { class: "bar" }, fill), h("span", { class: "mono" }, `${value}/${max}`)];
}

function debriefCard() {
  const d = C.debrief, r = d.result, bd = r.breakdown;
  const chosen = new Set(d.your.actions);
  if (chosen.has("close_tune")) chosen.add("close");
  const keyFound = d.key_events.filter((k) => k.found).length;
  const lesson = d.lessons;
  const labelFor = (k) => { const [kind, val] = [k.split(":")[0], k.split(":").slice(1).join(":")]; return `${LOOKUP_LABEL[kind] || kind}: ${val}`; };
  const section = (title, ...kids) => h("div", { class: "card" }, h("h3", {}, title), ...kids);

  const root = h("div", {});
  const head = h("div", { class: "card" },
    d.repeat && h("div", { class: "callout" }, "To powtórka tego samego scenariusza. Wynik nie wchodzi do statystyk."),
    h("div", { class: "row spread" },
      h("div", {}, h("div", { class: `score outcome-${r.outcome}` }, `${r.score}/100`), h("div", { class: `outcome-${r.outcome}` }, h("strong", {}, OUTCOME_TEXT[r.outcome])), h("div", { class: "muted" }, r.grade)),
      h("div", { class: "bars" }, ...bar("Werdykt", bd.verdict, 50), ...bar("Akcje", bd.actions, 15), ...bar("Dowody", bd.evidence, 20), ...bar("Dochodzenie", bd.investigation, 15),
        bd.hints ? [h("span", {}, "Podpowiedzi"), h("span", {}), h("span", { class: "mono" }, String(bd.hints))] : [])),
    r.flags.includes("false_negative") && h("div", { class: "callout" }, h("strong", {}, "Prawdziwy incydent uznany za niegroźny. "), "To najdroższy błąd w SOC, dlatego wynik jest ograniczony do 30 pkt. Zobacz sekcję „Dowody”: co przeoczyłeś?"),
    r.flags.includes("over_escalation") && h("div", { class: "callout" }, h("strong", {}, "Eskalacja bez incydentu. "), "Koszt: czas L2 i zmęczenie alertami. Zobacz, które sygnały sprawiały wrażenie zagrożenia, a nie były nim."),
    h("p", {}, h("strong", {}, `${d.template} · `), `Prawidłowy werdykt: `, h("strong", {}, `${d.truth.verdict.toUpperCase()} (${d.truth.verdict_label})`), `, priorytet: `, sevPill(d.truth.severity), "  Twój: ", h("strong", {}, d.your.verdict.toUpperCase())),
    h("p", {}, d.truth.summary));
  root.append(head);

  root.append(h("div", { class: "two card" },
    h("div", {}, h("h4", {}, "Twoje uzasadnienie"), h("div", { class: "compare" }, d.your.justification)),
    h("div", {}, h("h4", {}, "Wzorcowa notatka do ticketu"), h("div", { class: "compare" }, d.truth.model_note))));

  root.append(section(`Dowody: znalazłeś ${keyFound} z ${d.key_events.length} kluczowych`,
    h("ul", { class: "plain" }, d.key_events.map((k) => h("li", { class: k.found ? "item-ok" : "item-no" },
      h("code", {}, `${k.id} `), k.summary, " ", h("button", { class: "btn small ghost", onclick: () => { C.filters.text = ""; C.filters.around = null; C.selected = k.id; showTab("logs"); } }, "pokaż w logach"), h("br", {}), h("span", { class: "muted" }, k.note)))),
    d.herrings.length ? [h("h4", {}, "Zmyłki: wyglądają inaczej, niż jest"), h("ul", { class: "plain" }, d.herrings.map((k) => h("li", { class: k.flagged ? "item-no" : "item-warn" },
      h("code", {}, `${k.id} `), k.summary, k.flagged && h("strong", {}, "  (oznaczyłeś jako dowód)"), h("br", {}), h("span", { class: "muted" }, k.note))))] : []));

  root.append(section("Akcje",
    h("ul", { class: "plain" },
      d.actions.required.map((a) => h("li", { class: chosen.has(a.id) ? "item-ok" : "item-no" }, `${a.label}  `, h("span", { class: "muted" }, chosen.has(a.id) ? "(wybrane, wymagane)" : "(wymagane, pominąłeś)"))),
      d.actions.harmful.filter((a) => chosen.has(a.id)).map((a) => h("li", { class: "item-no" }, `${a.label}  `, h("span", { class: "muted" }, "(wybrane, a niewłaściwe w tym przypadku)"))))));

  root.append(section("Dochodzenie: narzędzia kontekstowe",
    r.lookups_hit.length || r.lookups_missed.length ? h("ul", { class: "plain" }, r.lookups_hit.map((k) => h("li", { class: "item-ok" }, labelFor(k))), r.lookups_missed.map((k) => h("li", { class: "item-no" }, `${labelFor(k)}  `, h("span", { class: "muted" }, "(nie sprawdziłeś)")))) : h("p", { class: "muted" }, "Ten scenariusz nie wymagał sprawdzeń kontekstowych."),
    h("details", {}, h("summary", {}, "Co pokazałyby wszystkie narzędzia kontekstowe"), contextDump(d.context))));

  root.append(h("div", { class: "two" },
    h("div", { class: "card col-tp" }, h("h3", {}, "Typowe oznaki prawdziwego incydentu"), h("ul", { class: "plain" }, lesson.tp_signs.map((s) => h("li", {}, s)))),
    h("div", { class: "card col-fp" }, h("h3", {}, "Typowe oznaki FP / zasadnej detekcji"), h("ul", { class: "plain" }, lesson.fp_signs.map((s) => h("li", {}, s))))));
  root.append(h("div", { class: "two" },
    h("div", { class: "card" }, h("h3", {}, "Checklista: na co spojrzeć"), h("ol", { class: "plain" }, lesson.checklist.map((s) => h("li", {}, s)))),
    h("div", { class: "card" }, h("h3", {}, "Pułapki"), h("ul", { class: "plain" }, lesson.pitfalls.map((s) => h("li", {}, s))),
      h("h4", {}, "MITRE ATT&CK"), h("ul", { class: "plain" }, lesson.attack.map((s) => h("li", {}, s))),
      h("h4", {}, "Gdzie to sprawdzić w praktyce"), h("ul", { class: "plain" }, lesson.tips.map((s) => h("li", {}, s))))));

  const next = h("div", { class: "row" },
    C.shiftIndex !== null ? h("button", { class: "btn primary", onclick: nextShiftItem }, "Następny alert z kolejki") : h("button", { class: "btn primary", onclick: () => startPractice() }, "Następny alert"),
    h("button", { class: "btn", onclick: () => document.querySelector(".tabs").scrollIntoView({ behavior: "smooth" }) }, "Wróć do logów (z oznaczonymi dowodami)"));
  root.append(h("div", { class: "card" }, next));
  return root;
}

function contextDump(ctx) {
  const blocks = [];
  const add = (title, obj) => { for (const [k, rec] of Object.entries(obj)) blocks.push(h("div", { class: "rec" }, h("h4", {}, `${title}: ${k}`), h("dl", { class: "kv" }, Object.entries(rec).flatMap(([a, b]) => [h("dt", {}, a), h("dd", { class: "sans" }, b)])))); };
  add("Zasób", ctx.assets); add("Użytkownik", ctx.users); add("Threat intel", ctx.ti);
  ctx.changes.forEach((c) => blocks.push(h("div", { class: "rec" }, h("h4", {}, `Zmiana ${c.ticket}`), h("dl", { class: "kv" }, h("dt", {}, "Zakres"), h("dd", { class: "sans" }, c.scope), h("dt", {}, "Opis"), h("dd", { class: "sans" }, c.title), h("dt", {}, "Okno"), h("dd", { class: "sans" }, `${c.start} – ${c.end}`)))));
  return h("div", {}, blocks.length ? blocks : h("p", { class: "muted" }, "Brak danych."));
}

// ---------------------------------------------------------------------------------------------------------------
// shift
// ---------------------------------------------------------------------------------------------------------------
async function startShift() {
  try {
    const sh = await api("/api/shift", { n: S.opts.n, difficulty: S.opts.difficulty });
    S.shift = { id: sh.shift_id, items: sh.items.map((i) => ({ ...i, status: "new" })), done: false };
    S.cases.shift = null;
    await openShiftItem(0);
  } catch (e) { document.getElementById("app").prepend(errorBox(e.message)); }
}

async function openShiftItem(i) {
  const it = S.shift.items[i];
  const scn = await api(`/api/scenario?token=${encodeURIComponent(it.token)}`);
  S.cases.shift = newCase(scn, i, it.debrief || null);
  if (it.debrief) S.cases.shift.form.text = it.justification || "";
  render();
  window.scrollTo(0, 0);
}

function nextShiftItem() {
  const items = S.shift.items;
  const idx = items.findIndex((it, i) => it.status === "new" && i !== C.shiftIndex);
  if (idx === -1) { S.shift.done = true; render(); } else openShiftItem(idx);
}

function viewShift() {
  if (!S.shift) {
    return h("div", {}, h("div", { class: "card" },
      h("h2", {}, "Nocna zmiana"),
      h("p", {}, "Kolejka alertów jak na prawdziwej zmianie: większość to fałszywe alarmy i zasadne detekcje zatwierdzonych działań, a wśród nich ukryty jest jeden lub dwa prawdziwe incydenty. Tak wygląda realny stosunek sygnału do szumu."),
      h("p", { class: "muted" }, "Nie ma kolejności ani wskazówki, który alert jest groźny. Na koniec dostajesz podsumowanie i notatkę przekazania zmiany."),
      optionControls(true), h("p", {}, h("button", { class: "btn primary", onclick: startShift }, "Rozpocznij zmianę"))));
  }
  if (S.shift.done) return shiftSummary();
  const done = S.shift.items.filter((i) => i.status !== "new").length;
  const queue = h("aside", { class: "card" }, h("h3", {}, `Kolejka (${done}/${S.shift.items.length})`),
    h("div", { class: "queue" }, S.shift.items.map((it, i) => h("button", { class: "qitem", "aria-current": C && C.shiftIndex === i, onclick: () => openShiftItem(i) },
      h("span", { class: "row spread" }, sevPill(it.severity), h("span", { class: `status-${it.status}` }, { new: "do oceny", correct: "✓ trafione", partial: "~ częściowo", wrong: "✗ błąd" }[it.status])),
      h("span", { class: "rule" }, it.rule), h("span", { class: "muted mono" }, `${it.source} · ${it.host || "-"}`)))),
    h("p", {}, h("button", { class: "btn", onclick: () => { S.shift.done = true; render(); } }, "Zakończ zmianę")));
  return h("div", { class: "shiftgrid" }, queue, C ? caseView() : h("div", { class: "card" }, "Wybierz alert z kolejki."));
}

function shiftSummary() {
  const items = S.shift.items;
  const solved = items.filter((i) => i.status !== "new");
  const pts = solved.reduce((a, i) => a + i.score, 0);
  const missed = solved.filter((i) => i.debrief.result.flags.includes("false_negative"));
  const skipped = items.filter((i) => i.status === "new");
  const note = [`# Przekazanie zmiany (trening)`, "", `Alerty ocenione: ${solved.length}/${items.length}.`, ""].concat(solved.flatMap((i) => [
    `## [${i.verdict.toUpperCase()}] ${i.rule}: ${i.host || "-"}`, `${i.justification}`, ""])).join("\n");
  return h("div", {},
    h("div", { class: "card" }, h("h2", {}, "Podsumowanie zmiany"),
      h("div", { class: "statgrid" },
        h("div", { class: "stat" }, h("b", {}, `${solved.length}/${items.length}`), "ocenionych"),
        h("div", { class: "stat" }, h("b", {}, solved.length ? Math.round(pts / solved.length) : 0), "średni wynik"),
        h("div", { class: "stat" }, h("b", { class: missed.length ? "outcome-wrong" : "outcome-correct" }, missed.length), "przeoczone incydenty"),
        h("div", { class: "stat" }, h("b", {}, solved.reduce((a, i) => a + (i.seconds || 0), 0) / Math.max(solved.length, 1) | 0), "śr. sekund / alert")),
      missed.length ? h("div", { class: "callout" }, h("strong", {}, "Przeoczyłeś prawdziwy incydent. "), "W realnej zmianie to ten alert zadecydowałby o ocenie całej nocy: ", missed.map((i) => i.rule).join("; ")) : null,
      skipped.length ? h("div", { class: "callout" }, `Pominięte alerty (${skipped.length}): w realnej zmianie niezamknięty alert trafia do następnej zmiany.`) : null),
    h("div", { class: "card" }, h("table", {}, h("thead", {}, h("tr", {}, ["Alert", "Host", "Twój", "Prawidłowy", "Wynik"].map((t) => h("th", {}, t)))),
      h("tbody", {}, items.map((it) => h("tr", {}, h("td", {}, it.rule), h("td", { class: "mono" }, it.host || "-"), h("td", {}, it.verdict ? it.verdict.toUpperCase() : "-"),
        h("td", {}, it.debrief ? it.debrief.truth.verdict.toUpperCase() : "?"), h("td", { class: `num status-${it.status}` }, it.status === "new" ? "-" : it.score)))))),
    h("div", { class: "card" }, h("h3", {}, "Notatka przekazania zmiany (z Twoich uzasadnień)"), h("textarea", { class: "out", readOnly: true, value: note, "aria-label": "Notatka przekazania zmiany" }),
      h("p", { class: "row" }, h("button", { class: "btn", onclick: () => navigator.clipboard && navigator.clipboard.writeText(note).catch(() => {}) }, "Kopiuj"),
        h("button", { class: "btn primary", onclick: () => { S.shift = null; S.cases.shift = null; render(); } }, "Nowa zmiana"))));
}

// ---------------------------------------------------------------------------------------------------------------
// stats and help
// ---------------------------------------------------------------------------------------------------------------
function viewStats() {
  const box = h("div", {}, h("p", { class: "muted" }, "Ładowanie…"));
  api("/api/stats").then((s) => box.replaceChildren(statsBody(s))).catch((e) => box.replaceChildren(errorBox(e.message)));
  return box;
}

function statsBody(s) {
  if (!s.attempts) return h("div", { class: "card empty" }, h("h2", {}, "Brak danych"), h("p", { class: "muted" }, "Rozwiąż pierwszy alert, a tutaj pojawi się Twój profil błędów."));
  const acc = Math.round((s.correct / s.attempts) * 100);
  const names = { tp: "TP", btp: "BTP", fp: "FP" };
  const b = s.bias;
  let bias = null;
  if (b.tp_total >= 3 && b.missed_tp / b.tp_total >= 0.25) bias = `Przeoczasz prawdziwe incydenty: ${b.missed_tp} z ${b.tp_total} TP uznałeś za niegroźne. To jest priorytet do ćwiczenia: przy wątpliwościach pytaj, co musiałoby być prawdą, żeby to był atak.`;
  else if (b.benign_total >= 3 && b.over_escalated / b.benign_total >= 0.4) bias = `Eskalujesz zbyt chętnie: ${b.over_escalated} z ${b.benign_total} niegroźnych zdarzeń zgłosiłeś jako TP. Ćwicz szukanie potwierdzenia w kalendarzu zmian, CMDB i prevalence.`;
  return h("div", {},
    h("div", { class: "card statgrid" }, h("div", { class: "stat" }, h("b", {}, s.attempts), "ocenionych"), h("div", { class: "stat" }, h("b", {}, `${acc}%`), "trafnych werdyktów"),
      h("div", { class: "stat" }, h("b", {}, s.avg_score), "średni wynik"), h("div", { class: "stat" }, h("b", {}, `${s.avg_seconds}s`), "śr. czas")),
    bias && h("div", { class: "callout" }, bias),
    h("div", { class: "card" }, h("h3", {}, "Macierz pomyłek (wiersz: prawda, kolumna: Twój werdykt)"),
      h("table", {}, h("thead", {}, h("tr", {}, [h("th", {}, ""), ...Object.values(names).map((n) => h("th", {}, n))])),
        h("tbody", {}, Object.entries(s.confusion).map(([t, row]) => h("tr", {}, h("th", {}, names[t]), Object.keys(names).map((v) => h("td", { class: "num" }, row[v] || 0))))))),
    h("div", { class: "card" }, h("h3", {}, "Scenariusze: od najsłabszych"),
      h("table", {}, h("thead", {}, h("tr", {}, ["Scenariusz", "Kategoria", "Próby", "Trafne", "Śr. wynik", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, s.templates.map((t) => h("tr", {}, h("td", {}, t.title), h("td", { class: "muted" }, t.category), h("td", { class: "num" }, t.n), h("td", { class: "num" }, t.correct), h("td", { class: "num" }, t.avg ?? "-"),
          h("td", {}, h("button", { class: "btn small", onclick: () => { S.view = "alert"; startPractice({ template: t.id }).then(render); } }, "Ćwicz"))))))),
    h("div", { class: "card" }, h("h3", {}, "Ostatnie próby"),
      h("table", {}, h("thead", {}, h("tr", {}, ["Kiedy", "Scenariusz", "Poz.", "Prawda", "Twój", "Wynik"].map((t) => h("th", {}, t)))),
        h("tbody", {}, s.recent.map((r) => h("tr", {}, h("td", { class: "mono" }, r.ts.replace("T", " ").slice(0, 16)), h("td", {}, r.template), h("td", { class: "num" }, r.difficulty),
          h("td", {}, names[r.truth]), h("td", { class: `status-${r.outcome}` }, names[r.verdict]), h("td", { class: "num" }, r.score)))))));
}

function viewHelp() {
  const p = (...k) => h("p", {}, ...k);
  return h("div", {},
    h("div", { class: "card" }, h("h2", {}, "Jak pracować z trenerem"),
      p("Każdy alert zawiera logi z kilku źródeł (SIEM, Sysmon, Windows Security, ESET, proxy, DNS, firewall, Entra ID, M365, poczta, WAF). Zadanie: ustalić, co się stało, i zdecydować jak na zmianie."),
      h("ol", { class: "plain" },
        h("li", {}, "Przeczytaj alert i zdarzenie, które go wywołało. Zapytaj: co ta reguła faktycznie wykrywa?"),
        h("li", {}, "W logach szukaj korelacji: ten sam host, użytkownik, IP, skrót pliku w oknie ±10 minut. Kliknij wartość, żeby przefiltrować lub sprawdzić ją w TI / CMDB / kalendarzu zmian."),
        h("li", {}, "Sprawdź kontekst: Czy host i użytkownik zachowują się normalnie? Czy jest zmiana, ticket, urlop? Czy domena jest młoda i rzadka?"),
        h("li", {}, "Oznacz ★ zdarzenia, na których opierasz werdykt. Napisz uzasadnienie. Wybierz akcje."),
        h("li", {}, "Po zatwierdzeniu zobaczysz prawdziwy przebieg, listę dowodów, zmyłki i checklistę dla tego typu alertu."))),
    h("div", { class: "card" }, h("h2", {}, "Werdykty"),
      h("ul", { class: "plain" },
        h("li", {}, h("strong", {}, "TP (True Positive): "), "to realny incydent, który wymaga reakcji."),
        h("li", {}, h("strong", {}, "BTP (Benign True Positive): "), "detekcja trafnie opisała zdarzenie, ale jest ono autoryzowane lub zgodne z procedurą (skan podatności, test penetracyjny, narzędzie admina w oknie zmiany)."),
        h("li", {}, h("strong", {}, "FP (False Positive): "), "detekcja się pomyliła, zdarzenie jest zwyczajne (telemetria, agent, aktualizator)."))),
    h("div", { class: "card" }, h("h2", {}, "Punktacja (100 pkt)"),
      h("ul", { class: "plain" },
        h("li", {}, "Werdykt 50 pkt. Pomylenie BTP z FP kosztuje niewiele (oba zamykają zgłoszenie). Przeoczenie prawdziwego incydentu = zero i limit 30 pkt dla całego alertu."),
        h("li", {}, "Akcje 15 pkt: wymagane akcje i kary za szkodliwe (np. izolacja serwera przy FP)."),
        h("li", {}, "Dowody 20 pkt: ile kluczowych zdarzeń oznaczyłeś, minus kary za zmyłki."),
        h("li", {}, "Dochodzenie 15 pkt: czy sprawdziłeś to, co sprawdziłby doświadczony analityk (TI, CMDB, kalendarz zmian)."),
        h("li", {}, "Każda podpowiedź kosztuje 5 pkt."))),
    h("div", { class: "card" }, h("h2", {}, "Uwagi"),
      p("Wszystkie dane są syntetyczne: firma, użytkownicy, hosty, domeny i adresy IP (zakresy dokumentacyjne) są wymyślone. Wyniki TI i sandboxa są symulowane i nie odnoszą się do żadnych prawdziwych wskaźników."),
      p("Scenariusz jest w pełni określony tokenem w polu „seed”, więc te same dane można odtworzyć. Statystyki zapisują się lokalnie w pliku SQLite.")));
}

// ---------------------------------------------------------------------------------------------------------------
async function boot() {
  try {
    S.meta = await api("/api/meta");
    Object.assign(S.opts, store("opts") || {});
    document.getElementById("tz").textContent = `Czas lokalny: ${S.meta.tz}`;
    render();
  } catch (e) {
    document.getElementById("app").replaceChildren(errorBox(`Nie udało się połączyć z serwerem trenera: ${e.message}`));
  }
}
boot();
