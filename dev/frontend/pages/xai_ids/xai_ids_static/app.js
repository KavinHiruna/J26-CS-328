/* XAI-IDS front end */
const $ = (id) => document.getElementById(id);
const state = { meta: null, page: 1, lastQuery: null, rec: { n: 1, total: 0, incident: null } };

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (p) => (p * 100).toFixed(p >= 0.995 || p < 0.005 ? 1 : 1) + "%";
const API_BASE = (window.XAI_IDS_API || "").replace(/\/$/, "");
const dataset = () => $("sbDataset").value;

class BackendDown extends Error {}

async function api(path, params = {}, opts = {}) {
  const qs = new URLSearchParams({ ...(dataset() ? { dataset: dataset() } : {}), ...params });
  let res;
  try {
    res = await fetch(`${API_BASE}${path}?${qs}`, opts);
  } catch {
    throw new BackendDown(`Cannot reach the backend API at ${API_BASE}. Start it with: python -m backend.common.xai_ids.server`);
  }
  const body = await res.json().catch(() => ({ error: res.statusText }));
  if (!res.ok || body.error) throw new Error(body.error || res.statusText);
  return body;
}

function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 2600);
}
function banner(msg, kind = "info") {
  const b = $("banner");
  if (!msg) { b.hidden = true; return; }
  b.className = "banner " + kind; b.innerHTML = msg; b.hidden = false;
}

/* ---------- clock ---------- */
function tick() {
  const d = new Date();
  const date = d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  const time = d.toLocaleTimeString("en-GB", { hour12: false });
  $("clock").textContent = `${date}   ${time}`;
}
setInterval(tick, 1000); tick();

/* ---------- badges ---------- */
const typeBadge = (inc) => `<span class="badge ${inc.type === "Normal" ? "t-normal" : "t-attack"}" title="${esc(inc.type)}">${esc(inc.type_display)}</span>`;
const sevBadge = (s) => `<span class="badge s-${esc(s)}">${esc(s)}</span>`;
const stBadge = (s) => `<span class="badge st-${esc(s)}">${esc(s)}</span>`;
const SQLI_XAI_URL = (window.SQLI_XAI_URL || "").replace(/\/$/, "");
// SQL injection is decided by the backend from the dataset (label / request URI), not the model
const isSqli = (inc) => !!inc.is_sqli;
const sqliUrl = (inc) => `${SQLI_XAI_URL}/?incident=${encodeURIComponent(inc.incident_id)}`;
const sqliLink = (inc) => isSqli(inc) && SQLI_XAI_URL
  ? `<a class="sqli-btn" href="${esc(sqliUrl(inc))}" target="_blank" rel="noopener">🛡 SQLi XAI</a>` : "";
const idCell = (inc) => isSqli(inc) && SQLI_XAI_URL
  ? `<a class="id-link" href="${esc(sqliUrl(inc))}" target="_blank" rel="noopener" title="Open in SQLi XAI">${esc(inc.incident_id)}</a>`
  : esc(inc.incident_id);
// top bar button: opens the SQLi XAI page (with the incident open in the popup, if any)
function setTopSqli(id = null) {
  const a = $("sqliTopBtn");
  if (!SQLI_XAI_URL) { a.hidden = true; return; }
  a.href = id ? `${SQLI_XAI_URL}/?incident=${encodeURIComponent(id)}` : `${SQLI_XAI_URL}/`;
  a.title = id ? `Open incident ${id} in the SQL Injection XAI page` : "Open the SQL Injection XAI page";
}
setTopSqli();
// sidebar button: opens the SQLi XAI dashboard for the current traffic record
function setSqliDash(id = null) {
  const a = $("sqliDashBtn");
  if (!SQLI_XAI_URL) { a.hidden = true; return; }
  a.href = id ? `${SQLI_XAI_URL}/?incident=${encodeURIComponent(id)}` : `${SQLI_XAI_URL}/`;
  a.title = id ? `Open record ${id} in the SQL Injection XAI dashboard` : "Open the SQL Injection XAI dashboard";
}
setSqliDash();
const eye = `<svg viewBox="0 0 24 24"><path d="M12 5C6.5 5 2.7 9.2 1.5 12c1.2 2.8 5 7 10.5 7s9.3-4.2 10.5-7C21.3 9.2 17.5 5 12 5zm0 11.5a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9zm0-2.3a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4z"/></svg>`;

/* ---------- init ---------- */
async function loadDatasets() {
  const sel = $("sbDataset");
  if (sel.options.length) return;
  const r = await api("/api/datasets");
  sel.innerHTML = r.datasets.map((d) => `<option value="${esc(d)}">${esc(d)}</option>`).join("");
  sel.value = r.default;
}

async function loadMeta() {
  banner(`<span class="spinner"></span>Loading dataset and model… the first run trains the model and can take a few minutes for large files.`);
  try {
    await loadDatasets();
    const m = await api("/api/meta");
    state.meta = m;
    banner(m.synthetic_time
      ? `The dataset's <b>frame.time</b> column could not be parsed reliably, so records were given sequential timestamps starting ${esc(m.min_time.replace("T", " "))} (one per second, in file order). Change this in <code>config.py</code>.`
      : "");

    const fill = (sel, items, label = (x) => x, keepFirst = true) => {
      const el = $(sel); const first = keepFirst ? el.options[0].outerHTML : "";
      el.innerHTML = first + items.map((x) => `<option value="${esc(x)}">${esc(label(x))}</option>`).join("");
    };
    fill("sbType", m.attack_types, (t) => `${m.type_display[t]} (${m.counts[t].toLocaleString()})`);
    fill("fType", m.attack_types, (t) => m.type_display[t]);
    fill("fSeverity", m.severities);
    fill("fStatus", m.statuses);

    const d0 = m.min_time.slice(0, 10), d1 = m.max_time.slice(0, 10);
    $("fromDate").value = d0; $("toDate").value = d0;
    $("fromDate").min = $("toDate").min = d0; $("fromDate").max = $("toDate").max = d1;

    const mi = m.model;
    $("modelInfo").innerHTML = `
      <div><b>${m.rows.toLocaleString()}</b> records · ${m.attack_types.length} classes</div>
      <div>Model: ${esc(mi.type)} · ${mi.features} features</div>
      ${mi.holdout_accuracy != null ? `<div>Hold-out accuracy ${pct(mi.holdout_accuracy)} · macro-F1 ${pct(mi.holdout_macro_f1)}</div>` : ""}
      <div>Data: ${esc(m.min_time.slice(0, 10))} → ${esc(m.max_time.slice(0, 10))}</div>`;

    await loadRecord(1);
    await searchRange(1);
    refreshBell();
    // arriving from the SQLi XAI page's back link: /?incident=ALR-000024
    const incoming = new URLSearchParams(location.search).get("incident");
    if (incoming) {
      history.replaceState(null, "", location.pathname);   // only once, not on dataset change
      $("incidentId").value = incoming; openIncident(incoming);
    }
  } catch (e) {
    if (e instanceof BackendDown) {
      banner(`<b>Backend not reachable.</b>\n${esc(e.message)}\nRetrying every 5 seconds…`, "error");
      setTimeout(loadMeta, 5000);
    } else {
      banner(`<b>Could not load the dataset.</b>\n${esc(e.message)}`, "error");
    }
    $("tbody").innerHTML = `<tr><td colspan="8" class="empty">No data</td></tr>`;
    $("foundSub").textContent = "Dataset not loaded";
  }
}

async function refreshBell() {
  try {
    const r = await api("/api/incidents", { status: "Open", from_date: "", page: 1 });
    const n = r.total; const el = $("bellCount");
    el.textContent = n > 99 ? "99+" : n; el.hidden = n === 0;
    $("bellBtn").title = `${n.toLocaleString()} open incidents`;
  } catch { /* ignore */ }
}
$("bellBtn").onclick = () => {
  $("fStatus").value = "Open"; $("fType").value = "All"; $("fSeverity").value = "All";
  $("fromDate").value = state.meta.min_time.slice(0, 10); $("fromTime").value = "00:00";
  $("toDate").value = state.meta.max_time.slice(0, 10); $("toTime").value = "23:59";
  searchRange(1);
};

/* ---------- incident search ---------- */
function rangeParams() {
  return {
    from_date: $("fromDate").value, from_time: $("fromTime").value || "00:00",
    to_date: $("toDate").value, to_time: $("toTime").value || "23:59",
    type: $("fType").value, severity: $("fSeverity").value, status: $("fStatus").value,
  };
}

async function runSearch(params, page, subtitle) {
  state.lastQuery = { params, subtitle }; state.page = page;
  $("tbody").innerHTML = `<tr><td colspan="8" class="empty"><span class="spinner"></span>Searching…</td></tr>`;
  try {
    const r = await api("/api/incidents", { ...params, page });
    $("foundSub").innerHTML = subtitle;
    $("totalCount").textContent = r.total.toLocaleString();
    const bd = Object.entries(r.breakdown).sort((a, b) => b[1] - a[1]);
    $("breakdown").innerHTML = bd.length > 1 ? bd.map(([t, n]) =>
      `<span class="chip">${esc(state.meta.type_display[t] || t)} <b>${n.toLocaleString()}</b></span>`).join("") : "";
    if (!r.incidents.length) {
      $("tbody").innerHTML = `<tr><td colspan="8" class="empty">No incidents match these filters.</td></tr>`;
    } else {
      const off = (r.page - 1) * r.page_size;
      $("tbody").innerHTML = r.incidents.map((inc, i) => `
        <tr>
          <td>${off + i + 1}</td>
          <td class="id">${idCell(inc)}</td>
          <td title="${esc(inc.time)}">${esc(inc.time.slice(11))}</td>
          <td>${esc(inc.src_ip)}</td>
          <td>${typeBadge(inc)}</td>
          <td>${sevBadge(inc.severity)}</td>
          <td>${stBadge(inc.status)}</td>
          <td><button class="view-btn" data-id="${esc(inc.incident_id)}">${eye}View</button>${sqliLink(inc)}</td>
        </tr>`).join("");
    }
    renderPager(r);
  } catch (e) {
    $("tbody").innerHTML = `<tr><td colspan="8" class="empty">${esc(e.message)}</td></tr>`;
  }
}

function renderPager(r) {
  if (r.pages <= 1) { $("pager").innerHTML = ""; return; }
  $("pager").innerHTML = `
    <button data-p="1" ${r.page === 1 ? "disabled" : ""}>«</button>
    <button data-p="${r.page - 1}" ${r.page === 1 ? "disabled" : ""}>‹</button>
    <span>Page ${r.page.toLocaleString()} of ${r.pages.toLocaleString()}</span>
    <button data-p="${r.page + 1}" ${r.page === r.pages ? "disabled" : ""}>›</button>
    <button data-p="${r.pages}" ${r.page === r.pages ? "disabled" : ""}>»</button>`;
}
$("pager").onclick = (e) => {
  const p = e.target.closest("button")?.dataset.p;
  if (p && state.lastQuery) runSearch(state.lastQuery.params, +p, state.lastQuery.subtitle);
};

function searchRange(page = 1) {
  const p = rangeParams();
  if (!p.from_date || !p.to_date) { toast("Choose a from and to date"); return; }
  if (`${p.from_date}T${p.from_time}` > `${p.to_date}T${p.to_time}`) { toast("The start of the range is after the end"); return; }
  const sub = `Showing incidents from ${esc(p.from_date)} ${esc(p.from_time)} &rarr; ${esc(p.to_date)} ${esc(p.to_time)}`;
  runSearch(p, page, sub);
}
$("rangeForm").onsubmit = (e) => { e.preventDefault(); searchRange(1); };
$("idForm").onsubmit = (e) => {
  e.preventDefault();
  const q = $("incidentId").value.trim();
  if (!q) { searchRange(1); return; }
  runSearch({ incident_id: q }, 1, `Showing incidents matching ID “${esc(q)}”`);
};
$("tbody").onclick = (e) => {
  const id = e.target.closest(".view-btn")?.dataset.id;
  if (id) openIncident(id);
};

/* ---------- sidebar record stepper ---------- */
async function loadRecord(n) {
  try {
    const r = await api("/api/record", { type: $("sbType").value, n });
    state.rec = r;
    $("recInput").value = r.n; $("recInput").max = r.total;
    $("recN").textContent = r.n.toLocaleString(); $("recTotal").textContent = r.total.toLocaleString();
    $("recId").textContent = `${r.incident.incident_id} · ${r.incident.time}`;
    setSqliDash(r.incident.incident_id);
    setStatus("Not Analyzed");
  } catch (e) { toast(e.message); }
}
$("recPrev").onclick = () => loadRecord(Math.max(1, state.rec.n - 1));
$("recNext").onclick = () => loadRecord(Math.min(state.rec.total, state.rec.n + 1));
$("recInput").onchange = () => loadRecord(parseInt($("recInput").value, 10) || 1);
$("sbType").onchange = () => loadRecord(1);
$("sbDataset").onchange = () => { $("resultCard").hidden = true; loadMeta(); };
$("collapseBtn").onclick = () => $("layout").classList.toggle("collapsed");

function setStatus(text, cls = "") {
  const el = $("analysisStatus"); el.textContent = text; el.className = "status-pill " + cls;
}

/* ---------- analyze / explain ---------- */
function verdictHTML(inc, pred) {
  const attack = pred.is_attack;
  return `
    <div class="verdict ${attack ? "attack" : "normal"}">
      <div class="v-label">Prediction</div>
      <div class="v-main">${attack ? "⚠ " : "✓ "}${esc(state.meta?.type_display[pred.predicted] || pred.predicted)}</div>
      <div class="v-conf">${attack ? "Intrusion detected" : "Benign traffic"} · ${pct(pred.confidence)} confidence</div>
      <dl>
        <dt>Incident</dt><dd>${esc(inc.incident_id)}</dd>
        <dt>Time</dt><dd>${esc(inc.time)}</dd>
        <dt>Source → Dest</dt><dd>${esc(inc.src_ip)} → ${esc(inc.dst_ip)}</dd>
        <dt>Dataset label</dt><dd>${esc(pred.actual)} ${pred.correct ? "✓" : "✗ (mismatch)"}</dd>
        <dt>Severity</dt><dd>${sevBadge(inc.severity)}</dd>
      </dl>
    </div>`;
}
function probsHTML(pred) {
  return `<div class="sub-h">Class probabilities</div>` + pred.top.map((t) => `
    <div class="prob-row"><span>${esc(state.meta?.type_display[t.label] || t.label)}</span>
      <div class="prob-bar"><span style="width:${(t.p * 100).toFixed(1)}%"></span></div>
      <span style="text-align:right">${pct(t.p)}</span></div>`).join("");
}
function explainHTML(x) {
  const max = Math.max(...x.contributions.map((c) => Math.abs(c.contribution)), 1e-9);
  return `
    <div class="sub-h">Why the model decided this</div>
    <div class="xai-summary">${esc(x.summary)}</div>
    <div class="sub-h">Feature contributions to “${esc(x.predicted)}”</div>
    ${x.contributions.map((c) => {
      const w = (Math.abs(c.contribution) / max) * 50;
      return `<div class="contrib">
        <div class="feat" title="${esc(c.feature)} = ${esc(c.value)}">${esc(c.feature)} <small>= ${esc(c.value)}</small></div>
        <div class="axis"><span class="bar ${c.contribution >= 0 ? "pos" : "neg"}" style="width:${w}%"></span></div>
        <div class="val">${c.contribution >= 0 ? "+" : ""}${(c.contribution * 100).toFixed(1)}%</div></div>`;
    }).join("")}
    <div class="legend"><span><i style="background:#d64545"></i>pushes toward this prediction</span>
      <span><i style="background:#3a7bdc"></i>pushes away from it</span></div>
    <div class="method">Method: ${esc(x.method)}. Baseline ${pct(x.base_value)} + contributions ≈ ${pct(x.confidence)}.</div>`;
}

function showResult(r, explained) {
  $("resultSub").textContent = `Record ${state.rec.n.toLocaleString()} of ${state.rec.total.toLocaleString()} · ${r.incident.incident_id}`;
  $("resultBody").innerHTML = `
    <div class="res-grid">
      <div>${verdictHTML(r.incident, r.prediction)}
        <div class="res-actions">
          ${explained ? "" : `<button class="btn btn-light" id="resExplain">Explain prediction</button>`}
          <button class="btn btn-primary" id="resOpen">${eye} Open incident</button>
        </div></div>
      <div>${explained ? explainHTML(r.explanation) : probsHTML(r.prediction)}</div>
    </div>`;
  $("resultCard").hidden = false;
  $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
  $("resExplain")?.addEventListener("click", explainCurrent);
  $("resOpen").onclick = () => openIncident(r.incident.incident_id);
}
$("resultClose").onclick = () => ($("resultCard").hidden = true);

async function withBusy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message); setStatus("Error", "alert"); } finally { btn.disabled = false; }
}
async function analyzeCurrent() {
  await withBusy($("analyzeBtn"), async () => {
    setStatus("Analyzing…", "busy");
    const r = await api("/api/analyze", { row: state.rec.incident.row });
    setStatus(r.prediction.is_attack ? "Attack Detected" : "Normal Traffic", r.prediction.is_attack ? "alert" : "ok");
    showResult(r, false);
  });
}
async function explainCurrent() {
  await withBusy($("explainBtn"), async () => {
    setStatus("Explaining…", "busy");
    const r = await api("/api/explain", { row: state.rec.incident.row });
    setStatus("Explained", "xai");
    showResult(r, true);
  });
}
$("analyzeBtn").onclick = analyzeCurrent;
$("explainBtn").onclick = explainCurrent;

/* ---------- incident modal ---------- */
async function openIncident(id) {
  $("modalTitle").textContent = `Incident ${id}`;
  $("modalBody").innerHTML = `<span class="spinner"></span>Analyzing and explaining…`;
  $("modal").hidden = false;
  try {
    const [x, d] = await Promise.all([api("/api/explain", { incident_id: id }), api(`/api/incident/${encodeURIComponent(id)}`)]);
    const inc = x.incident;
    setTopSqli(inc.incident_id);
    const opts = state.meta.statuses.map((s) => `<option ${s === inc.status ? "selected" : ""}>${s}</option>`).join("");
    $("modalBody").innerHTML = `
      <div class="meta-row">
        <div><span class="k">Type</span>${typeBadge(inc)}</div>
        <div><span class="k">Severity</span>${sevBadge(inc.severity)}</div>
        <div class="status-edit"><span class="k">Status</span><select class="input" id="statusSel">${opts}</select>
          <button class="btn btn-primary" id="statusSave" style="height:32px;font-size:14px;padding:0 14px">Update</button></div>
        ${sqliLink(inc) ? `<div>${sqliLink(inc)}</div>` : ""}
      </div>
      <div class="res-grid">
        <div>${verdictHTML(inc, x.prediction)}<div style="margin-top:18px">${probsHTML(x.prediction)}</div></div>
        <div>${explainHTML(x.explanation)}</div>
      </div>
      <details class="raw"><summary>All ${Object.keys(d.fields).length} dataset fields</summary>
        <div class="raw-grid">${Object.entries(d.fields).map(([k, v]) => `<div><span>${esc(k)}</span><span title="${esc(v)}">${esc(v)}</span></div>`).join("")}</div>
      </details>`;
    $("statusSave").onclick = async () => {
      try {
        await api(`/api/incident/${encodeURIComponent(id)}/status`, {}, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: $("statusSel").value }),
        });
        toast(`Status of ${id} set to ${$("statusSel").value}`);
        if (state.lastQuery) runSearch(state.lastQuery.params, state.page, state.lastQuery.subtitle);
        refreshBell();
      } catch (e) { toast(e.message); }
    };
  } catch (e) {
    $("modalBody").innerHTML = `<div class="banner error">${esc(e.message)}</div>`;
  }
}
const closeModal = () => { $("modal").hidden = true; setTopSqli(); };
$("modalClose").onclick = closeModal;
$("modal").onclick = (e) => { if (e.target.id === "modal") closeModal(); };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

loadMeta();
