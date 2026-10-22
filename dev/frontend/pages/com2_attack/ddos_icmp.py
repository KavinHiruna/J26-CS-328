"""
DDoS ICMP Flood - Explainable AI dashboard (Component 2)

One incident, fully explained: search the capture, pick an incident, and see
SHAP + LIME reasons together with the Component 2 novelty layer
(explanation consensus, knowledge-grounded alignment, counterfactual,
DDoS-vs-DoS attribution and an analyst report).

Backend: dev/backend/component2_xai/DDoS_icmp
"""
from __future__ import annotations

import hashlib
import io
import re as _re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

# ---------------------------------------------------------------- backend import
_DEV_DIR = Path(__file__).resolve().parents[3]          # .../dev
_BACKEND = _DEV_DIR / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from component2_xai.DDoS_icmp import (  # noqa: E402
    ATTACK_NAME, COMPONENT2_NOVELTY, COMPONENT2_NOVELTY_TITLE, DEFAULT_MODEL_PATH, FEATURE_SPECS, MODEL_FEATURES,
    SEARCH_HELP, SPEC_BY_NAME, ExplainSettings, ModelAdapter, background_sample, benign_reference_from_scores,
    build_features, build_incident, incident_options, incident_to_json, incident_to_markdown, make_demo_dataset,
    pretty, score, search_incidents, train_model,
)
from component2_xai.DDoS_icmp.novelty import severity as _sev  # noqa: E402

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    HAS_PLOTLY = True
except Exception:  # pragma: no cover
    HAS_PLOTLY = False

# ---------------------------------------------------------------- page config
try:
    st.set_page_config(page_title="DDoS ICMP Flood XAI", page_icon="📡", layout="wide")
except Exception:
    pass  # already set by the multipage app

# ---------------------------------------------------------------- palette
C = {
    "bg": "#070d1a", "panel": "#0d1628", "panel2": "#111c33", "line": "#1d2a44", "text": "#e6edf7",
    "muted": "#8ea3c2", "icmp": "#22d3ee", "attack": "#f43f5e", "benign": "#34d399", "warn": "#f59e0b",
    "blue": "#3b82f6",
}
SEV_COLOR = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#f59e0b", "Low": "#22c55e", "None": "#64748b"}
TRUST_COLOR = {"High": C["benign"], "Medium": C["warn"], "Low": C["attack"], "n/a": "#64748b"}
STATUS_LABEL = {"column": "", "inferred": "inferred", "estimated": "est.", "unavailable": "n/a"}

CSS = f"""
<style>
:root {{
  --bg:{C['bg']}; --panel:{C['panel']}; --panel2:{C['panel2']}; --line:{C['line']}; --text:{C['text']};
  --muted:{C['muted']}; --icmp:{C['icmp']}; --attack:{C['attack']}; --benign:{C['benign']}; --warn:{C['warn']};
}}
.stApp {{
  background:
    radial-gradient(900px 480px at 85% -8%, rgba(34,211,238,.10), transparent 60%),
    radial-gradient(700px 420px at -5% 10%, rgba(244,63,94,.07), transparent 60%),
    var(--bg);
  color: var(--text);
}}
.stApp [data-testid="stMarkdownContainer"] p, .stApp label, .stApp li {{ color: var(--text); }}
.block-container {{ padding-top: 1.6rem; max-width: 1400px; }}
h1, h2, h3, h4 {{ color: var(--text) !important; letter-spacing: -.01em; }}

/* ---------- sidebar (blue, as in the shared design) ---------- */
[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, #1e40af 0%, #1d4ed8 38%, #1e3a8a 100%);
  border-right: 1px solid rgba(255,255,255,.08);
}}
[data-testid="stSidebar"] * {{ color: #ffffff; }}
[data-testid="stSidebar"] h2 {{ font-size: 1.35rem; font-weight: 800; margin: .4rem 0 .6rem; }}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {{
  background: rgba(255,255,255,.04); border: 1px dashed rgba(255,255,255,.35); border-radius: 10px;
}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button {{
  background: #1f2433 !important; border: 1px solid rgba(255,255,255,.18) !important; border-radius: 8px;
}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] small,
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{ color: rgba(255,255,255,.72) !important; }}
[data-testid="stSidebar"] [data-baseweb="select"] > div {{ background: #0b1220; border-color: rgba(255,255,255,.2); }}
[data-testid="stSidebar"] [data-baseweb="select"] span {{ color: #60a5fa !important; }}

/* ---------- hero ---------- */
.hero {{ display:flex; align-items:center; gap:22px; padding: 22px 26px; border:1px solid var(--line);
  border-radius: 18px; background: linear-gradient(120deg, rgba(34,211,238,.08), rgba(13,22,40,.9) 45%, rgba(244,63,94,.08));
  margin-bottom: 14px; }}
.pulse {{ position:relative; width:64px; height:64px; flex:0 0 64px; }}
.pulse .core {{ position:absolute; inset:24px; border-radius:50%; background: var(--icmp); box-shadow: 0 0 18px var(--icmp); }}
.pulse .ring {{ position:absolute; inset:0; border-radius:50%; border:2px solid var(--icmp); opacity:0;
  animation: ping 2.4s cubic-bezier(.2,.6,.4,1) infinite; }}
.pulse .ring:nth-child(2) {{ animation-delay: .8s; }} .pulse .ring:nth-child(3) {{ animation-delay: 1.6s; }}
@keyframes ping {{ 0% {{ transform: scale(.35); opacity:.95; }} 100% {{ transform: scale(1.15); opacity:0; }} }}
@media (prefers-reduced-motion: reduce) {{ .pulse .ring {{ animation: none; opacity:.35; }} }}
.hero h1 {{ font-size: 1.9rem; margin: 0; line-height: 1.15; }}
.hero .sub {{ color: var(--muted); margin-top: 4px; font-size: .95rem; }}
.chips {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }}
.chip {{ font-size:.76rem; padding:3px 10px; border-radius:999px; border:1px solid var(--line); color: var(--muted);
  background: rgba(255,255,255,.02); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
.chip.warn {{ border-color: rgba(245,158,11,.5); color: #fbbf24; }}
.chip.ok {{ border-color: rgba(52,211,153,.45); color: #6ee7b7; }}

/* ---------- section labels ---------- */
.eyebrow {{ text-transform: uppercase; letter-spacing: .14em; font-size: .72rem; color: var(--icmp); font-weight: 700;
  margin: 18px 0 6px; }}
.section-title {{ font-size: 1.25rem; font-weight: 750; margin: 0 0 10px; color: var(--text); }}

/* ---------- novelty ---------- */
.novelty-wrap {{ border: 1px solid rgba(34,211,238,.35); border-radius: 16px; padding: 16px 18px;
  background: linear-gradient(180deg, rgba(34,211,238,.06), rgba(13,22,40,.6)); }}
.novelty-head {{ font-weight: 800; font-size: 1.02rem; margin-bottom: 10px; }}
.novelty-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }}
.nov {{ background: var(--panel); border:1px solid var(--line); border-radius: 12px; padding: 12px 13px; }}
.nov .n {{ font-family: ui-monospace, monospace; color: var(--icmp); font-size: .75rem; }}
.nov .t {{ font-weight: 700; margin: 2px 0 4px; font-size: .92rem; }}
.nov .d {{ color: var(--muted); font-size: .82rem; line-height: 1.4; }}

/* ---------- cards / kpis ---------- */
.card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }}
.kpi {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; }}
.kpi .l {{ color: var(--muted); font-size: .76rem; text-transform: uppercase; letter-spacing: .06em; }}
.kpi .v {{ font-size: 1.55rem; font-weight: 800; margin-top: 2px; font-variant-numeric: tabular-nums; }}
.kpi .s {{ color: var(--muted); font-size: .76rem; }}
.tag {{ font-size: .66rem; padding: 1px 6px; border-radius: 6px; border:1px solid var(--line); color: var(--muted);
  margin-left: 6px; vertical-align: middle; }}

/* ---------- incident header ---------- */
.incident {{ border-radius: 16px; padding: 18px 20px; border: 1px solid var(--line); background: var(--panel2); }}
.incident.attack {{ border-color: rgba(244,63,94,.55); box-shadow: inset 4px 0 0 var(--attack); }}
.incident.benign {{ border-color: rgba(52,211,153,.45); box-shadow: inset 4px 0 0 var(--benign); }}
.incident .id {{ font-family: ui-monospace, monospace; color: var(--muted); font-size: .8rem; }}
.incident .verdict {{ font-size: 1.45rem; font-weight: 800; margin: 2px 0 6px; }}
.badge {{ display:inline-block; padding: 3px 10px; border-radius: 999px; font-weight: 700; font-size: .78rem; margin-right: 6px; }}
.flow {{ font-family: ui-monospace, monospace; font-size: .95rem; margin-top: 6px; }}
.flow .arrow {{ color: var(--icmp); padding: 0 8px; }}
.narr {{ background: var(--panel); border:1px solid var(--line); border-left: 3px solid var(--icmp); border-radius: 12px;
  padding: 14px 16px; }}
.narr p {{ margin: 0 0 .55rem 0; }}

/* ---------- search ---------- */
.search-help {{ color: var(--muted); font-size: .8rem; margin-top: -6px; }}
div[data-testid="stTextInput"] input {{ font-family: ui-monospace, monospace; }}

/* ---------- tabs ---------- */
.stTabs [data-baseweb="tab-list"] {{ gap: 4px; flex-wrap: wrap; }}
.stTabs [data-baseweb="tab"] {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px 10px 0 0;
  padding: 6px 12px; }}
.stTabs [aria-selected="true"] {{ border-color: var(--icmp) !important; }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ================================================================ helpers
def _stretch(fn, *args, **kwargs):
    """Full-width rendering across Streamlit versions (width='stretch' vs use_container_width)."""
    try:
        return fn(*args, width="stretch", **kwargs)
    except Exception:
        return fn(*args, use_container_width=True, **kwargs)


def _hash(b: bytes | None) -> str:
    return hashlib.sha1(b).hexdigest()[:16] if b else "none"


def _fmt_num(v: float, unit: str = "") -> str:
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "-"
    if abs(v) >= 1e6:
        s = f"{v / 1e6:,.2f}M"
    elif abs(v) >= 1e4:
        s = f"{v / 1e3:,.1f}k"
    elif abs(v) >= 100:
        s = f"{v:,.0f}"
    elif abs(v) >= 1:
        s = f"{v:,.2f}"
    else:
        s = f"{v:.4f}"
    return f"{s} {unit}".strip()


def kpi(label: str, value: str, sub: str = "", tag: str = "", color: str | None = None) -> str:
    t = f'<span class="tag">{tag}</span>' if tag else ""
    style = f' style="color:{color}"' if color else ""
    return f'<div class="kpi"><div class="l">{label}{t}</div><div class="v"{style}>{value}</div><div class="s">{sub}</div></div>'


def _fig_layout(fig, height=360, title=None):
    fig.update_layout(
        template="plotly_dark", height=height, title=title, margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=C["text"], size=12), legend=dict(orientation="h", y=1.08, x=0),
    )
    fig.update_xaxes(gridcolor=C["line"], zerolinecolor="#334155")
    fig.update_yaxes(gridcolor=C["line"], zerolinecolor="#334155")
    return fig


def _plot(fig):
    _stretch(st.plotly_chart, fig, config={"displaylogo": False})


# ================================================================ cached work
@st.cache_data(show_spinner=False)
def load_csv(data: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data), low_memory=False)


@st.cache_data(show_spinner=False)
def demo_raw(seed: int = 7, base_key: str = "none", _base: pd.DataFrame | None = None) -> pd.DataFrame:
    return make_demo_dataset(_base, seed=seed)


@st.cache_data(show_spinner=False)
def engineer(key: str, _raw: pd.DataFrame):
    return build_features(_raw)


@st.cache_resource(show_spinner=False)
def load_adapter(model_key: str, model_bytes: bytes | None, enc_bytes: bytes | None) -> ModelAdapter:
    if model_bytes:
        return ModelAdapter.from_bytes(model_bytes, enc_bytes)
    enc_obj = None
    if enc_bytes:
        import joblib
        enc_obj = joblib.load(io.BytesIO(enc_bytes))
    import joblib
    return ModelAdapter.from_objects(joblib.load(DEFAULT_MODEL_PATH), enc_obj)


@st.cache_resource(show_spinner=False)
def train_baseline(key: str, _features: pd.DataFrame):
    bundle, metrics = train_model(_features, n_estimators=150)
    return ModelAdapter.from_objects(bundle), bundle, metrics


@st.cache_data(show_spinner=False)
def score_cached(key: str, _features: pd.DataFrame, _adapter: ModelAdapter, attack_class):
    # probabilities do not depend on the threshold, so moving the slider never re-scores
    return score(_features, _adapter, attack_class, 0.5)


# ================================================================ sidebar
with st.sidebar:
    st.markdown("## Inputs")
    up_csv = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="icmp_csv")
    up_model = st.file_uploader("Trained DDoS ICMP model (.joblib / .pkl)", type=["joblib", "pkl"], key="icmp_model")
    up_enc = st.file_uploader("Feature encoder (.joblib, optional)", type=["joblib", "pkl"], key="icmp_enc")
    st.caption("Only load pickle files you trust - loading a pickle can run code.")

    st.markdown("## Explanation settings")
    bg_rows = st.slider("Background sample (rows)", 50, 1000, 300, 50,
                        help="Rows sampled from the dataset as the reference distribution for SHAP (Kernel / "
                             "sampling) and LIME. More rows = more stable explanations, slower.")
    do_shap = st.toggle("Compute SHAP", value=True,
                        help="TreeExplainer for tree models, KernelExplainer otherwise. "
                             "Falls back to Monte-Carlo Shapley sampling if `shap` is not installed.")
    do_lime = st.toggle("Compute LIME", value=True)
    threshold = st.slider("Decision threshold", 0.05, 0.95, 0.50, 0.01,
                          help="Attack probability at or above this value is treated as a DDoS ICMP flood.")
    top_k = st.slider("Features shown in explanations", 3, len(MODEL_FEATURES), min(10, len(MODEL_FEATURES)))
    class_slot = st.empty()   # filled once the model is known


# ================================================================ data
notices: list[tuple[str, str]] = []
model_bytes = up_model.getvalue() if up_model else None
enc_bytes = up_enc.getvalue() if up_enc else None

if up_csv is not None:
    csv_bytes = up_csv.getvalue()
    data_key = _hash(csv_bytes)
    with st.spinner("Reading CSV ..."):
        raw = load_csv(csv_bytes)
    data_label = up_csv.name
    synthetic = False
else:
    raw = demo_raw(7)
    data_key = "demo-7"
    data_label = "demo capture"
    synthetic = True
    notices.append(("warn", "No CSV uploaded - showing a demo capture with **synthetic** ICMP floods. "
                            "Upload an Edge-IIoTset CSV (e.g. `DDoS_ICMP_Flood_attack.csv`) for real results."))

with st.spinner("Engineering ICMP flood features (rates, windows, source spread) ..."):
    features, report = engineer(data_key, raw)

has_icmp_attack = report.has_labels and any("icmp" in str(k).lower() for k in report.attack_types)
if up_csv is not None and report.has_labels and not has_icmp_attack and model_bytes is None \
        and not DEFAULT_MODEL_PATH.exists():
    inject = st.toggle("This CSV has no DDoS ICMP flood rows - inject synthetic floods for a demo", value=True)
    if inject:
        raw = demo_raw(7, base_key=data_key, _base=raw)
        data_key = f"{data_key}+demo"
        synthetic = True
        features, report = engineer(data_key, raw)
        notices.append(("warn", "Synthetic ICMP flood bursts were injected into your normal capture (demo only)."))

# ================================================================ model
adapter: ModelAdapter | None = None
model_source = ""
trained_metrics = trained_bundle = None
try:
    if model_bytes:
        adapter = load_adapter(_hash(model_bytes) + _hash(enc_bytes), model_bytes, enc_bytes)
        model_source = up_model.name
    elif DEFAULT_MODEL_PATH.exists():
        adapter = load_adapter(f"default-{DEFAULT_MODEL_PATH.stat().st_mtime}{_hash(enc_bytes)}", None, enc_bytes)
        model_source = DEFAULT_MODEL_PATH.name
        if "DEMO" in str(adapter.meta.get("model_name", "")):
            notices.append(("warn", "The saved backend model is a **demo** model trained on synthetic ICMP floods."))
    elif report.has_labels and features["target"].nunique() == 2:
        with st.spinner("No model uploaded - training a baseline RandomForest on this capture ..."):
            adapter, trained_bundle, trained_metrics = train_baseline(data_key, features)
        model_source = "baseline trained in-app"
        notices.append(("info", "No model was uploaded, so a baseline RandomForest was trained on this capture. "
                                "Download it from the Report tab or upload your own model."))
except Exception as exc:
    st.error(f"Could not load the model: {exc}")
    st.stop()

if adapter is None:
    st.error("No model available. Upload a trained DDoS ICMP model, or upload a labelled Edge-IIoTset CSV "
             "(with `Attack_type`) so a baseline can be trained.")
    st.stop()

classes = adapter.classes
with class_slot:
    attack_class = st.selectbox("Class that means 'DDoS ICMP flood / attack'", classes,
                                index=classes.index(adapter.guess_attack_class()),
                                format_func=lambda c: f"{c}" if adapter.display_class(c) == str(c)
                                else f"{c} - {adapter.display_class(c)}")

missing = [f for f in adapter.feature_names if f not in features.columns]
if missing:
    notices.append(("warn", f"Model features not found in the data and set to 0: {', '.join(missing[:8])}"
                            + (" ..." if len(missing) > 8 else "")))

with st.spinner("Scoring traffic ..."):
    scored, X = score_cached(f"{data_key}|{model_source}|{_hash(model_bytes)}|{_hash(enc_bytes)}|{attack_class}",
                             features, adapter, attack_class)
    scored["is_attack"] = scored["prob"] >= threshold
    scored["verdict"] = np.where(scored["is_attack"], ATTACK_NAME, "Benign")
    scored["severity"] = [(_sev(p, pps) if a else "None")
                          for p, pps, a in zip(scored["prob"], scored["pkts_per_sec"], scored["is_attack"])]

# ================================================================ hero
chips = [f'<span class="chip">data: {data_label}</span>',
         f'<span class="chip">{len(scored):,} packets</span>',
         f'<span class="chip">model: {type(adapter.model).__name__} ({model_source})</span>',
         f'<span class="chip">threshold {threshold:.2f}</span>']
if synthetic:
    chips.append('<span class="chip warn">synthetic ICMP floods</span>')
else:
    chips.append('<span class="chip ok">real capture</span>')
st.markdown(f"""
<div class="hero">
  <div class="pulse" aria-hidden="true"><div class="ring"></div><div class="ring"></div><div class="ring"></div><div class="core"></div></div>
  <div>
    <h1>DDoS ICMP Flood &mdash; Explainable AI dashboard</h1>
    <div class="sub">Component 2 &middot; Edge-IIoTset &middot; one ICMP flood incident, explained end-to-end:
      why the model raised it, whether two explainers agree, and whether the reasons match ICMP flood knowledge.</div>
    <div class="chips">{''.join(chips)}</div>
  </div>
</div>
""", unsafe_allow_html=True)

for kind, msg in notices:
    (st.warning if kind == "warn" else st.info)(msg)

# ================================================================ novelty
nov_cards = "".join(
    f'<div class="nov"><div class="n">N{i}</div><div class="t">{n.title}</div><div class="d">{n.summary}</div></div>'
    for i, n in enumerate(COMPONENT2_NOVELTY, 1))
st.markdown(f"""<div class="novelty-wrap"><div class="novelty-head">✦ {COMPONENT2_NOVELTY_TITLE}</div>
<div class="novelty-grid">{nov_cards}</div></div>""", unsafe_allow_html=True)

# ================================================================ overview
attacks = scored[scored["is_attack"]]
k1, k2, k3, k4 = st.columns(4)
k1.markdown(kpi("Packets analysed", f"{len(scored):,}", f"{(scored['ip_proto'] == 1).mean():.1%} ICMP"),
            unsafe_allow_html=True)
k2.markdown(kpi("Flagged as ICMP flood", f"{len(attacks):,}", f"{len(attacks) / max(len(scored), 1):.1%} of packets",
                color=C["attack"] if len(attacks) else None), unsafe_allow_html=True)
k3.markdown(kpi("Targets under attack", f"{attacks['dst_ip'].nunique():,}",
                ", ".join(attacks["dst_ip"].value_counts().index[:2]) or "none"), unsafe_allow_html=True)
k4.markdown(kpi("Peak rate to a target", _fmt_num(float(scored["pkts_per_sec"].max()), "pkt/s"),
                f"window {features['window_id'].max() + 1:,} s"), unsafe_allow_html=True)

# ================================================================ search
st.markdown('<div class="eyebrow">Find an incident</div>', unsafe_allow_html=True)
st.markdown('<div class="section-title">Search incidents</div>', unsafe_allow_html=True)
q = st.text_input("Search incidents", key="icmp_search", label_visibility="collapsed",
                  placeholder="e.g.  192.168.0.128   pred:attack prob>0.9   srcs>=10   sev:critical   row:1532")
st.markdown(f'<div class="search-help">{SEARCH_HELP}</div>', unsafe_allow_html=True)

try:
    hits = search_incidents(scored, q)
except Exception as exc:
    st.error(f"Search error: {exc}")
    hits = scored
cands = incident_options(hits)
if cands.empty:
    st.info("No incidents match this search. Clear the search box to see all incidents.")
    st.stop()

show_cols = ["row_id", "src_ip", "dst_ip", "prob", "verdict", "severity", "pkts_per_sec", "unique_src_count",
             "src_concentration"] + (["attack_type"] if "attack_type" in cands else [])
st.caption(f"{len(hits):,} matching packets -> {len(cands):,} incident windows (one row per target and second, "
           "attacks first).")
_stretch(st.dataframe, cands[show_cols].head(200).rename(columns={
    "row_id": "row", "prob": "p(attack)", "pkts_per_sec": "pkt/s", "unique_src_count": "sources",
    "src_concentration": "top-src share", "attack_type": "label"}),
    hide_index=True, height=230,
    column_config={"p(attack)": st.column_config.ProgressColumn("p(attack)", min_value=0.0, max_value=1.0,
                                                                format="%.2f")})

opt_ids = cands["row_id"].astype(int).tolist()
lookup = cands.set_index("row_id")


def _fmt_opt(rid: int) -> str:
    r = lookup.loc[rid]
    return (f"#{rid}  ·  {r['src_ip']} → {r['dst_ip']}  ·  p={r['prob']:.2f}  ·  {r['severity']}  ·  "
            f"{r['pkts_per_sec']:,.0f} pkt/s")


row_id = st.selectbox("Incident to explain", opt_ids, format_func=_fmt_opt, key="icmp_incident")

# ================================================================ the incident
settings = ExplainSettings(background_rows=bg_rows, compute_shap=do_shap, compute_lime=do_lime,
                           threshold=threshold, top_k=top_k)
bg = background_sample(X, bg_rows, settings.random_state)
ref = benign_reference_from_scores(scored, X, threshold)
with st.spinner("Explaining the incident (SHAP, LIME, novelty layer) ..."):
    inc = build_incident(scored, X, adapter, int(row_id), attack_class, settings, bg, ref)

row = inc["row"]
sev = inc["severity"]
cls = "attack" if inc["is_attack"] else "benign"
truth = f' · ground truth: <b>{inc["true_label"]}</b>' if inc.get("true_label") is not None else ""

st.markdown('<div class="eyebrow">Incident XAI</div>', unsafe_allow_html=True)
h1, h2 = st.columns([1.7, 1])
with h1:
    st.markdown(f"""
<div class="incident {cls}">
  <div class="id">INCIDENT #{inc['row_id']} · window {int(row['window_id'])} · t = {row['timestamp']:.3f} s{truth}</div>
  <div class="verdict" style="color:{C['attack'] if inc['is_attack'] else C['benign']}">{inc['verdict']}</div>
  <span class="badge" style="background:{SEV_COLOR.get(sev, '#64748b')}22;color:{SEV_COLOR.get(sev, '#94a3b8')};
     border:1px solid {SEV_COLOR.get(sev, '#64748b')}">Severity: {sev}</span>
  <span class="badge" style="background:#22d3ee18;color:{C['icmp']};border:1px solid #22d3ee66">{inc['attribution']['type']}</span>
  <span class="badge" style="background:{TRUST_COLOR[inc['consensus'].get('trust', 'n/a')]}18;
     color:{TRUST_COLOR[inc['consensus'].get('trust', 'n/a')]};border:1px solid {TRUST_COLOR[inc['consensus'].get('trust', 'n/a')]}66">
     Explanation trust: {inc['consensus'].get('trust', 'n/a')}</span>
  <div class="flow">{row['src_ip']}<span class="arrow">──ICMP──▶</span>{row['dst_ip']}</div>
</div>""", unsafe_allow_html=True)
with h2:
    if HAS_PLOTLY:
        g = go.Figure(go.Indicator(
            mode="gauge+number", value=inc["probability"] * 100, number={"suffix": "%", "font": {"size": 34}},
            title={"text": "p(DDoS ICMP flood)", "font": {"size": 13, "color": C["muted"]}},
            gauge={"axis": {"range": [0, 100], "tickcolor": C["muted"]},
                   "bar": {"color": C["attack"] if inc["is_attack"] else C["benign"]},
                   "bgcolor": C["panel"], "borderwidth": 0,
                   "threshold": {"line": {"color": "#ffffff", "width": 3}, "value": threshold * 100}}))
        _plot(_fig_layout(g, height=190))
    else:
        st.metric("p(DDoS ICMP flood)", f"{inc['probability']:.1%}")


def _tag(f):
    return STATUS_LABEL.get(report.status(f), "")


cols = st.columns(6)
cards = [
    ("Packets/sec", _fmt_num(row["pkts_per_sec"]), "to target, 1 s window", _tag("pkts_per_sec")),
    ("Bytes/sec", _fmt_num(row["bytes_per_sec"], "B/s"), "traffic volume", _tag("bytes_per_sec")),
    ("Unique sources", f"{int(row['unique_src_count'])}", "in the window", _tag("unique_src_count")),
    ("Top-source share", f"{row['src_concentration']:.0%}", "packet concentration", _tag("src_concentration")),
    ("Inter-arrival", _fmt_num(row["frame_time_delta"] * 1000, "ms"), "frame.time_delta", _tag("frame_time_delta")),
    ("ICMP type / code", f"{int(row['icmp_type'])} / {int(row['icmp_code'])}" if row["ip_proto"] == 1 else "not ICMP",
     "8 = echo request, 0 = reply", _tag("icmp_type")),
]
for c, (lab, val, sub, tg) in zip(cols, cards):
    c.markdown(kpi(lab, val, sub, tg), unsafe_allow_html=True)

st.markdown('<div class="eyebrow">Analyst summary</div>', unsafe_allow_html=True)
narr_html = "".join(f"<p>{p}</p>" for p in inc["narrative"].split("\n\n"))
narr_html = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", narr_html)
st.markdown(f'<div class="narr">{narr_html}</div>', unsafe_allow_html=True)
for e in inc["errors"]:
    st.warning(e)

# ---------------------------------------------------------------- tabs
tabs = st.tabs(["SHAP", "LIME", "N1 · Consensus", "N2 · Domain alignment", "N3 · Counterfactual",
                "N4 · DDoS vs DoS", "Traffic timeline", "N5 · Report & response"])


def _attr_bar(att, k, title, conditions=False):
    items = att.top(k)[::-1]
    labels = [(att.conditions.get(f) if conditions and att.conditions.get(f) else pretty(f)) for f, _ in items]
    vals = [v for _, v in items]
    colors = [C["attack"] if v > 0 else C["icmp"] for v in vals]
    fig = go.Figure(go.Bar(x=vals, y=labels, orientation="h", marker_color=colors,
                           text=[f"{v:+.3f}" for v in vals], textposition="outside",
                           hovertemplate="%{y}<br>contribution %{x:+.4f}<extra></extra>"))
    fig.add_vline(x=0, line_color="#475569")
    return _fig_layout(fig, height=max(280, 34 * len(items) + 60), title=title)


def _value_table(att):
    rows = []
    for f, v in att.top(top_k):
        rows.append({"parameter": pretty(f), "group": SPEC_BY_NAME[f].group if f in SPEC_BY_NAME else "",
                     "value": float(row[f]) if f in row else np.nan, "contribution": v,
                     "direction": "→ attack" if v > 0 else "→ benign", "source": report.status(f)})
    return pd.DataFrame(rows)


with tabs[0]:
    att = inc["shap"]
    if att is None:
        st.info("SHAP is switched off in the sidebar.")
    else:
        st.caption(f"**{att.method}** - {att.note}  Positive (red) pushes toward *{inc['attack_class']}*, "
                   f"negative (cyan) toward benign." + (f"  Base value: {att.base_value:.3f}." if att.base_value is not None else ""))
        if HAS_PLOTLY:
            _plot(_attr_bar(att, top_k, f"Top {top_k} SHAP contributions"))
        _stretch(st.dataframe, _value_table(att), hide_index=True)

with tabs[1]:
    att = inc["lime"]
    if att is None:
        st.info("LIME is switched off in the sidebar.")
    else:
        st.caption(f"**{att.method}** - {att.note}. Bars show local surrogate weights; labels are LIME's rules.")
        if HAS_PLOTLY:
            _plot(_attr_bar(att, top_k, f"Top {top_k} LIME weights", conditions=True))
        _stretch(st.dataframe, _value_table(att), hide_index=True)

with tabs[2]:
    cs = inc["consensus"]
    if not cs.get("available"):
        st.info(cs.get("reason"))
    else:
        a, b, c_, d = st.columns(4)
        a.markdown(kpi("Consensus score", f"{cs['score']:.0%}", f"{cs['trust']} trust",
                       color=TRUST_COLOR[cs["trust"]]), unsafe_allow_html=True)
        b.markdown(kpi(f"Top-{cs['k']} overlap", f"{cs['jaccard']:.0%}", "Jaccard of feature sets"),
                   unsafe_allow_html=True)
        c_.markdown(kpi("Direction agreement", f"{cs['sign_agreement']:.0%}", "same sign on shared features"),
                    unsafe_allow_html=True)
        d.markdown(kpi("Rank correlation", "-" if cs["rank_correlation"] is None else f"{cs['rank_correlation']:+.2f}",
                       "Spearman on |importance|"), unsafe_allow_html=True)
        st.caption("Score = 0.5 × overlap + 0.3 × direction agreement + 0.2 × rank agreement. "
                   "High ≥ 70 %, Medium ≥ 45 %. A low score means the two explainers tell different stories - "
                   "treat the explanation with care.")
        if HAS_PLOTLY:
            t = cs["table"].copy()
            t["shap_n"] = t["shap"] / (t["shap"].abs().max() or 1)
            t["lime_n"] = t["lime"] / (t["lime"].abs().max() or 1)
            t = t.reindex(t["shap_n"].abs().sort_values().index)
            fig = go.Figure()
            fig.add_bar(y=t["label"], x=t["shap_n"], orientation="h", name="SHAP (normalised)", marker_color=C["blue"])
            fig.add_bar(y=t["label"], x=t["lime_n"], orientation="h", name="LIME (normalised)", marker_color=C["warn"])
            fig.update_layout(barmode="group")
            _plot(_fig_layout(fig, height=max(300, 40 * len(t) + 60), title="SHAP vs LIME on the same incident"))
        if cs["shared_features"]:
            st.markdown("**Both explainers agree these drive the decision:** "
                        + ", ".join(f"`{pretty(f)}`" for f in cs["shared_features"]))

with tabs[3]:
    ka = inc["alignment"]
    if ka is None:
        st.info("Enable SHAP or LIME to check the explanation against ICMP flood domain knowledge.")
    else:
        a, b = st.columns(2)
        a.markdown(kpi("Knowledge-grounded alignment", f"{ka['alignment_score']:.0%}", ka["verdict"],
                       color=C["benign"] if ka["alignment_score"] >= .7 else C["warn"] if ka["alignment_score"] >= .4
                       else C["attack"]), unsafe_allow_html=True)
        b.markdown(kpi("Domain evidence present", f"{ka['evidence_score']:.0%}",
                       "weighted share of ICMP flood indicators that fired"), unsafe_allow_html=True)
        rules = ka["rules"].copy()
        rules["fired"] = rules["fired"].map({True: "✅ yes", False: "— no"})
        rules["contribution"] = rules["contribution"].map(lambda v: "-" if v is None else f"{v:+.4f}")
        _stretch(st.dataframe, rules[["rule", "indicator", "label", "value", "fired", "contribution", "status"]]
                 .rename(columns={"label": "parameter"}), hide_index=True)
        st.caption(f"Contributions from {inc['primary'].method}. Rules and thresholds come from the ICMP flood "
                   "parameter study and live in `backend/component2_xai/DDoS_icmp/config.py` (DOMAIN_RULES).")

with tabs[4]:
    cf = inc["counterfactual"]
    st.markdown(f"**{cf['message']}**")
    if cf.get("steps"):
        steps = pd.DataFrame(cf["steps"])
        if HAS_PLOTLY:
            ys = [cf["start_prob"]] + steps["prob_after"].tolist()
            xs = ["incident"] + [f"set {s}" for s in steps["label"]]
            fig = go.Figure(go.Scatter(x=xs, y=ys, mode="lines+markers+text", text=[f"{y:.2f}" for y in ys],
                                       textposition="top center", line=dict(color=C["icmp"], width=3),
                                       marker=dict(size=10, color=[C["attack"] if y >= threshold else C["benign"]
                                                                   for y in ys])))
            fig.add_hline(y=threshold, line_dash="dash", line_color=C["warn"],
                          annotation_text=f"threshold {threshold:.2f}")
            fig.update_yaxes(range=[0, 1.05], title="p(attack)")
            _plot(_fig_layout(fig, height=330, title="Greedy path to a benign decision"))
        steps["from"] = steps["from"].map(lambda v: f"{v:.4g}")
        steps["to"] = steps["to"].map(lambda v: f"{v:.4g}")
        _stretch(st.dataframe, steps[["label", "from", "to", "prob_after"]].rename(
            columns={"label": "parameter", "from": "incident value", "to": "benign value", "prob_after": "p(attack) after"}),
            hide_index=True)
        st.caption("Each step resets one parameter to the median of traffic the model calls benign and keeps the "
                   "change that lowers the attack probability most.")

with tabs[5]:
    at = inc["attribution"]
    a, b, c_ = st.columns(3)
    a.markdown(kpi("Attribution", at["type"].split(" (")[0], at["type"], color=C["icmp"]), unsafe_allow_html=True)
    b.markdown(kpi("Distinct sources", f"{at['unique_sources']}", f"{at['window_packets']:,} packets in window"),
               unsafe_allow_html=True)
    c_.markdown(kpi("Source entropy", f"{at['normalised_entropy']:.0%}", "1.0 = perfectly spread"),
                unsafe_allow_html=True)
    ts = at["top_sources"]
    if HAS_PLOTLY and len(ts):
        fig = go.Figure(go.Bar(x=ts["share"], y=ts["src_ip"], orientation="h", marker_color=C["icmp"],
                               text=[f"{s:.1%}" for s in ts["share"]], textposition="outside"))
        fig.update_yaxes(autorange="reversed")
        _plot(_fig_layout(fig, height=max(240, 30 * len(ts) + 60),
                          title=f"Top sources hitting {row['dst_ip']} in this window"))
    st.caption("Distributed (DDoS) when ≥ 3 sources and no source carries more than 60 % of the packets; "
               "otherwise a single/few-source (DoS) flood. This decides whether blocking IPs can work.")

with tabs[6]:
    tl = inc["timeline"]
    if HAS_PLOTLY and len(tl):
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        fig.add_trace(go.Scatter(x=tl["seconds_from_incident"], y=tl["pkts_per_sec"], name="pkt/s to target",
                                 fill="tozeroy", line=dict(color=C["icmp"])), secondary_y=False)
        fig.add_trace(go.Scatter(x=tl["seconds_from_incident"], y=tl["attack_prob"], name="mean p(attack)",
                                 line=dict(color=C["attack"], dash="dot")), secondary_y=True)
        fig.add_vline(x=0, line_color="#ffffff", line_dash="dash", annotation_text="incident")
        fig.update_xaxes(title="seconds relative to incident")
        fig.update_yaxes(title_text="packets / s", secondary_y=False)
        fig.update_yaxes(title_text="p(attack)", range=[0, 1.05], secondary_y=True)
        _plot(_fig_layout(fig, height=360, title=f"Traffic to {row['dst_ip']} (±30 s)"))
    _stretch(st.dataframe, tl, hide_index=True, height=220)

with tabs[7]:
    st.markdown("**Recommended response**")
    for i, s in enumerate(inc["mitigation"], 1):
        st.markdown(f"{i}. {s}")
    d1, d2, d3 = st.columns(3)
    d1.download_button("⬇ Incident report (JSON)", incident_to_json(inc), f"icmp_incident_{inc['row_id']}.json",
                       "application/json")
    d2.download_button("⬇ Incident report (Markdown)", incident_to_markdown(inc), f"icmp_incident_{inc['row_id']}.md",
                       "text/markdown")
    if trained_bundle is not None:
        import joblib
        buf = io.BytesIO()
        joblib.dump(trained_bundle, buf)
        d3.download_button("⬇ Baseline model (.joblib)", buf.getvalue(), "ddos_icmp_model.joblib",
                           "application/octet-stream")
    with st.expander("Model details"):
        st.json(adapter.describe())
        if trained_metrics:
            st.json({k: v for k, v in trained_metrics.items() if k != "feature_importance"})

# ================================================================ provenance
with st.expander("ICMP flood parameters used by the model (from the parameter study)"):
    prov = pd.DataFrame([{
        "group": s.group, "parameter": s.parameter, "feature": s.name,
        "why important for ICMP flood": s.why,
        "model input": "yes" if s.model_input else "context only",
        "how obtained": report.status(s.name) if s.model_input else "column",
        "incident value": (f"{float(row[s.name]):.4g}" if s.model_input else str(row[s.name])),
    } for s in FEATURE_SPECS])
    _stretch(st.dataframe, prov, hide_index=True)
    st.caption("inferred = derived from other Edge-IIoTset columns (e.g. ip.proto from icmp.* fields, rates from "
               "1 s windows); est. = estimated (frame.len is not exported by Edge-IIoTset); n/a = not in the CSV. "
               "Source/Destination IP are incident context only, so the model cannot memorise lab addresses.")
    for n in report.notes:
        st.caption("• " + n)
