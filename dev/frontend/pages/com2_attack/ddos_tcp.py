"""
DDoS TCP SYN Flood — Explainable AI dashboard (Component 2, Edge-IIoTset), Network Flood UI.

Same architecture as ddos_icmp.py (DDoS Network Flood: TCP SYN · UDP · ICMP): both pages share one layout and differ only
in the PAGE block below and their backend package (DDoS_tcp / DDoS_icmp). Tabs:
Incident XAI · Live Detection (Network Flood view + devices) · Packet Explanation ·
★ XAI Consensus (Component-2 novelty) · Global Explainability · Model Performance.
Device / sensor details come from backend/component2_xai/edge_devices.py.

Location : dev/frontend/pages/com2_attack/ddos_tcp.py
Backend  : dev/backend/component2_xai/DDoS_tcp

Run standalone:   python -m streamlit run frontend/pages/com2_attack/ddos_tcp.py --server.port 8512   (from dev/)
XAI IDS link    : the IDS dashboard opens this page as  ?incident=<ID>  (e.g. linked from the XAI IDS);
                  "← Back to XAI IDS" returns to XAI_IDS_URL (default http://127.0.0.1:5000).
"""
from __future__ import annotations

import copy
import json
import os
import sys
from io import BytesIO
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# --------------------------------------------------------------------------- #
# Backend import (dev/frontend/pages/com2_attack/ddos_tcp.py -> dev/backend)
# --------------------------------------------------------------------------- #
DEV_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = DEV_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from component2_xai.DDoS_tcp import DDoSTcpXAI, ModelNotTrainedError  # noqa: E402
from component2_xai.DDoS_tcp import config as ddos_cfg                  # noqa: E402
from component2_xai.DDoS_tcp.data_loader import repair_shifted           # noqa: E402
from component2_xai import edge_devices as devices                       # noqa: E402

# --------------------------------------------------------------------------- #
# Theme — keep every colour/style decision here so it can be aligned with the
# SQLi XAI page in one place.
# --------------------------------------------------------------------------- #
THEME = {
    "bg": "#0b1020",
    "panel": "#121a2f",
    "panel_border": "#1f2b4a",
    "text": "#e6ecff",
    "muted": "#8a96b8",
    "accent": "#4cc9f0",
    "attack": "#ff4d6d",
    "normal": "#2ec4b6",
    "warn": "#ffb703",
    "font": "Inter, 'Segoe UI', sans-serif",
    "mono": "'JetBrains Mono', Consolas, monospace",
    "sidebar_top": "#1e6fe8",
    "sidebar_bottom": "#0d47a1",
    "sidebar_text": "#ffffff",
}
ATTACK, NORMAL = ddos_cfg.CLASS_NAMES[1], ddos_cfg.CLASS_NAMES[0]

# --------------------------------------------------------------------------- #
# PAGE — what this dashboard detects (everything else is shared with the sister page)
# --------------------------------------------------------------------------- #
FLOOD = ddos_cfg.CLASS_NAMES[1]                    # e.g. "DDoS ICMP Flood"
FLOOD_PROTO = ddos_cfg.FLOOD_PROTOCOL              # short name: "TCP SYN", "network", ...
FLOOD_SET = list(getattr(ddos_cfg, "FLOOD_PROTOCOLS", [FLOOD_PROTO]))   # protocol() values of its packets
FLOOD_SHORT = f"{FLOOD_PROTO} flood"
PAGE_ICON = "⚡"
HERO_TEXT = ("Detects TCP SYN floods (many spoofed sources open half-open connections to one target) in IIoT "
             "traffic and explains every verdict: which packet features drove the decision, how many SYNs the "
             "target could still answer with SYN-ACK, which devices and sensors are affected, and whether "
             "independent XAI methods agree.")
CLASS_COLORS = {ATTACK: THEME["attack"], NORMAL: THEME["normal"]}


def inject_styles() -> None:
    t = THEME
    st.markdown(f"""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;600&display=swap');
      .stApp {{ background: radial-gradient(1200px 600px at 10% -10%, #16224a 0%, {t['bg']} 55%); color:{t['text']}; font-family:{t['font']}; }}
      /* sidebar — same blue gradient as the SQL Injection XAI page */
      [data-testid="stSidebar"] {{ background:linear-gradient(180deg,{t['sidebar_top']} 0%,{t['sidebar_bottom']} 100%); }}
      [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3,
      [data-testid="stSidebar"] label, [data-testid="stSidebar"] p, [data-testid="stSidebar"] span,
      [data-testid="stSidebar"] small {{ color:{t['sidebar_text']} !important; }}
      [data-testid="stSidebar"] [data-baseweb="select"] *, [data-testid="stSidebar"] input {{ color:{t['sidebar_bottom']} !important; }}
      [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {{ background:rgba(255,255,255,.08);
          border:1px dashed rgba(255,255,255,.35); }}
      [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button span {{ color:{t['sidebar_bottom']} !important; }}
      h1, h2, h3, h4 {{ color:{t['text']}; font-family:{t['font']}; letter-spacing:-0.01em; }}
      .xai-hero {{ padding:22px 26px; border-radius:16px; margin-bottom:18px;
                  background:linear-gradient(135deg, rgba(255,77,109,.18), rgba(76,201,240,.10));
                  border:1px solid {t['panel_border']}; }}
      .xai-hero h1 {{ margin:0; font-size:2rem; font-weight:800; }}
      .xai-hero p {{ margin:6px 0 0; color:{t['muted']}; }}
      .xai-badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:.72rem; font-weight:600;
                   margin-right:6px; border:1px solid {t['panel_border']}; background:{t['panel']}; color:{t['accent']}; }}
      .xai-card {{ background:{t['panel']}; border:1px solid {t['panel_border']}; border-radius:14px; padding:16px 18px; height:100%; }}
      .xai-card .label {{ color:{t['muted']}; font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; }}
      .xai-card .value {{ font-size:1.7rem; font-weight:800; margin-top:4px; font-family:{t['mono']}; }}
      .xai-card .sub {{ color:{t['muted']}; font-size:.8rem; margin-top:2px; }}
      .xai-verdict {{ border-radius:14px; padding:18px 20px; border:1px solid {t['panel_border']}; }}
      .xai-verdict.attack {{ background:rgba(255,77,109,.12); border-color:{t['attack']}; }}
      .xai-verdict.normal {{ background:rgba(46,196,182,.12); border-color:{t['normal']}; }}
      .xai-verdict .title {{ font-size:1.35rem; font-weight:800; }}
      .xai-section {{ font-size:1.05rem; font-weight:700; margin:14px 0 6px; color:{t['text']};
                     border-left:3px solid {t['accent']}; padding-left:10px; }}
      .xai-path {{ font-family:{t['mono']}; font-size:.85rem; background:{t['panel']}; border:1px solid {t['panel_border']};
                  border-radius:10px; padding:12px 14px; line-height:1.9; }}
      .stTabs [data-baseweb="tab-list"] {{ gap:6px; }}
      .stTabs [data-baseweb="tab"] {{ background:{t['panel']}; border-radius:10px 10px 0 0; padding:8px 16px; }}
      .stTabs [aria-selected="true"] {{ border-bottom:2px solid {t['accent']} !important; }}
      div[data-testid="stDataFrame"] {{ border:1px solid {t['panel_border']}; border-radius:10px; }}
      .xai-novelty {{ padding:20px 24px; border-radius:16px; margin:4px 0 16px; border:1px solid {t['accent']};
                     background:linear-gradient(135deg, rgba(76,201,240,.14), rgba(255,77,109,.10)); }}
      .xai-novelty .tag {{ color:{t['warn']}; font-size:.75rem; font-weight:800; letter-spacing:.12em; }}
      .xai-novelty h3 {{ margin:4px 0 6px; font-weight:800; }}
      .xai-novelty p {{ color:{t['muted']}; margin:0 0 10px; line-height:1.55; }}
      .xai-novelty .chips span {{ display:inline-block; padding:4px 10px; margin:0 6px 6px 0; border-radius:999px;
                                 background:{t['panel']}; border:1px solid {t['panel_border']}; font-size:.8rem; }}
      .xai-novelty .formula {{ font-family:{t['mono']}; font-size:.82rem; background:{t['panel']};
                              border:1px solid {t['panel_border']}; border-radius:10px; padding:10px 12px; margin-top:4px; }}
    </style>
    """, unsafe_allow_html=True)


def style_fig(fig: go.Figure, height: int = 380, legend: bool = True) -> go.Figure:
    t = THEME
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=t["font"], color=t["text"], size=12),
        showlegend=legend, legend=dict(orientation="h", y=1.08, x=0, bgcolor="rgba(0,0,0,0)"),
        title_font=dict(size=14),
    )
    fig.update_xaxes(gridcolor=t["panel_border"], zerolinecolor=t["panel_border"])
    fig.update_yaxes(gridcolor=t["panel_border"], zerolinecolor=t["panel_border"])
    return fig


def card(label: str, value: str, sub: str = "", color: str | None = None) -> None:
    style = f"color:{color};" if color else ""
    st.markdown(f"""<div class="xai-card"><div class="label">{label}</div>
        <div class="value" style="{style}">{value}</div><div class="sub">{sub}</div></div>""",
                unsafe_allow_html=True)


def section(title: str) -> None:
    st.markdown(f'<div class="xai-section">{title}</div>', unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Data / model loading
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner=f"Loading {FLOOD} model…")
def load_xai() -> DDoSTcpXAI:
    return DDoSTcpXAI()


@st.cache_data(show_spinner="Loading dataset…")
def read_csv(source: str | bytes, name: str) -> pd.DataFrame:
    """Read a CSV from a path or uploaded bytes once and cache it."""
    return repair_shifted(pd.read_csv(BytesIO(source) if isinstance(source, bytes) else source, low_memory=False, dtype=str))


def load_artifact(upload):
    """joblib/pickle artifact from the sidebar (joblib also reads plain pickles)."""
    return joblib.load(BytesIO(upload.getvalue()))


def configure_xai(base: DDoSTcpXAI, model, encoder, data: pd.DataFrame, bg_size: int,
                  use_shap: bool, attack_class) -> DDoSTcpXAI:
    """Per-session copy of the cached service with the sidebar's model/settings applied."""
    xai = copy.copy(base)
    for cached in ("global_consensus", "_normal_baseline"):
        xai.__dict__.pop(cached, None)          # depend on model / encoder
    xai.model, xai.encoder = model, encoder
    xai.use_shap, xai.attack_class = use_shap, attack_class
    xai._shap_explainer = None
    # Background rows for LIME: real rows from the selected dataset, like the SQLi page.
    sample = data.sample(min(bg_size, len(data)), random_state=ddos_cfg.RANDOM_STATE)
    xai.background = xai.encode(sample).reset_index(drop=True)
    return xai


@st.cache_data(show_spinner="Scoring packets…", max_entries=8)
def score(_xai: DDoSTcpXAI, _raw: pd.DataFrame, key: tuple) -> pd.DataFrame:
    """Cached per (data, model, settings, threshold) so widget reruns don't re-score big files."""
    return _xai.predict(_raw)


# --------------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------------- #
FLOOD_PROTOCOLS = ["TCP SYN", "UDP", "ICMP"]
PROTO_COLORS = {"TCP SYN": "#ff4d6d", "UDP": "#ffb703", "ICMP": "#c77dff", "TCP": "#4cc9f0", "other": "#8a96b8"}


def network_flood_view(raw: pd.DataFrame, scored: pd.DataFrame, secs: pd.Series, ind: dict) -> None:
    """Spec 'Network Flood UI': live packets/s, SYN vs SYN-ACK ratio, top source IPs, protocol breakdown."""
    section("Network flood view — packets per second, SYN vs SYN-ACK, sources and protocols")
    proto = scored["protocol"]
    flagged = scored["is_attack"]
    src = raw["ip.src_host"].astype(str) if "ip.src_host" in raw.columns else pd.Series("", index=raw.index)
    synack = (raw["tcp.connection.synack"].astype(str).str.startswith("1") if "tcp.connection.synack" in raw.columns
              else pd.Series(False, index=raw.index))
    minute = (secs // 60) * 60
    no_time = int((flagged & secs.isna()).sum())

    left, right = st.columns([1.6, 1])
    with left:
        f = pd.DataFrame({"minute": minute[flagged], "protocol": proto[flagged]}).dropna()
        pps = f.groupby(["minute", "protocol"]).size().div(60).rename("pps").reset_index()
        total = minute.dropna().value_counts().sort_index().div(60)
        fig = go.Figure()
        for p in [x for x in FLOOD_PROTOCOLS + ["TCP", "other"] if x in set(pps["protocol"])]:
            d = pps[pps["protocol"] == p].sort_values("minute")
            fig.add_trace(go.Scatter(x=d["minute"].map(lambda m: _hhmmss(m)[:5]), y=d["pps"], mode="lines",
                                     stackgroup="flagged", name=f"flagged {p}", line=dict(width=0.5, color=PROTO_COLORS[p])))
        fig.add_trace(go.Scatter(x=[_hhmmss(m)[:5] for m in total.index], y=total.values, mode="lines",
                                 name="all traffic", line=dict(color=THEME["muted"], width=1, dash="dot")))
        fig.update_layout(title="Live packets per second (per-minute average)", xaxis_title="time of day",
                          yaxis_title="packets / s")
        st.plotly_chart(style_fig(fig, 340), width="stretch")
        if no_time:
            st.caption(f"{no_time:,} flagged packets have no timestamp (the export shifted those rows — "
                       "mostly the UDP flood); they are counted in the breakdowns but not in this chart.")
    with right:
        sa = pd.DataFrame({"minute": minute, "SYN": proto == "TCP SYN", "SYN-ACK": synack}).dropna()
        per = sa.groupby("minute")[["SYN", "SYN-ACK"]].sum()
        per = per[(per["SYN"] > 0) | (per["SYN-ACK"] > 0)]
        fig = go.Figure()
        for name, color in (("SYN", PROTO_COLORS["TCP SYN"]), ("SYN-ACK", THEME["normal"])):
            fig.add_trace(go.Scatter(x=[_hhmmss(m)[:5] for m in per.index], y=per[name], mode="lines", name=name,
                                     line=dict(color=color, width=2)))
        ratio = ind["syn_synack_ratio"]
        fig.update_layout(title=f"SYN vs SYN-ACK per minute (overall ratio {ratio:.1f} : 1)"
                          if np.isfinite(ratio) else "SYN vs SYN-ACK per minute", xaxis_title="time of day",
                          yaxis_title="packets / minute")
        st.plotly_chart(style_fig(fig, 340), width="stretch")
        st.caption("A healthy server answers most SYNs with a SYN-ACK; many SYNs without SYN-ACKs means "
                   "half-open connections piling up (SYN flood).")

    left, right = st.columns([1, 1])
    with left:
        top = src[flagged].value_counts().head(8).index
        d = pd.DataFrame({"src": src[flagged], "protocol": proto[flagged]})
        d = d[d["src"].isin(top)].groupby(["src", "protocol"]).size().rename("packets").reset_index()
        fig = px.bar(d, x="packets", y="src", color="protocol", orientation="h", color_discrete_map=PROTO_COLORS,
                     category_orders={"src": list(top)}, title="Top source IPs (flagged packets)")
        st.plotly_chart(style_fig(fig, 340), width="stretch")
        st.caption(f"{ind['distinct_sources_flagged']:,} distinct sources; the busiest sends "
                   f"{ind['source_concentration']:.1%} of flagged packets — spoofed floods spread over many sources.")
    with right:
        order = [p for p in FLOOD_PROTOCOLS + ["TCP", "other"] if p in set(proto)]
        b = pd.DataFrame({"protocol": order,
                          "all traffic": [int((proto == p).sum()) for p in order],
                          "flagged": [int((proto[flagged] == p).sum()) for p in order]}).melt(
            id_vars="protocol", var_name="set", value_name="packets")
        fig = px.bar(b, x="packets", y="protocol", color="set", barmode="group", orientation="h", text="packets",
                     color_discrete_map={"all traffic": THEME["normal"], "flagged": THEME["attack"]},
                     category_orders={"protocol": order}, title="Protocol breakdown")
        fig.update_traces(texttemplate="%{text:,}", textposition="outside", cliponaxis=False)
        st.plotly_chart(style_fig(fig, 340), width="stretch")


def flood_targets(raw: pd.DataFrame, scored: pd.DataFrame) -> pd.Series:
    """Victim of each packet: its destination, or its source when a known device is replying to a stranger."""
    src = raw["ip.src_host"].astype(str).str.strip() if "ip.src_host" in raw.columns else pd.Series("", index=raw.index)
    dst = raw["ip.dst_host"].astype(str).str.strip() if "ip.dst_host" in raw.columns else pd.Series("", index=raw.index)
    known = set(devices.inventory()["ip"]) if len(devices.inventory()) else set()
    reply = src.isin(known) & ~dst.isin(known)
    return dst.where(~reply, src)


def devices_under_attack(raw: pd.DataFrame, scored: pd.DataFrame) -> None:
    """Which Edge-IIoT devices / sensors the flagged traffic hits (device inventory from edge_devices.py)."""
    section("Devices & sensors under attack")
    flagged = scored["is_attack"]
    if not flagged.any():
        st.info("No packets are flagged at the current threshold.")
    else:
        src = raw["ip.src_host"].astype(str) if "ip.src_host" in raw.columns else pd.Series("", index=raw.index)
        tgt = flood_targets(raw, scored)
        g = (pd.DataFrame({"target": tgt[flagged], "src": src[flagged]})
             .groupby("target").agg(flagged_packets=("src", "size"), distinct_sources=("src", "nunique"))
             .sort_values("flagged_packets", ascending=False).head(8).reset_index())
        info = [devices.describe(ip) for ip in g["target"]]
        g["device"] = [d["device"] for d in info]
        g["layer / role"] = [d["role"] for d in info]
        g["sensors at risk"] = [", ".join(d["dependent_sensors"]) or "—" for d in info]
        top = info[0]
        st.markdown(f'<div class="xai-card"><div class="label">MOST ATTACKED DEVICE</div>'
                    f'<div class="value" style="color:{THEME["attack"]};font-size:1.25rem">{top["ip"]} — '
                    f'{top["device"].split(" · ")[0]}</div>'
                    f'<div class="sub">{top["protocols"] or top["role"]}'
                    + (f' · telemetry of <b>{", ".join(top["dependent_sensors"])}</b> passes through it — a flood can '
                       f'delay or drop those sensor readings' if top["dependent_sensors"] else "")
                    + "</div></div>", unsafe_allow_html=True)
        st.dataframe(g[["target", "device", "layer / role", "flagged_packets", "distinct_sources", "sensors at risk"]],
                     width="stretch", hide_index=True)
    with st.expander("Edge-IIoTset device / sensor inventory (learned from the per-sensor captures)"):
        st.dataframe(devices.inventory(), width="stretch", hide_index=True)


def device_context(ctx: dict) -> None:
    """Device cards for one incident: who is attacked, who (claims to) send it."""
    section("Device & sensor context")
    tgt = devices.describe(ctx.get("target", ctx["dst"]))
    src = devices.describe(ctx["peer"] if ctx.get("flood") else ctx["src"])
    c1, c2 = st.columns(2)
    with c1:
        card("Target device", tgt["device"].split(" · ")[0], f"{tgt['ip']} · {tgt['role']}",
             THEME["attack"] if tgt["known"] else None)
        if tgt["dependent_sensors"]:
            st.caption("Sensors whose MQTT telemetry goes through this device: **"
                       + ", ".join(tgt["dependent_sensors"]) + "**")
    with c2:
        card("Source", src["device"].split(" · ")[0], f"{src['ip']}" + (f" · {src['role']}" if src["known"] else ""))


def tab_detection(xai: DDoSTcpXAI, raw: pd.DataFrame, scored: pd.DataFrame, data_key: tuple) -> None:
    ind = xai.flood_indicators(raw, scored)
    fb = ind["flagged_by_protocol"]
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        card("Packets analysed", f"{ind['packets']:,}")
    with c2:
        card(f"Flagged as {FLOOD_SHORT}", f"{ind['flagged']:,}", f"{ind['flagged_ratio']:.1%} of traffic", THEME["attack"])
    with c3:
        card("Flagged by protocol", " · ".join(f"{fb.get(p, 0):,}" for p in FLOOD_PROTOCOLS),
             " · ".join(FLOOD_PROTOCOLS))
    with c4:
        r = ind["syn_synack_ratio"]
        card("SYN : SYN-ACK", f"{r:.1f} : 1" if np.isfinite(r) else "∞",
             f"{ind['syn']:,} SYN · {ind['synack']:,} SYN-ACK", THEME["attack"] if r > 3 else THEME["normal"])
    with c5:
        acc = None
        if "actual" in scored.columns:
            acc = (scored["prediction"] == scored["actual"]).mean()
        card("Agreement with labels", f"{acc:.1%}" if acc is not None else "—",
             "dataset labels present" if acc is not None else "no labels in file", THEME["normal"])

    network_flood_view(raw, scored, seconds_of_day(raw, data_key), ind)
    devices_under_attack(raw, scored)

    section("Model verdicts")
    left, right = st.columns([1, 2])
    with left:
        level = ind["flagged_ratio"] * 100
        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=level, number={"suffix": "%"},
            title={"text": "Threat level (share of flagged packets)"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": THEME["attack"]},
                   "steps": [{"range": [0, 10], "color": "rgba(46,196,182,.25)"},
                             {"range": [10, 40], "color": "rgba(255,183,3,.25)"},
                             {"range": [40, 100], "color": "rgba(255,77,109,.25)"}]}))
        st.plotly_chart(style_fig(gauge, 300, legend=False), use_container_width=True)
    with right:
        tl = scored.reset_index(drop=True)
        tl["packet"] = np.arange(len(tl))
        tl["rolling"] = tl["attack_probability"].rolling(max(5, len(tl) // 100), min_periods=1).mean()
        fig = go.Figure()
        fig.add_trace(go.Scattergl(x=tl["packet"], y=tl["attack_probability"], mode="markers",
                                   marker=dict(size=4, color=tl["attack_probability"],
                                               colorscale=[[0, THEME["normal"]], [1, THEME["attack"]]]),
                                   name="packet"))
        fig.add_trace(go.Scatter(x=tl["packet"], y=tl["rolling"], mode="lines",
                                 line=dict(color=THEME["accent"], width=2), name="rolling mean"))
        fig.add_hline(y=xai.threshold, line_dash="dash", line_color=THEME["warn"],
                      annotation_text="threshold")
        fig.update_layout(title="Attack probability per packet", xaxis_title="packet #",
                          yaxis_title=f"P({FLOOD_SHORT})", yaxis_range=[0, 1.02])
        st.plotly_chart(style_fig(fig, 300), use_container_width=True)

    c1, c3 = st.columns(2)
    with c1:
        fig = px.histogram(scored, x="attack_probability", color="prediction", nbins=40,
                           color_discrete_map=CLASS_COLORS, title="Probability distribution")
        st.plotly_chart(style_fig(fig, 320), use_container_width=True)
    with c3:
        # Bars, not a donut: one level usually dominates and tiny slices' labels collide.
        levels = ["Low", "Elevated", "High", "Critical"]
        mix = scored["risk_level"].value_counts().reindex(levels).fillna(0).astype(int)
        share = mix / max(int(mix.sum()), 1)
        fig = go.Figure(go.Bar(
            x=mix.values, y=levels, orientation="h",
            marker=dict(color=[THEME["normal"], THEME["accent"], THEME["warn"], THEME["attack"]],
                        cornerradius=4),
            text=[f"{n:,} · {s:.1%}" for n, s in zip(mix.values, share)], textposition="outside",
            textfont=dict(color=THEME["text"]), cliponaxis=False,
            customdata=share, hovertemplate="%{y}: %{x:,} packets (%{customdata:.2%})<extra></extra>"))
        fig.update_layout(title="Risk levels", xaxis_title="packets",
                          xaxis_range=[0, mix.max() * 1.35 or 1], bargap=0.35)
        fig.update_yaxes(autorange="reversed", showgrid=False)
        st.plotly_chart(style_fig(fig, 320, legend=False), use_container_width=True)

    section("Packet verdicts")
    only_flagged = st.toggle("Show flagged packets only", value=False, key="tcp_only_flagged")
    view = scored[scored["is_attack"]] if only_flagged else scored
    view = view.sort_values("attack_probability", ascending=False)
    st.dataframe(
        view.drop(columns=["is_attack"]),
        use_container_width=True, height=360,
        column_config={"attack_probability": st.column_config.ProgressColumn(
            f"P({FLOOD_SHORT})", min_value=0.0, max_value=1.0, format="%.3f")},
    )
    st.download_button("Download verdicts (CSV)", view.to_csv().encode(), "ddos_tcp_verdicts.csv", "text/csv")


def waterfall(exp: dict) -> go.Figure:
    contribs = exp["contributions"][::-1]
    labels = [f"{c['feature']} = {c['value']}" for c in contribs]
    values = [c["contribution"] for c in contribs]
    if abs(exp["other_contribution"]) > 1e-6:
        labels = ["other features"] + labels
        values = [exp["other_contribution"]] + values
    fig = go.Figure(go.Waterfall(
        orientation="h", base=exp["base_value"], y=labels, x=values,
        measure=["relative"] * len(values),
        increasing=dict(marker=dict(color=THEME["attack"])),
        decreasing=dict(marker=dict(color=THEME["normal"])),
        connector=dict(line=dict(color=THEME["panel_border"])),
        text=[f"{v:+.3f}" for v in values], textposition="outside",
    ))
    fig.add_vline(x=exp["base_value"], line_dash="dot", line_color=THEME["muted"],
                  annotation_text=f"base {exp['base_value']:.2f}")
    fig.add_vline(x=exp["probability"], line_dash="dash", line_color=THEME["warn"],
                  annotation_text=f"output {exp['probability']:.2f}")
    fig.update_layout(title=f"{exp['method']} — contribution to P({FLOOD_SHORT})", xaxis_title="probability")
    return fig


def tab_local(xai: DDoSTcpXAI, raw: pd.DataFrame, scored: pd.DataFrame, top_k: int,
              use_lime: bool = True) -> None:
    # Long lists freeze the browser; the highest-risk packets are the ones worth explaining.
    MAX_PICK = 2_000
    order = scored.sort_values("attack_probability", ascending=False).index[:MAX_PICK].tolist()
    inc_col = next((c for c in ("Incident ID", "Incident_ID") if c in raw.columns), None)

    def label(i):
        r = scored.loc[i]
        inc = f" · {raw.at[i, inc_col]}" if inc_col else ""
        src = f" · {r['ip.src_host']}" if "ip.src_host" in scored.columns else ""
        return f"#{i}{inc} · {r['prediction']} · p={r['attack_probability']:.3f}{src}"

    attribution = "SHAP" if xai.capabilities["attribution_method"].startswith("SHAP") else "Tree-path"
    methods = [attribution] + (["LIME"] if use_lime else []) + ["Surrogate rule"]
    c1, c2 = st.columns([3, 1])
    with c1:
        idx = st.selectbox("Packet to explain (sorted by attack probability)", order,
                           format_func=label, key="tcp_packet")
        if len(scored) > MAX_PICK:
            st.caption(f"Showing the {MAX_PICK:,} highest-probability packets of {len(scored):,}.")
    with c2:
        method = st.radio("Explainer", methods, key="tcp_method",
                          help="Turn SHAP / LIME on or off in the sidebar's Explanation settings.")
    row = raw.loc[[idx]]
    exp = xai.explain(row, top_k=top_k)
    is_att = exp["prediction"] == ATTACK
    actual = scored.loc[idx, "actual"] if "actual" in scored.columns else None

    v1, v2 = st.columns([1, 2])
    with v1:
        st.markdown(f"""<div class="xai-verdict {'attack' if is_att else 'normal'}">
            <div class="label" style="color:{THEME['muted']}">VERDICT</div>
            <div class="title" style="color:{THEME['attack'] if is_att else THEME['normal']}">
              {'🚨 ' if is_att else '✅ '}{exp['prediction']}</div>
            <div style="font-family:{THEME['mono']};font-size:1.5rem;margin-top:6px">{exp['probability']:.1%}</div>
            <div style="color:{THEME['muted']};font-size:.85rem">attack probability · threshold {xai.threshold:.2f}</div>
            {f"<div style='margin-top:8px;font-size:.85rem'>Dataset label: <b>{actual}</b></div>" if actual else ""}
            </div>""", unsafe_allow_html=True)
        section("Why?")
        st.markdown(exp["narrative"])
    with v2:
        if method == attribution:
            st.plotly_chart(style_fig(waterfall(exp), 460, legend=False), use_container_width=True)
        elif method == "LIME":
            if not xai.capabilities["lime"]:
                st.warning("LIME is not installed in this environment — `pip install lime`.")
            else:
                with st.spinner("Fitting LIME local surrogate…"):
                    lime = xai.explain_lime(row, num_features=top_k)
                w = pd.DataFrame(lime["weights"])[::-1]
                fig = go.Figure(go.Bar(x=w["weight"], y=w["rule"], orientation="h",
                                       marker_color=[THEME["attack"] if v > 0 else THEME["normal"] for v in w["weight"]]))
                fig.update_layout(title=f"LIME — local rule weights towards {FLOOD_SHORT}")
                st.plotly_chart(style_fig(fig, 460, legend=False), use_container_width=True)
        else:
            section("Global surrogate decision path for this packet")
            fid = xai.global_xai["surrogate"]["fidelity"]
            st.caption(f"Depth-{xai.global_xai['surrogate']['max_depth']} decision tree that mimics the "
                       f"Random Forest with {fid:.1%} fidelity.")
            st.markdown('<div class="xai-path">' + "<br>".join(xai.surrogate_path(row)) + "</div>",
                        unsafe_allow_html=True)

    section("Feature values vs. typical traffic")
    tbl = pd.DataFrame([{
        "feature": c["feature"], "meaning": c["description"], "this packet": c["value"],
        "typical normal": xai.encoder.decode_value(c["feature"], c["normal_median"]),
        f"typical {FLOOD_SHORT}": xai.encoder.decode_value(c["feature"], c["attack_median"]),
        "contribution": c["contribution"],
    } for c in exp["contributions"]])
    st.dataframe(tbl, use_container_width=True, hide_index=True,
                 column_config={"contribution": st.column_config.NumberColumn(format="%+.4f")})
    with st.expander("Raw packet fields"):
        st.dataframe(row.T.rename(columns={idx: "value"}), use_container_width=True)


def tab_global(xai: DDoSTcpXAI, top_k: int) -> None:
    g = xai.global_xai
    fi = pd.DataFrame(g["feature_importance"])
    st.caption(f"Global attributions computed with **{g['attribution_method']}** on "
               f"{len(xai.shap_sample['y'])} held-out packets.")

    c1, c2 = st.columns(2)
    with c1:
        top = fi.head(top_k)[::-1]
        fig = go.Figure(go.Bar(x=top["mean_abs_attribution"], y=top["feature"], orientation="h",
                               marker_color=THEME["accent"],
                               hovertext=top["description"]))
        fig.update_layout(title="Mean |attribution| — overall feature impact", xaxis_title="mean |contribution|")
        st.plotly_chart(style_fig(fig, 440, legend=False), use_container_width=True)
    with c2:
        s = xai.shap_sample
        feats = fi.head(top_k)["feature"].tolist()
        rows = []
        for f in feats:
            j = list(s["X"].columns).index(f)
            x = s["X"][f].to_numpy()
            rng = (x.max() - x.min()) or 1.0
            rows.append(pd.DataFrame({"feature": f, "attribution": s["values"][:, j],
                                      "feature value (scaled)": (x - x.min()) / rng}))
        bees = pd.concat(rows)
        fig = go.Figure()
        for f in feats:
            part = bees[bees["feature"] == f]
            jitter = np.random.default_rng(0).uniform(-0.3, 0.3, len(part))
            fig.add_trace(go.Scattergl(
                x=part["attribution"], y=feats.index(f) + jitter, mode="markers", showlegend=False,
                marker=dict(size=5, color=part["feature value (scaled)"], cmin=0, cmax=1,
                            colorscale=[[0, THEME["accent"]], [1, THEME["attack"]]],
                            colorbar=dict(title="value", thickness=10) if f == feats[0] else None,
                            showscale=f == feats[0]),
                hovertemplate=f"{f}<br>attribution=%{{x:.3f}}<extra></extra>"))
        fig.update_yaxes(tickvals=list(range(len(feats))), ticktext=feats, autorange="reversed")
        fig.add_vline(x=0, line_color=THEME["muted"])
        fig.update_layout(title="Attribution beeswarm (each dot = one packet; colour = feature value)",
                          xaxis_title=f"contribution to P({FLOOD_SHORT})")
        st.plotly_chart(style_fig(fig, 440, legend=False), use_container_width=True)

    section("Do the importance methods agree?")
    comp = fi.head(top_k).copy()
    for col in ["mean_abs_attribution", "gini_importance", "permutation_importance"]:
        m = comp[col].abs().max() or 1.0
        comp[col] = comp[col] / m
    comp = comp.melt(id_vars="feature", value_vars=["mean_abs_attribution", "gini_importance",
                                                    "permutation_importance"],
                     var_name="method", value_name="normalised importance")
    comp["method"] = comp["method"].map({"mean_abs_attribution": g["attribution_method"],
                                         "gini_importance": "Gini (impurity)",
                                         "permutation_importance": "Permutation (F1 drop)"})
    fig = px.bar(comp, x="feature", y="normalised importance", color="method", barmode="group",
                 color_discrete_sequence=[THEME["accent"], THEME["warn"], THEME["attack"]])
    st.plotly_chart(style_fig(fig, 360), use_container_width=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        section("Dependence plot")
        f = st.selectbox("Feature", fi["feature"].tolist(), key="tcp_dep_feature")
        s = xai.shap_sample
        j = list(s["X"].columns).index(f)
        dep = pd.DataFrame({"value": s["X"][f], "attribution": s["values"][:, j],
                            "class": np.where(s["y"] == 1, ATTACK, NORMAL)})
        fig = px.scatter(dep, x="value", y="attribution", color="class", color_discrete_map=CLASS_COLORS,
                         title=f"How {f} moves the prediction")
        if f in xai.encoder.vocab:
            inv = {v: k for k, v in xai.encoder.vocab[f].items()}
            ticks = sorted(dep["value"].unique())
            fig.update_xaxes(tickvals=ticks, ticktext=[inv.get(int(t), "?") for t in ticks])
        st.plotly_chart(style_fig(fig, 360), use_container_width=True)
    with c2:
        section("Global surrogate rules")
        sur = g["surrogate"]
        st.caption(f"A depth-{sur['max_depth']} decision tree reproduces the Random Forest's decisions "
                   f"with **{sur['fidelity']:.1%} fidelity** — a readable summary of what the model learned.")
        rules = pd.DataFrame([{"IF": " AND ".join(r["conditions"]) or "(always)",
                               "THEN": r["prediction"], "confidence": r["confidence"],
                               "packets": r["support"]} for r in sur["rules"]])
        st.dataframe(rules, use_container_width=True, hide_index=True, height=320,
                     column_config={"confidence": st.column_config.ProgressColumn(
                         "confidence", min_value=0.0, max_value=1.0, format="%.2f")})


def tab_performance(xai: DDoSTcpXAI) -> None:
    m = xai.metrics
    cols = st.columns(6)
    for col, (lab, key) in zip(cols, [("Accuracy", "accuracy"), ("Precision", "precision"),
                                      ("Recall", "recall"), ("F1-score", "f1"),
                                      ("ROC-AUC", "roc_auc"), ("False-positive rate", "false_positive_rate")]):
        with col:
            card(lab, f"{m[key]:.4f}" if key != "false_positive_rate" else f"{m[key]:.2%}")

    c1, c2, c3 = st.columns(3)
    with c1:
        cm = np.array(m["confusion_matrix"])
        fig = go.Figure(go.Heatmap(z=cm, x=[f"Pred {c}" for c in ddos_cfg.CLASS_NAMES],
                                   y=[f"True {c}" for c in ddos_cfg.CLASS_NAMES],
                                   text=cm, texttemplate="%{text:,}", showscale=False,
                                   colorscale=[[0, THEME["panel"]], [1, THEME["accent"]]]))
        fig.update_yaxes(autorange="reversed")
        fig.update_layout(title="Confusion matrix (test set)")
        st.plotly_chart(style_fig(fig, 340, legend=False), use_container_width=True)
    with c2:
        fig = go.Figure(go.Scatter(x=m["roc_curve"]["fpr"], y=m["roc_curve"]["tpr"], mode="lines",
                                   line=dict(color=THEME["attack"], width=3), fill="tozeroy",
                                   name=f"AUC {m['roc_auc']:.4f}"))
        fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", line=dict(dash="dot", color=THEME["muted"]),
                                 name="chance"))
        fig.update_layout(title="ROC curve", xaxis_title="False-positive rate", yaxis_title="True-positive rate")
        st.plotly_chart(style_fig(fig, 340), use_container_width=True)
    with c3:
        fig = go.Figure(go.Scatter(x=m["pr_curve"]["recall"], y=m["pr_curve"]["precision"], mode="lines",
                                   line=dict(color=THEME["accent"], width=3), name=f"AP {m['pr_auc']:.4f}"))
        fig.update_layout(title="Precision–recall curve", xaxis_title="Recall", yaxis_title="Precision",
                          yaxis_range=[0, 1.02])
        st.plotly_chart(style_fig(fig, 340), use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        section("Classification report")
        rep = pd.DataFrame(m["classification_report"]).T
        st.dataframe(rep.style.format("{:.4f}"), use_container_width=True)
    with c2:
        section("Training data")
        cc = m["class_counts"]
        fig = go.Figure(go.Pie(labels=list(cc.keys()), values=list(cc.values()), hole=.55,
                               marker=dict(colors=[CLASS_COLORS.get(k, THEME["accent"]) for k in cc])))
        st.plotly_chart(style_fig(fig, 260), use_container_width=True)
        st.caption(f"Trained {m['trained_at']} · {m['n_train']:,} train / {m['n_test']:,} test packets · "
                   f"fit {m['fit_seconds']}s · {m['inference_ms_per_packet']} ms/packet")

    with st.expander("Model & preprocessing details"):
        st.json({"model": m["model"], "params": m["params"], "features_used": m["features"],
                 "categorical_features": m["categorical_features"],
                 "dropped_columns (Edge-IIoTset paper + identifiers)": m["dropped_columns"],
                 "dropped_constant_columns": m["dropped_constant_columns"],
                 "data_sources": m["source_counts"]})


# --------------------------------------------------------------------------- #
# NOVELTY — Multi-method XAI Consensus
# --------------------------------------------------------------------------- #
TRUST_COLORS = {"High": THEME["normal"], "Medium": THEME["warn"], "Low": THEME["attack"]}
COMPONENT_LABELS = {"rank": "Rank agreement (ρ→[0,1])",
                    "topk": "Top-k feature overlap",
                    "direction": "Direction agreement"}


def novelty_banner(xai: DDoSTcpXAI) -> None:
    labels = xai.method_labels
    lime_state = "" if xai.capabilities["lime"] else " (install <code>lime</code> to enable)"
    w = ddos_cfg.CONSENSUS_WEIGHTS
    st.markdown(f"""<div class="xai-novelty">
      <div class="tag">★ NOVELTY · COMPONENT 2</div>
      <h3>Multi-method XAI Consensus</h3>
      <p>Different XAI methods often disagree about <i>why</i> a packet was flagged, and a single
      explanation gives the analyst no way to know whether it can be trusted. This component explains
      every packet with <b>four independent methods</b> and measures how much they agree, producing an
      <b>XAI Consensus Score (XCS)</b> and a trust level for each verdict. Low-consensus verdicts are
      routed to analyst review instead of automated mitigation.</p>
      <div class="chips">
        <span>A · {labels['rf_attribution']}</span><span>B · LIME{lime_state}</span>
        <span>C · Occlusion (normal-baseline substitution)</span><span>D · Global surrogate tree</span>
      </div>
      <div class="formula">XCS = {w['rank']:.2f}·Rank + {w['topk']:.2f}·Top-k overlap + {w['direction']:.2f}·Direction
        + {w['verdict']:.2f}·Verdict &nbsp;→&nbsp; High ≥ {ddos_cfg.CONSENSUS_HIGH:.2f} · Medium ≥ {ddos_cfg.CONSENSUS_MEDIUM:.2f} · Low</div>
    </div>""", unsafe_allow_html=True)


def tab_consensus(xai: DDoSTcpXAI, raw: pd.DataFrame, scored: pd.DataFrame, use_lime: bool = True) -> None:
    novelty_banner(xai)
    labels = xai.method_labels

    # ---------------- A. packet-level consensus ------------------------------
    section("A · Packet-level consensus")
    order = scored.sort_values("attack_probability", ascending=False).index[:2_000].tolist()
    idx = st.selectbox("Packet (2,000 highest attack probability)", order, key="tcp_cons_packet",
                       format_func=lambda i: f"#{i} · {scored.loc[i, 'prediction']} · "
                                             f"p={scored.loc[i, 'attack_probability']:.3f}")
    with st.spinner("Explaining with every method and measuring agreement…"):
        cons = xai.consensus(raw.loc[[idx]], use_lime=use_lime)
    tcol = TRUST_COLORS[cons["trust"]]

    c1, c2, c3 = st.columns([1.1, 1.4, 1.2])
    with c1:
        g = go.Figure(go.Indicator(
            mode="gauge+number", value=cons["score"], number={"valueformat": ".2f"},
            title={"text": "XAI Consensus Score"},
            gauge={"axis": {"range": [0, 1]}, "bar": {"color": tcol},
                   "steps": [{"range": [0, ddos_cfg.CONSENSUS_MEDIUM], "color": "rgba(255,77,109,.20)"},
                             {"range": [ddos_cfg.CONSENSUS_MEDIUM, ddos_cfg.CONSENSUS_HIGH], "color": "rgba(255,183,3,.20)"},
                             {"range": [ddos_cfg.CONSENSUS_HIGH, 1], "color": "rgba(46,196,182,.20)"}]}))
        st.plotly_chart(style_fig(g, 250, legend=False), use_container_width=True)
        st.markdown(f"""<div class="xai-verdict" style="border-color:{tcol};background:rgba(0,0,0,.15)">
            <div class="label" style="color:{THEME['muted']}">TRUST LEVEL</div>
            <div class="title" style="color:{tcol}">{cons['trust']} consensus</div>
            <div style="font-size:.88rem;margin-top:6px">{cons['recommendation']}</div></div>""",
                    unsafe_allow_html=True)
    with c2:
        comp = cons["components"]
        fig = go.Figure(go.Bar(
            x=[comp[k] for k in COMPONENT_LABELS], y=list(COMPONENT_LABELS.values()), orientation="h",
            marker_color=[TRUST_COLORS["High"] if comp[k] >= ddos_cfg.CONSENSUS_HIGH else
                          TRUST_COLORS["Medium"] if comp[k] >= ddos_cfg.CONSENSUS_MEDIUM else
                          TRUST_COLORS["Low"] for k in COMPONENT_LABELS],
            text=[f"{comp[k]:.2f}" for k in COMPONENT_LABELS], textposition="outside"))
        fig.update_layout(title="Agreement components", xaxis_range=[0, 1.15])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(style_fig(fig, 250, legend=False), use_container_width=True)
        st.caption(f"Methods compared: {', '.join(labels[m] for m in cons['methods'])}")
    with c3:
        section("Verdict per method")
        for name, v in cons["verdicts"].items():
            col = THEME["attack"] if v else THEME["normal"]
            agree = "✔" if v == cons["verdicts"]["Random Forest"] else "✘"
            st.markdown(f"""<div class="xai-card" style="padding:10px 14px;margin-bottom:8px">
                <span class="label">{name}</span>
                <span style="float:right;color:{col};font-weight:700">{ATTACK if v else NORMAL} {agree}</span>
                </div>""", unsafe_allow_html=True)
        st.caption(f"Random Forest P({FLOOD_SHORT}) = {cons['probability']:.3f}")

    rank = pd.DataFrame(cons["ranking"])
    if not rank.empty:
        c1, c2 = st.columns([1.3, 1])
        with c1:
            feats = rank["feature"].tolist()
            z = np.array([[rank.loc[rank["feature"] == f, m].iloc[0] for f in feats] for m in cons["methods"]])
            fig = go.Figure(go.Heatmap(
                z=z, x=feats, y=[labels[m] for m in cons["methods"]], zmid=0, zmin=-1, zmax=1,
                colorscale=[[0, THEME["normal"]], [0.5, THEME["panel"]], [1, THEME["attack"]]],
                text=np.round(z, 2), texttemplate="%{text}", colorbar=dict(title="→ flood", thickness=10)))
            fig.update_layout(title=f"Normalised attribution per method (red → {FLOOD_SHORT}, teal → Normal)")
            st.plotly_chart(style_fig(fig, 330, legend=False), use_container_width=True)
        with c2:
            section("Consensus explanation")
            tbl = rank[["feature", "value", "direction", "consensus_importance"]].copy()
            tbl["support"] = rank["methods_supporting"].astype(str) + "/" + rank["methods_total"].astype(str)
            st.dataframe(tbl, use_container_width=True, hide_index=True, height=300,
                         column_config={"consensus_importance": st.column_config.ProgressColumn(
                             "importance", min_value=0.0, max_value=1.0, format="%.2f")})
        if cons["pairs"]:
            with st.expander("Pairwise method agreement for this packet"):
                st.dataframe(pd.DataFrame([{"method pair": " vs ".join(labels[m] for m in k.split("|")),
                                            "Spearman ρ": v["spearman"], "top-k overlap": v["overlap"]}
                                           for k, v in cons["pairs"].items()]),
                             use_container_width=True, hide_index=True)

    # ---------------- B. traffic triage --------------------------------------
    section("B · Consensus-based triage of flagged traffic")
    flagged = scored[scored["is_attack"]].sort_values("attack_probability", ascending=False)
    if flagged.empty:
        st.info("No packets are flagged at the current threshold.")
    else:
        sel = flagged.index[: ddos_cfg.CONSENSUS_TRIAGE_MAX]
        with st.spinner(f"Scoring consensus for {len(sel):,} flagged packets…"):
            tri = xai.batch_consensus(raw.loc[sel])
        st.caption(f"Fast consensus (methods A, C, D) on the {len(sel):,} most suspicious flagged packets.")
        counts = tri["trust"].value_counts()
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            card("Mean XCS", f"{tri['xcs'].mean():.2f}")
        for col, lvl, sub in [(k2, "High", "auto-mitigation safe"), (k3, "Medium", "corroborate"),
                              (k4, "Low", "analyst review")]:
            with col:
                card(f"{lvl} consensus", f"{int(counts.get(lvl, 0)):,}", sub, TRUST_COLORS[lvl])
        c1, c2 = st.columns(2)
        with c1:
            fig = px.histogram(tri, x="xcs", color="trust", nbins=25, color_discrete_map=TRUST_COLORS,
                               title="XCS distribution of flagged packets")
            st.plotly_chart(style_fig(fig, 320), use_container_width=True)
        with c2:
            fig = px.scatter(tri, x="attack_probability", y="xcs", color="trust",
                             color_discrete_map=TRUST_COLORS,
                             title="Model confidence vs. explanation consensus")
            fig.add_hline(y=ddos_cfg.CONSENSUS_MEDIUM, line_dash="dash", line_color=THEME["muted"])
            st.plotly_chart(style_fig(fig, 320), use_container_width=True)
        review = tri[tri["trust"] == "Low"].join(scored.drop(columns=["attack_probability", "prediction"]))
        st.markdown(f"**Escalated for analyst review:** {len(review):,} packets")
        if not review.empty:
            st.dataframe(review.drop(columns=[c for c in review.columns if c.startswith(("pair_", "is_attack"))]),
                         use_container_width=True, height=260)

    # ---------------- C. global study ----------------------------------------
    section("C · Does consensus reveal unreliable predictions? (held-out test packets)")
    gc = xai.global_consensus
    wrong = gc[~gc["correct"]]
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        card("Packets studied", f"{len(gc):,}")
    with k2:
        card("Mean XCS · correct", f"{gc.loc[gc['correct'], 'xcs'].mean():.2f}", "", THEME["normal"])
    with k3:
        card("Mean XCS · misclassified", f"{wrong['xcs'].mean():.2f}" if len(wrong) else "—",
             f"{len(wrong)} errors", THEME["attack"])
    with k4:
        auc = None
        if 0 < len(wrong) < len(gc):
            from sklearn.metrics import roc_auc_score
            auc = roc_auc_score(~gc["correct"], 1 - gc["xcs"])
        card("Error-detection AUROC", f"{auc:.3f}" if auc is not None else "—",
             "low XCS → model error" if auc is not None else "needs ≥1 error")
    c1, c2 = st.columns(2)
    with c1:
        gc_plot = gc.assign(outcome=np.where(gc["correct"], "correct", "misclassified"))
        fig = px.box(gc_plot, x="actual", y="xcs", color="outcome", points="all",
                     color_discrete_map={"correct": THEME["normal"], "misclassified": THEME["attack"]},
                     title="XCS by true class and prediction outcome")
        st.plotly_chart(style_fig(fig, 340), use_container_width=True)
    with c2:
        pair_cols = [c for c in gc.columns if c.startswith("pair_")]
        methods = sorted({m for c in pair_cols for m in c[5:].split("|")})
        mat = pd.DataFrame(np.eye(len(methods)), index=methods, columns=methods)
        for c in pair_cols:
            a, b = c[5:].split("|")
            mat.loc[a, b] = mat.loc[b, a] = gc[c].mean()
        names = [labels[m] for m in methods]
        fig = go.Figure(go.Heatmap(z=mat.values, x=names, y=names, zmin=-1, zmax=1,
                                   colorscale=[[0, THEME["attack"]], [0.5, THEME["panel"]], [1, THEME["normal"]]],
                                   text=np.round(mat.values, 2), texttemplate="%{text}", showscale=False))
        fig.update_layout(title="Mean method-to-method rank agreement (Spearman ρ)")
        st.plotly_chart(style_fig(fig, 340, legend=False), use_container_width=True)


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Incident XAI — one incident explained end-to-end (mirrors the SQLi XAI page)
# --------------------------------------------------------------------------- #
IDS_URL = os.environ.get("XAI_IDS_URL", "http://127.0.0.1:5000").rstrip("/")
FLOOD_WINDOW_S = 60          # ± seconds of traffic around the incident used as flood context
PRIORITY_COLORS = {"Critical": THEME["attack"], "High": THEME["warn"], "Medium": THEME["accent"], "Low": THEME["normal"]}


def incident_col(raw: pd.DataFrame) -> str | None:
    return next((c for c in ("Incident ID", "Incident_ID") if c in raw.columns), None)


@st.cache_data(show_spinner=False, max_entries=4)
def seconds_of_day(_raw: pd.DataFrame, key: tuple) -> pd.Series:
    """frame.time -> seconds since midnight (Edge-IIoTset exports drop the date part)."""
    if "frame.time" not in _raw.columns:
        return pd.Series(np.nan, index=_raw.index)
    hms = _raw["frame.time"].astype(str).str.extract(r"(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)")
    return hms[0].astype(float) * 3600 + hms[1].astype(float) * 60 + hms[2].astype(float)


def flood_context(raw: pd.DataFrame, scored: pd.DataFrame, secs: pd.Series, idx) -> dict:
    """Traffic around one incident: is its target being hit by many sources at a flood-like rate?

    A network DDoS is many (often spoofed) sources -> one target over one protocol, so the evidence
    is the packet rate to the target, how many distinct sources send it and how concentrated they
    are; for a TCP SYN flood also how few SYNs the target answers with SYN-ACK.
    """
    def col(name):
        return raw[name].astype(str).str.strip() if name in raw.columns else pd.Series("", index=raw.index)

    src, dst, proto = col("ip.src_host"), col("ip.dst_host"), scored["protocol"]
    p = proto[idx]
    base = {"src": src[idx], "dst": dst[idx], "protocol": p, "time": secs[idx],
            "src_flagged": float(scored.loc[src == src[idx], "is_attack"].mean())}
    if p not in FLOOD_PROTOCOLS:
        return {**base, "flood": False, "series": pd.DataFrame()}
    same = proto == p
    synack = col("tcp.connection.synack").str.startswith("1")
    # the target is the endpoint of this packet that receives the most traffic of this protocol (handles replies)
    received = dst[same].value_counts()
    target = src[idx] if received.get(src[idx], 0) > received.get(dst[idx], 0) else dst[idx]
    direction = "reply from target" if src[idx] == target else "packet to target"
    to_t = same & (dst == target)
    from_t = (src == target) & (same | synack if p == "TCP SYN" else same)
    t0 = secs[idx]
    timed = pd.notna(t0)
    near = ((secs - t0).abs() <= FLOOD_WINDOW_S) if timed else pd.Series(True, index=raw.index)
    win_to = to_t & near
    win_src = src[win_to].value_counts()
    peer = dst[idx] if src[idx] == target else src[idx]
    return {
        **base, "flood": True, "timed": timed, "target": target, "direction": direction, "peer": peer,
        "to_target": int(to_t.sum()), "from_target": int(from_t.sum()),
        "sources_to_target": int(src[to_t].nunique()),
        "peer_packets": int((to_t & (src == peer)).sum()),
        "window_to_target": int(win_to.sum()),
        "window_rate_s": float(win_to.sum()) / (2 * FLOOD_WINDOW_S) if timed else None,
        "window_sources": int(len(win_src)),
        "window_concentration": float(win_src.iloc[0] / win_to.sum()) if win_to.any() else 0.0,
        "window_flagged": float(scored.loc[win_to, "is_attack"].mean()) if win_to.any() else 0.0,
        "window_synack": int((near & (src == target) & synack).sum()) if p == "TCP SYN" else None,
        "series": pd.DataFrame({"t": secs[to_t | from_t], "src": src[to_t | from_t],
                                "kind": np.where(to_t[to_t | from_t], "to target", "from target")}),
    }


def incident_priority(p: float, is_attack: bool, trust: str) -> tuple[str, str]:
    """Analyst priority from model confidence + explanation consensus (as on the SQLi page)."""
    if not is_attack:
        return "Low", ""
    if p >= 0.8 and trust == "High":
        return "Critical", ""
    if p >= 0.8:
        return "High", "The model is confident but the XAI methods disagree — confirm with the traffic context before blocking."
    return "Medium", "Borderline score — corroborate with the target's packet rate and source spread before acting."


def _a(word: str) -> str:
    """English article: 'an ICMP', 'a TCP SYN', 'a UDP'."""
    return ("an " if word[:1].upper() in "AEIO" else "a ") + word   # "a UDP" (you-sound), "an ICMP"


def _hhmmss(s: float) -> str:
    return "—" if pd.isna(s) else f"{int(s // 3600):02d}:{int(s % 3600 // 60):02d}:{s % 60:06.3f}"


def tab_incident(xai: DDoSTcpXAI, raw: pd.DataFrame, scored: pd.DataFrame, top_k: int,
                 use_lime: bool, data_key: tuple) -> None:
    id_col = incident_col(raw)
    if not id_col:
        st.error("No Incident ID column found (expected 'Incident ID' or 'Incident_ID').")
        return

    # --- the IDS opens this page as ?incident=ALR-000024 -> select it once
    incoming = st.query_params.get("incident", "").strip()
    if incoming and st.session_state.get("_tcp_applied_incident") != incoming:
        st.session_state["_tcp_applied_incident"] = incoming
        st.session_state["tcp_incident_select"] = incoming

    # --- filter toggle, search box, incident dropdown
    only_flood = st.toggle(f"Show only {' · '.join(FLOOD_SET)} packets", True, key="tcp_only_flood_proto",
                           help=f"Fast pre-filter to find interesting incidents (a {FLOOD_SHORT} is made of "
                                f"{' / '.join(FLOOD_SET)} packets). It is not a classifier.")
    view = scored[scored["protocol"].isin(FLOOD_SET)] if only_flood else scored
    view = view.sort_values("attack_probability", ascending=False)
    search = st.text_input("Search Incident ID (optional)", key="tcp_incident_search",
                           placeholder="e.g. ALR-035871")
    ids = raw.loc[view.index, id_col].astype(str)
    if search:
        ids = ids[ids.str.contains(search.strip(), case=False, regex=False)]
    options = ids.drop_duplicates().head(5000).tolist()
    all_ids = raw[id_col].astype(str)
    # the incident sent by the IDS stays listed even if the filter hides it (but a search narrows it)
    if incoming and not search and incoming not in options and (all_ids == incoming).any():
        options = [incoming] + options
    if not options:
        st.warning("No Incident ID matches the search." if search else "No incidents match the filter.")
        return
    if st.session_state.get("tcp_incident_select") not in options:
        st.session_state.pop("tcp_incident_select", None)

    def label(i):
        r = scored.loc[all_ids.index[all_ids == i][0]]
        return f"{i} · {r['prediction']} · p={r['attack_probability']:.3f}"

    c1, c2 = st.columns([4, 1])
    with c1:
        selected = st.selectbox(f"Incident ({len(options):,} shown, highest attack probability first)", options,
                                format_func=label, key="tcp_incident_select")
    st.query_params["incident"] = selected
    st.session_state["_tcp_applied_incident"] = selected
    with c2:
        st.write("")
        st.link_button("← Back to XAI IDS", f"{IDS_URL}/?incident={selected}", width="stretch")

    idx = all_ids.index[all_ids == selected][0]
    row = raw.loc[[idx]]
    with st.spinner("Explaining incident (attribution, LIME, occlusion, surrogate, consensus, flood context)…"):
        exp = xai.explain(row, top_k=top_k)
        cons = xai.consensus(row, use_lime=use_lime)
        ctx = flood_context(raw, scored, seconds_of_day(raw, data_key), idx)
    is_att = exp["prediction"] == ATTACK
    level, note = incident_priority(exp["probability"], is_att, cons["trust"])
    actual = scored.loc[idx, "actual"] if "actual" in scored.columns else None

    # --- KPI cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        card("Model prediction", exp["prediction"], f"dataset label: {actual}" if actual else "no label in file",
             THEME["attack"] if is_att else THEME["normal"])
    with k2:
        card(f"P({FLOOD_SHORT})", f"{exp['probability']:.1%}", f"threshold {xai.threshold:.2f}")
    with k3:
        card("Analyst priority", level, f"source flagged {ctx['src_flagged']:.0%} of the time", PRIORITY_COLORS[level])
    with k4:
        card("Explanation trust", cons["trust"], f"XAI consensus score {cons['score']:.2f}", TRUST_COLORS[cons["trust"]])
    if note:
        st.warning(note)

    # --- analyst summary
    if ctx["flood"]:
        p = ctx["protocol"]
        spread = (f"a distributed, spoofed-source pattern typical of {_a(p)} DDoS"
                  if ctx["window_concentration"] < 0.2 else "a concentrated pattern (few senders)")
        where = (f"Within ±{FLOOD_WINDOW_S}s the target received **{ctx['window_to_target']:,} {p} packets** "
                 f"(≈{ctx['window_rate_s']:.1f}/s)" if ctx["timed"] else
                 f"This packet has no timestamp (shifted export row); over the capture the target received "
                 f"**{ctx['window_to_target']:,} {p} packets**")
        synack_txt = (f" It answered only **{ctx['window_synack']:,} SYN-ACKs** in that window — half-open connections "
                      "pile up." if p == "TCP SYN" and ctx["timed"] else "")
        context_txt = (f" This packet is {_a(p)} {ctx['direction']} **{ctx['target']}**. {where} from "
                       f"**{ctx['window_sources']:,} distinct sources**; the busiest sent only "
                       f"{ctx['window_concentration']:.2%} — {spread}.{synack_txt} The peer **{ctx['peer']}** itself "
                       f"sent {ctx['peer_packets']:,} {p} packet(s) to the target.")
    else:
        context_txt = (f" This packet is {ctx['protocol']} traffic ({ctx['src']} → {ctx['dst']}), "
                       "not one of the flood protocols (TCP SYN · UDP · ICMP).")
    tdev = devices.describe(ctx.get("target", ctx["dst"]))
    if ctx.get("flood") and tdev["known"]:
        context_txt += f" The target is the **{tdev['device'].split(' · ')[0]}**"
        context_txt += (f"; telemetry of **{', '.join(tdev['dependent_sensors'])}** passes through it, so the flood "
                        "can delay or drop those sensor readings." if tdev["dependent_sensors"] else ".")
    st.markdown(f'<div class="xai-card" style="line-height:1.6"><div class="label">ANALYST SUMMARY</div>'
                f'<div style="margin-top:6px">{_md_bold(exp["narrative"] + context_txt)}</div>'
                f'<div style="margin-top:8px;color:{THEME["muted"]}">{cons["recommendation"]}</div></div>',
                unsafe_allow_html=True)

    left, right = st.columns([1.15, 1], gap="large")
    with left:
        section("Why the model decided this")
        st.plotly_chart(style_fig(waterfall(exp), 420, legend=False), width="stretch")
        section("Incident fields vs. typical traffic")
        st.dataframe(pd.DataFrame([{
            "feature": c["feature"], "meaning": c["description"], "this incident": c["value"],
            "typical normal": xai.encoder.decode_value(c["feature"], c["normal_median"]),
            f"typical {FLOOD_SHORT}": xai.encoder.decode_value(c["feature"], c["attack_median"]),
            "contribution": c["contribution"]} for c in exp["contributions"]]),
            width="stretch", hide_index=True,
            column_config={"contribution": st.column_config.NumberColumn(format="%+.4f")})
    with right:
        device_context(ctx)
        section("Flood evidence — is the target hit by many sources at once?")
        if ctx["flood"]:
            p = ctx["protocol"]
            span = f"±{FLOOD_WINDOW_S}s" if ctx["timed"] else "in capture"
            e1, e2, e3 = st.columns(3)
            with e1:
                card(f"{p} to target {span}", f"{ctx['window_to_target']:,}",
                     (f"≈{ctx['window_rate_s']:.1f} packets/s → {ctx['target']}" if ctx["timed"]
                      else f"→ {ctx['target']} (no timestamp)"))
            with e2:
                card("Distinct sources", f"{ctx['window_sources']:,}", f"{span} · {ctx['sources_to_target']:,} overall")
            with e3:
                if p == "TCP SYN" and ctx["timed"]:
                    card(f"SYN-ACK from target {span}", f"{ctx['window_synack']:,}",
                         f"vs {ctx['window_to_target']:,} SYN in", THEME["attack"])
                else:
                    card("Busiest source share", f"{ctx['window_concentration']:.2%}", "low = distributed (DDoS)",
                         THEME["attack"] if ctx["window_concentration"] < 0.2 else THEME["warn"])
            s = ctx["series"].dropna(subset=["t"])
            if not s.empty:
                s = s.assign(minute=(s["t"] // 60) * 60)
                per_min = s.groupby(["minute", "kind"]).size().reset_index(name="packets")
                per_min["clock"] = per_min["minute"].map(lambda m: _hhmmss(m)[:5])
                fig = px.bar(per_min, x="clock", y="packets", color="kind",
                             color_discrete_map={"to target": THEME["attack"], "from target": THEME["accent"]},
                             title=f"{p} packets per minute to / from {ctx['target']}"
                                   + (" (incl. SYN-ACK replies)" if p == "TCP SYN" else ""))
                if pd.notna(ctx["time"]):
                    fig.add_vline(x=_hhmmss((ctx["time"] // 60) * 60)[:5], line_dash="dash", line_color=THEME["warn"])
                fig.update_layout(bargap=0.15, xaxis_title="time of day (dataset is a sample, rates are approximate)")
                st.plotly_chart(style_fig(fig, 300), width="stretch")
            elif not ctx["timed"]:
                st.caption("These packets have no timestamps in the export, so no per-minute chart is possible.")
        else:
            st.info("This packet is not TCP SYN, UDP or ICMP, so there is no network-flood context for it.")

        section("Do the XAI methods agree?")
        comp = cons["components"]
        fig = go.Figure(go.Bar(
            x=[comp[k] for k in COMPONENT_LABELS], y=list(COMPONENT_LABELS.values()), orientation="h",
            marker_color=[TRUST_COLORS["High"] if comp[k] >= ddos_cfg.CONSENSUS_HIGH else
                          TRUST_COLORS["Medium"] if comp[k] >= ddos_cfg.CONSENSUS_MEDIUM else
                          TRUST_COLORS["Low"] for k in COMPONENT_LABELS],
            text=[f"{comp[k]:.2f}" for k in COMPONENT_LABELS], textposition="outside", cliponaxis=False))
        fig.update_layout(title=f"Consensus components (XCS {cons['score']:.2f})", xaxis_range=[0, 1.15])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(style_fig(fig, 230, legend=False), width="stretch")
        st.caption("Verdicts: " + " · ".join(f"{n}: {ATTACK if v else NORMAL}" for n, v in cons["verdicts"].items()))
        section("Global surrogate rule for this incident")
        st.markdown('<div class="xai-path">' + "<br>".join(xai.surrogate_path(row)) + "</div>", unsafe_allow_html=True)

    with st.expander("Raw incident fields"):
        st.dataframe(row.T.rename(columns={idx: "value"}), width="stretch")
    report = {"incident_id": selected, "prediction": exp["prediction"], "attack_probability": exp["probability"],
              "dataset_label": actual, "analyst_priority": level, "explanation_trust": cons["trust"],
              "xai_consensus_score": cons["score"], "consensus_components": cons["components"],
              "method_verdicts": cons["verdicts"], "recommendation": cons["recommendation"],
              "attribution_method": exp["method"], "base_value": exp["base_value"],
              "top_contributions": [{k: c[k] for k in ("feature", "value", "contribution")} for c in exp["contributions"]],
              "flood_context": {k: v for k, v in ctx.items() if k != "series"} | {"window_seconds": FLOOD_WINDOW_S},
              "surrogate_path": xai.surrogate_path(row)}
    st.download_button("Download incident explanation (JSON)", json.dumps(report, indent=2, default=str),
                       f"ddos_tcp_incident_{selected}.json", "application/json")


def _md_bold(text: str) -> str:
    """Minimal **bold** / `code` markdown -> HTML for text placed inside custom HTML cards."""
    import html as _html
    import re
    text = _html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", text)


def main() -> None:
    try:
        st.set_page_config(page_title=f"{FLOOD} XAI", page_icon=PAGE_ICON, layout="wide")
    except Exception:
        pass  # already set by the multipage app
    inject_styles()

    st.markdown(f"""<div class="xai-hero">
        <span class="xai-badge">Component 2 · Attack XAI</span><span class="xai-badge">Edge-IIoTset</span>
        <span class="xai-badge">Network Flood UI</span>
        <span class="xai-badge">Random Forest + SHAP · LIME · Surrogate</span>
        <span class="xai-badge">★ Novelty: Multi-method XAI Consensus</span>
        <h1>{PAGE_ICON} {FLOOD} — Explainable Detection</h1>
        <p>{HERO_TEXT}</p></div>""", unsafe_allow_html=True)

    try:
        xai = load_xai()
    except ModelNotTrainedError as e:
        st.error(f"The {FLOOD} model has not been trained yet.")
        st.code(str(e).split("Run:")[-1].strip() if "Run:" in str(e) else str(e), language="bash")
        st.markdown("Training data must include Edge-IIoTset network-flood CSVs (**`DDoS_TCP_SYN`**, **`DDoS_UDP`**, **`DDoS_ICMP`**) "
                    "(or `DNN-EdgeIIoT-dataset.csv`) plus normal-traffic CSVs.")
        st.stop()

    # ----------------------------------------------------------------- sidebar
    with st.sidebar:
        st.header("Inputs")
        data_up = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="tcp_data")
        model_up = st.file_uploader(f"Trained {FLOOD} model (.joblib / .pkl)",
                                    type=["joblib", "pkl", "pickle"], key="tcp_model")
        enc_up = st.file_uploader("Feature encoder (.joblib, optional)",
                                  type=["joblib", "pkl", "pickle"], key="tcp_encoder")
        st.caption("Only load pickle files you trust - loading a pickle can run code.")
        st.header("Explanation settings")
        bg_size = st.slider("Background sample (rows)", 100, 1000, 300, 50, key="tcp_bg",
                            help="Real dataset rows used as the LIME background distribution.")
        use_shap = st.toggle("Compute SHAP", xai.capabilities["shap"], key="tcp_use_shap",
                             disabled=not xai.capabilities["shap"],
                             help="Off → exact tree-path contributions instead of SHAP.")
        use_lime = st.toggle("Compute LIME", xai.capabilities["lime"], key="tcp_use_lime",
                             disabled=not xai.capabilities["lime"])
        threshold = st.slider("Decision threshold", 0.1, 0.9, 0.5, 0.05, key="tcp_threshold",
                              help=f"Packets with P({FLOOD_SHORT}) ≥ threshold are flagged.")
        top_k = st.slider("Features shown in explanations", 5, 20, 10, key="tcp_topk")

    # ------------------------------------------------------------ dataset
    if data_up is not None:
        raw, data_name = read_csv(data_up.getvalue(), data_up.name), data_up.name
    elif ddos_cfg.DATASET_PATH.exists():
        raw, data_name = read_csv(str(ddos_cfg.DATASET_PATH), ddos_cfg.DATASET_PATH.name), ddos_cfg.DATASET_PATH.name
    else:
        st.warning(f"Dataset not found at `{ddos_cfg.DATASET_PATH}` — showing the saved test sample instead.")
        raw, data_name = xai.sample_traffic(), ddos_cfg.SAMPLE_TRAFFIC_PATH.name

    # ------------------------------------------------------ model + encoder
    try:
        model = load_artifact(model_up) if model_up else xai.model
        encoder = load_artifact(enc_up) if enc_up else xai.encoder
    except Exception as exc:
        st.error(f"Could not load model/encoder file: {type(exc).__name__}: {exc}")
        st.stop()
    n_in = getattr(model, "n_features_in_", len(encoder.feature_names))
    if not hasattr(model, "predict_proba") or n_in != len(encoder.feature_names):
        st.error(f"The model expects {n_in} features but the encoder produces {len(encoder.feature_names)}. "
                 "Upload the encoder that was saved with this model (artifacts/feature_encoder.joblib).")
        st.stop()

    classes = list(getattr(model, "classes_", [0, 1]))
    with st.sidebar:
        attack_class = st.selectbox(f"Class that means '{FLOOD_SHORT} / attack'", classes,
                                    index=classes.index(1) if 1 in classes else len(classes) - 1,
                                    key="tcp_attack_class")

    signature = (data_name, len(raw), getattr(model_up, "name", "default-model"),
                 getattr(enc_up, "name", "default-encoder"), bg_size, use_shap, str(attack_class))
    if st.session_state.get("tcp_xai_sig") != signature:
        with st.spinner("Building explanation engine and background sample…"):
            st.session_state["tcp_xai"] = configure_xai(xai, model, encoder, raw, bg_size, use_shap, attack_class)
        st.session_state["tcp_xai_sig"] = signature
    xai = st.session_state["tcp_xai"]
    xai.threshold = threshold

    st.caption(f"Dataset **{data_name}** · {len(raw):,} rows · model classes: "
               f"{', '.join(map(str, classes))} · attack class: {attack_class} · "
               f"explainer: {xai.capabilities['attribution_method']} · LIME {'on' if use_lime else 'off'}")

    MAX_ROWS = 200_000
    if len(raw) > MAX_ROWS:
        st.warning(f"File has {len(raw):,} rows; analysing the first {MAX_ROWS:,}.")
        raw = raw.iloc[:MAX_ROWS]
    raw = raw.reset_index(drop=True)
    scored = score(xai, raw, signature + (threshold,))

    t0, t1, t2, t3, t4, t5 = st.tabs(["🔎 Incident XAI", "🛡️ Live Detection", "🔍 Packet Explanation",
                                      "★ XAI Consensus", "🌐 Global Explainability", "📊 Model Performance"])
    with t0:
        tab_incident(xai, raw, scored, top_k, use_lime, signature)
    with t1:
        tab_detection(xai, raw, scored, signature)
    with t2:
        tab_local(xai, raw, scored, top_k, use_lime)
    with t3:
        tab_consensus(xai, raw, scored, use_lime)
    with t4:
        tab_global(xai, top_k)
    with t5:
        tab_performance(xai)


main()
