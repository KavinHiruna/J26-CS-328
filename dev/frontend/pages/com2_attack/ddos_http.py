"""
DDoS HTTP Flood — Explainable AI dashboard (Component 2, Edge-IIoTset).

Location : dev/frontend/pages/com2_attack/ddos_http.py
Backend  : dev/backend/component2_xai/DDoS_http

Run standalone:   streamlit run frontend/pages/com2_attack/ddos_http.py   (from dev/)
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
# Backend import (dev/frontend/pages/com2_attack/ddos_http.py -> dev/backend)
# --------------------------------------------------------------------------- #
DEV_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = DEV_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from component2_xai.DDoS_http import DDoSHttpXAI, ModelNotTrainedError  # noqa: E402
from component2_xai.DDoS_http import config as ddos_cfg                  # noqa: E402

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
@st.cache_resource(show_spinner="Loading DDoS HTTP Flood model…")
def load_xai() -> DDoSHttpXAI:
    return DDoSHttpXAI()


@st.cache_data(show_spinner="Loading dataset…")
def read_csv(source: str | bytes, name: str) -> pd.DataFrame:
    """Read a CSV from a path or uploaded bytes once and cache it."""
    return pd.read_csv(BytesIO(source) if isinstance(source, bytes) else source, low_memory=False, dtype=str)


def load_artifact(upload):
    """joblib/pickle artifact from the sidebar (joblib also reads plain pickles)."""
    return joblib.load(BytesIO(upload.getvalue()))


def configure_xai(base: DDoSHttpXAI, model, encoder, data: pd.DataFrame, bg_size: int,
                  use_shap: bool, attack_class) -> DDoSHttpXAI:
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
def score(_xai: DDoSHttpXAI, _raw: pd.DataFrame, key: tuple) -> pd.DataFrame:
    """Cached per (data, model, settings, threshold) so widget reruns don't re-score big files."""
    return _xai.predict(_raw)


# --------------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------------- #
def tab_detection(xai: DDoSHttpXAI, raw: pd.DataFrame, scored: pd.DataFrame) -> None:
    ind = xai.flood_indicators(raw, scored)
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        card("Packets analysed", f"{ind['packets']:,}")
    with c2:
        card("Flagged as HTTP flood", f"{ind['flagged']:,}", f"{ind['flagged_ratio']:.1%} of traffic", THEME["attack"])
    with c3:
        card("HTTP request packets", f"{ind['http_request_ratio']:.1%}",
             ", ".join(f"{k}: {v:,}" for k, v in ind["http_methods"].items()) or "none")
    with c4:
        card("Flagged sources", f"{ind['distinct_sources_flagged']:,}", "distinct source IPs")
    with c5:
        acc = None
        if "actual" in scored.columns:
            acc = (scored["prediction"] == scored["actual"]).mean()
        card("Agreement with labels", f"{acc:.1%}" if acc is not None else "—",
             "dataset labels present" if acc is not None else "no labels in file", THEME["normal"])

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
                          yaxis_title="P(HTTP flood)", yaxis_range=[0, 1.02])
        st.plotly_chart(style_fig(fig, 300), use_container_width=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        fig = px.histogram(scored, x="attack_probability", color="prediction", nbins=40,
                           color_discrete_map=CLASS_COLORS, title="Probability distribution")
        st.plotly_chart(style_fig(fig, 320), use_container_width=True)
    with c2:
        if ind["top_flagged_sources"]:
            src = pd.DataFrame({"source": list(ind["top_flagged_sources"].keys()),
                                "packets": list(ind["top_flagged_sources"].values())})
            fig = px.bar(src, x="packets", y="source", orientation="h", title="Top flagged source IPs",
                         color_discrete_sequence=[THEME["attack"]])
            fig.update_yaxes(categoryorder="total ascending")
            st.plotly_chart(style_fig(fig, 320, legend=False), use_container_width=True)
        else:
            st.info("No packets flagged — no source IPs to rank.")
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
    only_flagged = st.toggle("Show flagged packets only", value=False, key="ddos_only_flagged")
    view = scored[scored["is_attack"]] if only_flagged else scored
    view = view.sort_values("attack_probability", ascending=False)
    st.dataframe(
        view.drop(columns=["is_attack"]),
        use_container_width=True, height=360,
        column_config={"attack_probability": st.column_config.ProgressColumn(
            "P(HTTP flood)", min_value=0.0, max_value=1.0, format="%.3f")},
    )
    st.download_button("Download verdicts (CSV)", view.to_csv().encode(), "ddos_http_verdicts.csv", "text/csv")


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
    fig.update_layout(title=f"{exp['method']} — contribution to P(HTTP flood)", xaxis_title="probability")
    return fig


def tab_local(xai: DDoSHttpXAI, raw: pd.DataFrame, scored: pd.DataFrame, top_k: int,
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
                           format_func=label, key="ddos_packet")
        if len(scored) > MAX_PICK:
            st.caption(f"Showing the {MAX_PICK:,} highest-probability packets of {len(scored):,}.")
    with c2:
        method = st.radio("Explainer", methods, key="ddos_method",
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
                fig.update_layout(title="LIME — local rule weights towards HTTP flood")
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
        "typical HTTP flood": xai.encoder.decode_value(c["feature"], c["attack_median"]),
        "contribution": c["contribution"],
    } for c in exp["contributions"]])
    st.dataframe(tbl, use_container_width=True, hide_index=True,
                 column_config={"contribution": st.column_config.NumberColumn(format="%+.4f")})
    with st.expander("Raw packet fields"):
        st.dataframe(row.T.rename(columns={idx: "value"}), use_container_width=True)


def tab_global(xai: DDoSHttpXAI, top_k: int) -> None:
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
                          xaxis_title="contribution to P(HTTP flood)")
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
        f = st.selectbox("Feature", fi["feature"].tolist(), key="ddos_dep_feature")
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


def tab_performance(xai: DDoSHttpXAI) -> None:
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
COMPONENT_LABELS = {"rank": "Rank agreement", "topk": "Top-k feature overlap",
                    "direction": "Direction agreement", "verdict": "Verdict agreement"}


def novelty_banner(xai: DDoSHttpXAI) -> None:
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


def tab_consensus(xai: DDoSHttpXAI, raw: pd.DataFrame, scored: pd.DataFrame, use_lime: bool = True) -> None:
    novelty_banner(xai)
    labels = xai.method_labels

    # ---------------- A. packet-level consensus ------------------------------
    section("A · Packet-level consensus")
    order = scored.sort_values("attack_probability", ascending=False).index[:2_000].tolist()
    idx = st.selectbox("Packet (2,000 highest attack probability)", order, key="ddos_cons_packet",
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
        st.caption(f"Random Forest P(HTTP flood) = {cons['probability']:.3f}")

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
            fig.update_layout(title="Normalised attribution per method (red → HTTP flood, teal → Normal)")
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
    """Traffic around one incident: is its source repeating the same request at a flood-like rate?"""
    def col(name):
        return raw[name].astype(str).str.strip() if name in raw.columns else pd.Series("", index=raw.index)

    src, uri, method = col("ip.src_host"), col("http.request.full_uri"), col("http.request.method")
    is_req = ~method.isin(["", "0", "0.0", "nan"])
    same_src = src == src[idx]
    t0 = secs[idx]
    near = same_src & ((secs - t0).abs() <= FLOOD_WINDOW_S) if pd.notna(t0) else same_src & False
    same_req = (same_src & is_req & (uri == uri[idx]) & (method == method[idx])) if is_req[idx] else same_src & False
    return {
        "src": src[idx], "uri": uri[idx] if is_req[idx] else "", "method": method[idx] if is_req[idx] else "",
        "time": t0, "src_packets": int(same_src.sum()), "src_requests": int((same_src & is_req).sum()),
        "same_request": int(same_req.sum()),
        "window_packets": int(near.sum()), "window_requests": int((near & is_req).sum()),
        "window_flagged": float(scored.loc[near, "is_attack"].mean()) if near.any() else 0.0,
        "src_flagged": float(scored.loc[same_src, "is_attack"].mean()) if same_src.any() else 0.0,
        "series": pd.DataFrame({"t": secs[same_src & is_req], "same": same_req[same_src & is_req]}),
    }


def incident_priority(p: float, is_attack: bool, trust: str) -> tuple[str, str]:
    """Analyst priority from model confidence + explanation consensus (as on the SQLi page)."""
    if not is_attack:
        return "Low", ""
    if p >= 0.8 and trust == "High":
        return "Critical", ""
    if p >= 0.8:
        return "High", "The model is confident but the XAI methods disagree — confirm with the traffic context before blocking."
    return "Medium", "Borderline score — corroborate with the source's request rate before acting."


def _hhmmss(s: float) -> str:
    return "—" if pd.isna(s) else f"{int(s // 3600):02d}:{int(s % 3600 // 60):02d}:{s % 60:06.3f}"


def tab_incident(xai: DDoSHttpXAI, raw: pd.DataFrame, scored: pd.DataFrame, top_k: int,
                 use_lime: bool, data_key: tuple) -> None:
    id_col = incident_col(raw)
    if not id_col:
        st.error("No Incident ID column found (expected 'Incident ID' or 'Incident_ID').")
        return

    # --- the IDS opens this page as ?incident=ALR-000024 -> select it once
    incoming = st.query_params.get("incident", "").strip()
    if incoming and st.session_state.get("_ddos_applied_incident") != incoming:
        st.session_state["_ddos_applied_incident"] = incoming
        st.session_state["ddos_incident_select"] = incoming

    # --- filter toggle, search box, incident dropdown
    only_req = st.toggle("Show only HTTP request packets", True, key="ddos_only_requests",
                         help="Fast pre-filter to find interesting incidents (an HTTP flood is made of requests). "
                              "It is not a classifier.")
    method = raw["http.request.method"].astype(str).str.strip() if "http.request.method" in raw.columns else None
    view = scored if not only_req or method is None else scored[~method.isin(["", "0", "0.0", "nan"])]
    view = view.sort_values("attack_probability", ascending=False)
    search = st.text_input("Search Incident ID (optional)", key="ddos_incident_search",
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
    if st.session_state.get("ddos_incident_select") not in options:
        st.session_state.pop("ddos_incident_select", None)

    def label(i):
        r = scored.loc[all_ids.index[all_ids == i][0]]
        return f"{i} · {r['prediction']} · p={r['attack_probability']:.3f}"

    c1, c2 = st.columns([4, 1])
    with c1:
        selected = st.selectbox(f"Incident ({len(options):,} shown, highest attack probability first)", options,
                                format_func=label, key="ddos_incident_select")
    st.query_params["incident"] = selected
    st.session_state["_ddos_applied_incident"] = selected
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
        card("P(HTTP flood)", f"{exp['probability']:.1%}", f"threshold {xai.threshold:.2f}")
    with k3:
        card("Analyst priority", level, f"source flagged {ctx['src_flagged']:.0%} of the time", PRIORITY_COLORS[level])
    with k4:
        card("Explanation trust", cons["trust"], f"XAI consensus score {cons['score']:.2f}", TRUST_COLORS[cons["trust"]])
    if note:
        st.warning(note)

    # --- analyst summary
    rate = ctx["window_requests"] / (2 * FLOOD_WINDOW_S / 60)
    context_txt = ""
    if ctx["uri"]:
        context_txt = (f" In the dataset, source **{ctx['src']}** sent this exact request "
                       f"(`{ctx['method']} {ctx['uri']}`) **{ctx['same_request']:,} times**, and "
                       f"{ctx['window_requests']:,} HTTP requests within ±{FLOOD_WINDOW_S}s of this incident "
                       f"(≈{rate:.1f} requests/min).")
    elif ctx["src"]:
        context_txt = f" This packet carries no HTTP request; its source **{ctx['src']}** sent {ctx['src_requests']:,} HTTP requests in the dataset."
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
            "typical HTTP flood": xai.encoder.decode_value(c["feature"], c["attack_median"]),
            "contribution": c["contribution"]} for c in exp["contributions"]]),
            width="stretch", hide_index=True,
            column_config={"contribution": st.column_config.NumberColumn(format="%+.4f")})
    with right:
        section("Flood evidence — is this source repeating itself?")
        e1, e2, e3 = st.columns(3)
        with e1:
            card("Same request", f"{ctx['same_request']:,}", "identical method + URL from this source")
        with e2:
            card(f"Requests ±{FLOOD_WINDOW_S}s", f"{ctx['window_requests']:,}", f"≈{rate:.1f} / min")
        with e3:
            card(f"Flagged ±{FLOOD_WINDOW_S}s", f"{ctx['window_flagged']:.0%}", "of this source's packets")
        s = ctx["series"].dropna()
        if not s.empty:
            s = s.assign(minute=(s["t"] // 60) * 60,
                         kind=np.where(s["same"], "same request as incident", "other requests"))
            per_min = s.groupby(["minute", "kind"]).size().reset_index(name="requests")
            per_min["clock"] = per_min["minute"].map(lambda m: _hhmmss(m)[:5])
            fig = px.bar(per_min, x="clock", y="requests", color="kind",
                         color_discrete_map={"same request as incident": THEME["attack"], "other requests": THEME["accent"]},
                         title=f"HTTP requests per minute from {ctx['src']}")
            if pd.notna(ctx["time"]):
                fig.add_vline(x=_hhmmss((ctx["time"] // 60) * 60)[:5], line_dash="dash", line_color=THEME["warn"])
            fig.update_layout(bargap=0.15, xaxis_title="time of day (dataset is a sample, rates are approximate)")
            st.plotly_chart(style_fig(fig, 300), width="stretch")
        else:
            st.info("This source sent no HTTP requests in the dataset.")

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
                       f"ddos_http_incident_{selected}.json", "application/json")


def _md_bold(text: str) -> str:
    """Minimal **bold** / `code` markdown -> HTML for text placed inside custom HTML cards."""
    import html as _html
    import re
    text = _html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", text)


def main() -> None:
    try:
        st.set_page_config(page_title="DDoS HTTP Flood XAI", page_icon="🌊", layout="wide")
    except Exception:
        pass  # already set by the multipage app
    inject_styles()

    st.markdown("""<div class="xai-hero">
        <span class="xai-badge">Component 2 · Attack XAI</span><span class="xai-badge">Edge-IIoTset</span>
        <span class="xai-badge">Random Forest + SHAP · LIME · Surrogate</span>
        <h1>🌊 DDoS HTTP Flood — Explainable Detection</h1>
        <p>Detects HTTP GET/POST flood packets in IIoT traffic and explains every verdict:
           which packet features drove the decision, how they compare to normal traffic,
           and the global rules the model learned.</p></div>""", unsafe_allow_html=True)

    try:
        xai = load_xai()
    except ModelNotTrainedError as e:
        st.error("The DDoS HTTP Flood model has not been trained yet.")
        st.code(str(e).split("Run:")[-1].strip() if "Run:" in str(e) else str(e), language="bash")
        st.markdown("Training data must include Edge-IIoTset **`DDoS_HTTP_Flood_attack.csv`** "
                    "(or `DNN-EdgeIIoT-dataset.csv`) plus normal-traffic CSVs.")
        st.stop()

    # ----------------------------------------------------------------- sidebar
    with st.sidebar:
        st.header("Inputs")
        data_up = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="ddos_data")
        model_up = st.file_uploader("Trained DDoS HTTP model (.joblib / .pkl)",
                                    type=["joblib", "pkl", "pickle"], key="ddos_model")
        enc_up = st.file_uploader("Feature encoder (.joblib, optional)",
                                  type=["joblib", "pkl", "pickle"], key="ddos_encoder")
        st.caption("Only load pickle files you trust - loading a pickle can run code.")
        st.header("Explanation settings")
        bg_size = st.slider("Background sample (rows)", 100, 1000, 300, 50, key="ddos_bg",
                            help="Real dataset rows used as the LIME background distribution.")
        use_shap = st.toggle("Compute SHAP", xai.capabilities["shap"], key="ddos_use_shap",
                             disabled=not xai.capabilities["shap"],
                             help="Off → exact tree-path contributions instead of SHAP.")
        use_lime = st.toggle("Compute LIME", xai.capabilities["lime"], key="ddos_use_lime",
                             disabled=not xai.capabilities["lime"])
        threshold = st.slider("Decision threshold", 0.1, 0.9, 0.5, 0.05, key="ddos_threshold",
                              help="Packets with P(HTTP flood) ≥ threshold are flagged.")
        top_k = st.slider("Features shown in explanations", 5, 20, 10, key="ddos_topk")

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
        attack_class = st.selectbox("Class that means 'DDoS HTTP flood / attack'", classes,
                                    index=classes.index(1) if 1 in classes else len(classes) - 1,
                                    key="ddos_attack_class")

    signature = (data_name, len(raw), getattr(model_up, "name", "default-model"),
                 getattr(enc_up, "name", "default-encoder"), bg_size, use_shap, str(attack_class))
    if st.session_state.get("ddos_xai_sig") != signature:
        with st.spinner("Building explanation engine and background sample…"):
            st.session_state["ddos_xai"] = configure_xai(xai, model, encoder, raw, bg_size, use_shap, attack_class)
        st.session_state["ddos_xai_sig"] = signature
    xai = st.session_state["ddos_xai"]
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
        tab_detection(xai, raw, scored)
    with t2:
        tab_local(xai, raw, scored, top_k, use_lime)
    with t3:
        tab_consensus(xai, raw, scored, use_lime)
    with t4:
        tab_global(xai, top_k)
    with t5:
        tab_performance(xai)


main()
