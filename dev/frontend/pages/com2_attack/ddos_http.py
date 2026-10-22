"""
DDoS HTTP Flood — Explainable AI dashboard (Component 2, Edge-IIoTset).

Location : dev/frontend/pages/com2_attack/ddos_http.py
Backend  : dev/backend/component2_xai/DDoS_http

Run standalone:   streamlit run frontend/pages/com2_attack/ddos_http.py   (from dev/)
"""
from __future__ import annotations

import sys
from pathlib import Path

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
}
ATTACK, NORMAL = ddos_cfg.CLASS_NAMES[1], ddos_cfg.CLASS_NAMES[0]
CLASS_COLORS = {ATTACK: THEME["attack"], NORMAL: THEME["normal"]}


def inject_styles() -> None:
    t = THEME
    st.markdown(f"""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;600&display=swap');
      .stApp {{ background: radial-gradient(1200px 600px at 10% -10%, #16224a 0%, {t['bg']} 55%); color:{t['text']}; font-family:{t['font']}; }}
      section[data-testid="stSidebar"] {{ background:{t['panel']}; border-right:1px solid {t['panel_border']}; }}
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


@st.cache_data(show_spinner=False)
def read_upload(file_bytes: bytes, name: str) -> pd.DataFrame:
    from io import BytesIO
    return pd.read_csv(BytesIO(file_bytes), low_memory=False, dtype=str)


def score(xai: DDoSHttpXAI, raw: pd.DataFrame, threshold: float) -> pd.DataFrame:
    xai.threshold = threshold
    return xai.predict(raw)


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
        mix = scored["risk_level"].value_counts().reindex(["Low", "Elevated", "High", "Critical"]).fillna(0)
        fig = go.Figure(go.Pie(labels=mix.index, values=mix.values, hole=.55,
                               marker=dict(colors=[THEME["normal"], THEME["accent"], THEME["warn"], THEME["attack"]])))
        fig.update_layout(title="Risk levels")
        st.plotly_chart(style_fig(fig, 320), use_container_width=True)

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


def tab_local(xai: DDoSHttpXAI, raw: pd.DataFrame, scored: pd.DataFrame, top_k: int) -> None:
    order = scored.sort_values("attack_probability", ascending=False).index.tolist()

    def label(i):
        r = scored.loc[i]
        src = f" · {r['ip.src_host']}" if "ip.src_host" in scored.columns else ""
        return f"#{i} · {r['prediction']} · p={r['attack_probability']:.3f}{src}"

    c1, c2 = st.columns([3, 1])
    with c1:
        idx = st.selectbox("Packet to explain (sorted by attack probability)", order,
                           format_func=label, key="ddos_packet")
    with c2:
        method = st.radio("Explainer", ["SHAP / tree-path", "LIME", "Surrogate rule"], key="ddos_method",
                          help="SHAP is used when installed; otherwise exact tree-path contributions.")
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
        if method == "SHAP / tree-path":
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
# Page
# --------------------------------------------------------------------------- #
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

    with st.sidebar:
        st.markdown("### 🌊 DDoS HTTP Flood")
        source = st.radio("Traffic source", ["Sample test traffic", "Upload CSV"], key="ddos_source")
        raw = None
        if source == "Upload CSV":
            up = st.file_uploader("Edge-IIoTset-format CSV", type=["csv"], key="ddos_upload")
            if up is not None:
                raw = read_upload(up.getvalue(), up.name)
        else:
            raw = xai.sample_traffic()
        threshold = st.slider("Decision threshold", 0.05, 0.95, 0.50, 0.05, key="ddos_threshold",
                              help="Packets with P(HTTP flood) ≥ threshold are flagged.")
        top_k = st.slider("Features shown in explanations", 5, 20, 10, key="ddos_topk")
        caps = xai.capabilities
        st.caption(f"Explainer: **{caps['attribution_method']}** · LIME {'✅' if caps['lime'] else '❌'}")

    if raw is None or raw.empty:
        st.info("Upload a CSV in Edge-IIoTset format (same 63 columns) to analyse it.")
        tabs = st.tabs(["🌐 Global Explainability", "📊 Model Performance"])
        with tabs[0]:
            tab_global(xai, top_k)
        with tabs[1]:
            tab_performance(xai)
        return

    MAX_ROWS = 200_000
    if len(raw) > MAX_ROWS:
        st.warning(f"File has {len(raw):,} rows; analysing the first {MAX_ROWS:,}.")
        raw = raw.iloc[:MAX_ROWS]
    raw = raw.reset_index(drop=True)
    scored = score(xai, raw, threshold)

    t1, t2, t3, t4 = st.tabs(["🛡️ Live Detection", "🔍 Packet Explanation",
                              "🌐 Global Explainability", "📊 Model Performance"])
    with t1:
        tab_detection(xai, raw, scored)
    with t2:
        tab_local(xai, raw, scored, top_k)
    with t3:
        tab_global(xai, top_k)
    with t4:
        tab_performance(xai)


main()
