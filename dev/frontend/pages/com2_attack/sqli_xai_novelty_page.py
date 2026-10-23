"""
Component 2 - Web Injection XAI: SQL injection · XSS · Malicious upload (Streamlit page - FRONTEND)

FILE LOCATION : dev/frontend/pages/com2_attack/sqli_xai_novelty_page.py
BACKEND FILES : dev/backend/component2_xai/
                sqli_xai_config.py    (file paths: dataset, models, outputs)
                sqli_xai_engine.py    (SQLi evidence XAI: PSS, trust, counterfactual, techniques)
                web_injection_xai.py  (XSS + upload features, labels, payload inspector, techniques)
                sqli_xai_styles.py    (colours, fonts, CSS)
DATASET       : dev/data/EdgeIIoT_train_80_with_incident_id.csv
MODEL         : dev/backend/component2_xai/model/web_injection_rf.pkl (+ web_feature_columns.pkl)
                built by model/train_web_injection_rf.py (classes: Other, SQL_injection, XSS, Uploading)

Same architecture as the DDoS pages (ddos_http.py / ddos_icmp.py):
  theme + chart helpers -> cached loaders -> one function per tab -> main()
  Tabs: Incident XAI | Live Detection | ★ Explanation Trust (SQLi) | Global Explainability | Model Performance

Run from the repo's dev folder:
  python -m streamlit run frontend\\pages\\com2_attack\\sqli_xai_novelty_page.py

==============================================================================
SCREEN MAP - where each part of the page is in this code
(search for the tag, e.g. "[SCREEN-3]", to jump to that block)
==============================================================================

 +----------------+--------------------------------------------------------+
 |  SIDEBAR       |  [SCREEN-2] Page title + dataset info                  |
 |  [SCREEN-1]    |  TABS:                                                 |
 |  - Inputs      |  🔎 Incident XAI  (tab_incident)                        |
 |    (uploads)   |     [SCREEN-3]  filter toggle / search box / incident  |
 |  - Explanation |     [SCREEN-4]  4 KPI cards                            |
 |    settings    |     [SCREEN-5]  analyst summary                        |
 |  - Attack      |     [SCREEN-6]  payload inspector (SQL / XSS / upload) |
 |    types       |     [SCREEN-7]  technique cards (CWE-89 / 79 / 434)    |
 |                |     [SCREEN-8..12] SQLi only: PSS heat-map, counterf., |
 |                |                 trust | class probabilities, SHAP, LIME|
 |                |     [SCREEN-13/14] expanders, JSON download            |
 |                |  🛡️ Live Detection        (tab_detection)              |
 |                |  ★ Explanation Trust      (tab_trust)  - SQLi N1-N5    |
 |                |  🌐 Global Explainability (tab_global)                 |
 |                |  📊 Model Performance     (tab_performance)            |
 +----------------+--------------------------------------------------------+
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# =============================================================================
# [NO SCREEN] CONNECT TO THE BACKEND
#   this page : dev/frontend/pages/com2_attack/
#   backend   : dev/backend/component2_xai/   (config, engines, styles)
# =============================================================================
BACKEND_DIR = Path(__file__).resolve().parents[3] / "backend" / "component2_xai"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import sqli_xai_config as C  # noqa: E402   -> file paths + model loading
import sqli_xai_engine as X  # noqa: E402   -> SQLi evidence XAI (PSS, SHAP, LIME, trust)
import sqli_xai_styles as S  # noqa: E402   -> colours, fonts, CSS
import web_injection_xai as W  # noqa: E402 -> XSS / upload features, labels, inspector, techniques

# --------------------------------------------------------------------------- #
# Theme — the page keeps its own blue & white look (sqli_xai_styles.py);
# these names mirror the DDoS pages so all Component-2 pages read the same way.
# --------------------------------------------------------------------------- #
THEME = {
    "text": S.COLORS["navy"],
    "muted": S.COLORS["muted"],
    "grid": S.COLORS["card_border"],
    "accent": S.COLORS["blue"],
    "attack": S.HEAT["towards_attack"],
    "normal": S.CHART["secondary"],
    "good": S.PILLS["green"][1],
    "warn": "#d48a00",
    "font": S.FONTS["body"],
}
OTHER = W.DISPLAY[W.OTHER]
TYPE_COLORS = {W.DISPLAY[W.SQLI]: W.INSPECT_COLORS["sql"], W.DISPLAY[W.XSS]: W.INSPECT_COLORS["xss"],
               W.DISPLAY[W.UPLOAD]: W.INSPECT_COLORS["upload"], OTHER: THEME["normal"]}
RISK_LEVELS = ["Low", "Elevated", "High", "Critical"]
RISK_COLORS = [THEME["good"], THEME["accent"], THEME["warn"], THEME["attack"]]
TRUST_COLORS = {"High": THEME["good"], "Medium": THEME["warn"], "Low": THEME["attack"], "Not assessed": THEME["muted"]}
IDS_URL = os.environ.get("XAI_IDS_URL", "http://127.0.0.1:5000").rstrip("/")

NOVELTY_CSS = f"""<style>
.xai-novelty {{background:{S.COLORS["card_bg"]};border:1px solid {S.COLORS["card_border"]};
  border-left:5px solid {S.COLORS["blue"]};border-radius:12px;padding:16px 20px;margin:4px 0 14px;color:{S.COLORS["text"]}}}
.xai-novelty .tag {{color:{THEME["warn"]};font-size:.75rem;font-weight:800;letter-spacing:.12em}}
.xai-novelty h3 {{margin:4px 0 6px}}
.xai-novelty p {{margin:0 0 8px;line-height:1.55}}
.xai-novelty .chips span {{display:inline-block;padding:3px 10px;margin:0 6px 6px 0;border-radius:999px;
  background:{S.COLORS["soft_bg"]};border:1px solid {S.COLORS["card_border"]};font-size:.8rem}}
</style>"""


def style_fig(fig: go.Figure, height: int = 340, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=THEME["font"], color=THEME["text"], size=12),
        showlegend=legend, legend=dict(orientation="h", y=1.1, x=0, bgcolor="rgba(0,0,0,0)"),
        title_font=dict(size=14),
    )
    fig.update_xaxes(gridcolor=THEME["grid"], zerolinecolor=THEME["grid"])
    fig.update_yaxes(gridcolor=THEME["grid"], zerolinecolor=THEME["grid"])
    return fig


def card(label: str, value: str, sub: str = "") -> None:
    st.metric(label, value)
    if sub:
        st.caption(sub)


def section(title: str) -> None:
    st.markdown(S.section_title(title), unsafe_allow_html=True)


def bar_h(labels, values, title: str, color, text=None, height: int = 300) -> go.Figure:
    """Horizontal bars with values written beside them (readable even when one bar dominates)."""
    fig = go.Figure(go.Bar(x=values, y=labels, orientation="h", marker=dict(color=color, cornerradius=4),
                           text=text, textposition="outside", cliponaxis=False,
                           textfont=dict(color=THEME["text"])))
    top = max([v for v in values if v is not None] or [1])
    fig.update_layout(title=title, xaxis_range=[0, top * 1.3 or 1], bargap=0.35)
    fig.update_yaxes(autorange="reversed", showgrid=False)
    return style_fig(fig, height, legend=False)


def inspector_legend() -> str:
    return ('<div class="legend">' + "".join(
        f'<span style="background:{W.INSPECT_COLORS[k]}">{lab}</span>'
        for k, lab in (("sql", "SQL injection evidence"), ("xss", "XSS evidence"), ("upload", "upload / web-shell evidence")))
        + "</div>")


# =============================================================================
# [NO SCREEN] Data / model loading (cached)
# =============================================================================
@st.cache_data(show_spinner="Loading dataset...")
def load_csv(source) -> pd.DataFrame:
    """Read the dataset CSV once and cache it (fast reloads)."""
    return pd.read_csv(source, low_memory=False)


@st.cache_data(show_spinner="Extracting SQL / XSS / upload features from every request...", max_entries=2)
def features_all(_df: pd.DataFrame, feature_names: tuple, key: tuple) -> pd.DataFrame:
    return W.build_matrix(_df, list(feature_names))


@st.cache_data(show_spinner="Scoring every request with the web-injection model...", max_entries=4)
def score_all(_model, _df: pd.DataFrame, _Xa: pd.DataFrame, key: tuple) -> pd.DataFrame:
    """One row per record: class probabilities, most likely attack type, risk level. Cached per key."""
    P = np.asarray(_model.predict_proba(_Xa))
    classes = [str(c) for c in _model.classes_]
    out = pd.DataFrame(index=_df.index)
    res = X.ColumnResolver(_df.columns)
    if res.id_col:
        out["incident_id"] = _df[res.id_col].astype(str).values
    atk = [c for c in W.ATTACK_TYPES if c in classes]
    pa = P[:, [classes.index(c) for c in atk]]
    out["attack_probability"] = pa.max(axis=1)
    out["attack_type"] = [W.DISPLAY[atk[i]] for i in pa.argmax(axis=1)]
    for c in atk:
        out[f"P({W.DISPLAY[c]})"] = P[:, classes.index(c)]
    out["risk_level"] = pd.cut(out["attack_probability"], [-0.01, 0.3, 0.5, 0.8, 1.01], labels=RISK_LEVELS).astype(str)
    for col in ("ip.src_host", "http.request.method", "http.request.full_uri", "http.content_length"):
        if col in _df.columns:
            out[col] = _df[col].astype(str).values
    labels = W.web_labels(_df)
    if labels is not None:
        out["actual"] = labels.map(W.DISPLAY).values
    return out


@st.cache_data(show_spinner=False, max_entries=4)
def candidates(_df: pd.DataFrame, key: tuple) -> pd.Series:
    return W.candidate_mask(_df)


@st.cache_resource(show_spinner=False)
def tree_explainer(_model, key: str):
    try:
        import shap
    except ImportError:
        return None
    return shap.TreeExplainer(_model)


def with_verdicts(scored: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """Threshold-dependent columns (cheap; recomputed when the slider moves)."""
    out = scored.copy()
    out["is_attack"] = out["attack_probability"] >= threshold
    out.insert(2, "prediction", np.where(out["is_attack"], out["attack_type"], OTHER))
    return out


def priority_for(p: float, techniques: list) -> dict:
    """Same rule as the SQLi engine: probability x worst technique severity."""
    sev = max((t["severity"] for t in techniques), default=0.3)
    score = p * sev
    level = "Critical" if score >= 0.75 else "High" if score >= 0.55 else "Medium" if score >= 0.3 else "Low"
    return {"score": float(score), "level": level, "max_technique_severity": sev, "note": ""}


# =============================================================================
# 🔎 Incident XAI — one incident explained end-to-end
# =============================================================================
def tab_incident(engine: X.SQLiXAIEngine, model, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
                 types: list, use_shap: bool, use_lime: bool, threshold: float, model_key: str) -> None:
    res = engine.resolver(df.columns)
    # [NO SCREEN] the IDS opens this page as ?incident=ALR-000024 -> select it once
    incoming_id = st.query_params.get("incident", "").strip()
    if incoming_id and st.session_state.get("_applied_incident") != incoming_id:
        st.session_state["_applied_incident"] = incoming_id
        st.session_state["incident_select"] = incoming_id

    # =========================================================================
    # [SCREEN-3] filter toggle, Incident ID search box, incident dropdown + IDS button
    # =========================================================================
    only_candidates = st.toggle("Show only requests containing SQL / XSS / upload-like text", True,
                                key="sqli_only_candidates",
                                help="Fast text pre-filter to find interesting incidents. It is not a classifier.")
    view = scored[cand] if only_candidates else scored
    view = view[view["attack_type"].isin(types) | ~view["is_attack"]] if types else view
    view = view.sort_values("attack_probability", ascending=False, kind="stable")
    search = st.text_input("Search Incident ID (optional)", placeholder="e.g. ALR-000024", key="sqli_incident_search")
    ids = view["incident_id"]
    if search:
        ids = ids[ids.str.contains(search.strip(), case=False, regex=False)]
    options = ids.drop_duplicates().head(5000).tolist()
    all_ids = scored["incident_id"]
    # the incident sent by the IDS stays listed even if the filter hides it (but a search narrows it)
    if incoming_id and not search and incoming_id not in options and (all_ids == incoming_id).any():
        options = [incoming_id] + options
    if not options:
        st.warning("No Incident ID matches the search." if search else "No incidents match the filter.")
        return
    if st.session_state.get("incident_select") not in options:
        st.session_state.pop("incident_select", None)
    id_to_row = dict(zip(all_ids, scored.index))

    def incident_label(i: str) -> str:
        r = scored.loc[id_to_row[i]]
        return f"{i} · {r['prediction']} · p={r['attack_probability']:.3f}"

    sel_col, btn_col = st.columns([4, 1], vertical_alignment="bottom")
    with sel_col:
        selected = st.selectbox(f"Incident ({len(options):,} shown, highest attack probability first)", options,
                                format_func=incident_label, key="incident_select")
    st.query_params["incident"] = selected
    st.session_state["_applied_incident"] = selected
    with btn_col:
        st.link_button("← Back to XAI IDS", f"{IDS_URL}/?incident={selected}", width="stretch")
    idx = id_to_row[selected]
    record, row = df.loc[idx], scored.loc[idx]
    view_req = res.view(record)
    attack_type, p_type = row["attack_type"], float(row["attack_probability"])
    is_sqli = row["prediction"] == W.DISPLAY[W.SQLI]

    # SQLi incidents get the full evidence engine; every incident gets class SHAP + web techniques
    e = None
    with st.spinner("Explaining incident..."):
        if is_sqli:
            e = engine.explain(record, incident_id=selected, use_shap=use_shap, use_lime=use_lime)
        techniques = W.all_techniques(view_req)
        x = W.build_matrix(df.loc[[idx]], engine.feature_names)
        cls_name = {v: k for k, v in W.DISPLAY.items()}[attack_type]
        cls_idx = [str(c) for c in model.classes_].index(cls_name)
        explainer = tree_explainer(model, model_key) if use_shap else None
        sv = W.class_shap(explainer, x, cls_idx)[0] if explainer is not None else None
    priority = e.priority if e else priority_for(p_type if row["is_attack"] else 0.0, techniques)

    # =========================================================================
    # [SCREEN-4] ROW OF 4 KPI CARDS: attack type | P(type) | priority | trust
    # =========================================================================
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        card("Model prediction", row["prediction"],
             f"dataset label: {row['actual']}" if "actual" in row else "no label in file")
    with c2:
        card(f"P({attack_type})", f"{p_type:.1%}", f"threshold {threshold:.2f}")
    with c3:
        card("Analyst priority", priority["level"], f"score {priority['score']:.2f}")
    with c4:
        if e:
            card("Explanation trust", e.trust["level"],
                 "score -" if e.trust["score"] is None else f"score {e.trust['score']:.2f}")
        else:
            card("Explanation trust", "n/a", "evidence trust score is defined for SQL injection")
    if e and e.priority.get("note"):
        st.warning(e.priority["note"])

    # [SCREEN-5] analyst summary
    if e:
        narrative = e.narrative
    else:
        top = (sorted(zip(engine.feature_names, sv), key=lambda kv: -kv[1])[:3] if sv is not None else [])
        tech_txt = "; ".join(f"{t['technique']} ({t['cwe']}, evidence: {t['evidence']})" for t in techniques[:3])
        narrative = (f"The model classifies this request as {row['prediction']} "
                     f"(P({attack_type}) = {p_type:.1%}). "
                     + (f"Rule evidence: {tech_txt}. " if tech_txt else "No XSS / upload technique pattern was found. ")
                     + ("Model features pushing towards " + attack_type + ": "
                        + ", ".join(f"{X.feature_label(f)} ({v:+.2f})" for f, v in top if v > 0) + "." if top else ""))
    st.markdown(S.narrative_box(narrative), unsafe_allow_html=True)
    st.write("")

    left, right = st.columns([1.15, 1], gap="large")
    with left:
        # [SCREEN-6] payload inspector (all three attack types)
        section("Payload inspector")
        st.markdown(inspector_legend(), unsafe_allow_html=True)
        st.markdown(S.heat_box(W.render_inspector_html(view_req)), unsafe_allow_html=True)
        cl = pd.to_numeric(pd.Series([record.get("http.content_length")]), errors="coerce").fillna(0).iloc[0]
        st.caption(f"Method {view_req.method or '-'} · content-length {cl:,.0f} · "
                   f"URL decoded {view_req.decode_rounds}× · rule highlights, not model attributions")

        # [SCREEN-7] technique cards (CWE-89 SQLi, CWE-79 XSS, CWE-434 upload)
        section("Attack technique profile")
        if techniques:
            for t in techniques:
                st.markdown(S.technique_card(t), unsafe_allow_html=True)
        else:
            st.info("No known SQLi / XSS / upload technique pattern in this request.")

        if e:
            # [SCREEN-8] SQLi: span heat-map from Payload-Span Shapley
            section("SQLi: where in the request the decision comes from")
            st.markdown(S.heat_legend(), unsafe_allow_html=True)
            st.markdown(S.heat_box(X.render_attribution_html(e)), unsafe_allow_html=True)
            st.caption("Payload-Span Shapley: each SQL evidence group is really removed from the request text, features "
                       "are re-extracted and the model is re-scored for every combination.")
            # [SCREEN-8b] minimal sanitisation counterfactual
            section("SQLi: minimal sanitisation counterfactual")
            cf = e.counterfactual
            if cf.get("found"):
                st.success("Removing only **" + "**, **".join(cf["removed_labels"]) +
                           f"** lowers P(SQL injection) to **{cf['probability_after']:.1%}** (below the threshold).")
                st.code(cf["sanitized_preview"], language="text")
            else:
                st.info(cf.get("reason", "Not available."))
            # [SCREEN-12] explanation trust breakdown
            section("SQLi: explanation trust breakdown")
            fmt = lambda v: "n/a" if v is None else f"{v:.2f}"  # noqa: E731
            trust_rows = [
                ("Rules ↔ PSS agreement", fmt(e.trust["rule_pss_agreement"]), "Do the rule-detected techniques match what drove the model?"),
                ("PSS ↔ SHAP agreement", fmt(e.trust["pss_shap_agreement"]), "Same top evidence groups?"),
                ("PSS ↔ LIME agreement", fmt(e.trust["pss_lime_agreement"]), "Same top evidence groups?"),
                ("Deletion fidelity gain", fmt(e.trust["fidelity_gain"]),
                 f"Removing top evidence drops P by {fmt(e.trust['deletion_drop_top'])} vs "
                 f"{fmt(e.trust['deletion_drop_random'])} for random characters"),
                ("Payload share", fmt(e.trust["payload_share"]), "Part of the attack probability explained by the payload text"),
            ]
            st.dataframe(pd.DataFrame(trust_rows, columns=["Check", "Value", "Meaning"]), hide_index=True, width="stretch")

    with right:
        # [SCREEN-9] class probabilities
        section("Attack-type probabilities")
        pcols = [c for c in scored.columns if c.startswith("P(")]
        names = [c[2:-1] for c in pcols]
        vals = [float(row[c]) for c in pcols]
        st.plotly_chart(bar_h(names, vals, "Model probability per attack type",
                              [TYPE_COLORS.get(n, THEME["accent"]) for n in names],
                              [f"{v:.1%}" for v in vals], height=220), width="stretch")
        # [SCREEN-10] SHAP for the most likely attack type
        if sv is not None:
            section(f"SHAP towards {attack_type} (model features)")
            sdf = (pd.DataFrame({"Feature": engine.feature_names, "SHAP value": sv,
                                 "group": [X.feature_family(f) for f in engine.feature_names]})
                   .assign(abs=lambda d: d["SHAP value"].abs()).sort_values("abs", ascending=False).head(12))
            fig = px.bar(sdf[::-1], x="SHAP value", y="Feature", color="group", orientation="h")
            st.plotly_chart(style_fig(fig, 380), width="stretch")
        elif use_shap:
            st.info("Install `shap` to see feature-level SHAP values.")
        if e and e.pss:
            # [SCREEN-11] SQLi Payload-Span Shapley + LIME
            section("SQLi: Payload-Span Shapley (evidence groups)")
            pss_df = pd.DataFrame({"Evidence group": [X.FAMILY_LABELS.get(k, k) for k in e.pss],
                                   "Shapley value": list(e.pss.values())}).sort_values("Shapley value", ascending=False)
            st.bar_chart(pss_df.set_index("Evidence group"), color=S.CHART["primary"])
            st.caption(f"P(SQL injection) with all payload evidence removed: {e.pss_base:.1%} → actual "
                       f"{e.attack_probability:.1%}. Values add up exactly to this difference.")
        if e and e.lime_weights:
            section("SQLi: LIME (local surrogate)")
            ldf = pd.DataFrame({"Feature": list(e.lime_weights), "LIME weight": list(e.lime_weights.values())})
            st.bar_chart(ldf.set_index("Feature")["LIME weight"], color=S.CHART["secondary"])

    # [SCREEN-13] collapsible sections
    with st.expander("Model input features for this incident"):
        st.dataframe(pd.DataFrame({"Feature": engine.feature_names, "Value": x.iloc[0].tolist(),
                                   "Group": [X.feature_family(f) for f in engine.feature_names]}),
                     hide_index=True, width="stretch")
    if e and e.messages:
        with st.expander("Diagnostics"):
            for m in e.messages:
                st.write("•", m)

    # [SCREEN-14] download JSON button + footer note
    report = json.loads(e.to_json()) if e else {}
    report.update({"incident_id": selected, "prediction": row["prediction"], "attack_type": attack_type,
                   "attack_probability": p_type, "class_probabilities": dict(zip(names, vals)),
                   "priority": priority, "techniques": techniques,
                   "shap_top": dict(sorted(zip(engine.feature_names, map(float, sv)), key=lambda kv: -abs(kv[1]))[:12])
                   if sv is not None else None})
    st.download_button("Download incident explanation (JSON)", json.dumps(report, indent=2, default=str),
                       file_name=f"web_injection_xai_{selected}.json", mime="application/json")
    st.caption("All probabilities and attributions come from the loaded model; highlights and technique cards are "
               "rule-based evidence. Explanations describe model behaviour; they do not prove an attack succeeded.")


# =============================================================================
# 🛡️ Live Detection — the whole dataset scored at once
# =============================================================================
def _uri_path(uri: str) -> str:
    m = re.match(r"https?://[^/]+(/[^?]*)", str(uri))
    return m.group(1) if m else ""


def tab_detection(scored: pd.DataFrame, cand: pd.Series, threshold: float) -> None:
    flagged = scored[scored["is_attack"]]
    counts = flagged["prediction"].value_counts()
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        card("Requests analysed", f"{len(scored):,}", f"{int(cand.sum()):,} with SQL / XSS / upload-like text")
    for col, t in zip((c2, c3, c4), W.ATTACK_TYPES):
        with col:
            card(W.DISPLAY[t], f"{int(counts.get(W.DISPLAY[t], 0)):,}", "flagged requests")
    with c5:
        if "actual" in scored.columns:
            card("Agreement with labels", f"{(scored['prediction'] == scored['actual']).mean():.2%}",
                 "label rules from the model card")
        else:
            card("Agreement with labels", "—", "no labels in file")

    c1, c2, c3 = st.columns(3)
    with c1:
        mix = scored["risk_level"].value_counts().reindex(RISK_LEVELS).fillna(0).astype(int)
        share = mix / max(int(mix.sum()), 1)
        st.plotly_chart(bar_h(RISK_LEVELS, mix.tolist(), "Risk levels", RISK_COLORS,
                              [f"{n:,} · {s:.1%}" for n, s in zip(mix, share)]), width="stretch")
    with c2:
        if "ip.src_host" in flagged.columns and not flagged.empty:
            top = flagged["ip.src_host"].value_counts().head(6)
            st.plotly_chart(bar_h(top.index.tolist(), top.tolist(), "Top attacking source IPs", THEME["attack"],
                                  [f"{n:,}" for n in top]), width="stretch")
        else:
            st.info("No requests flagged — no source IPs to rank.")
    with c3:
        if "http.request.full_uri" in flagged.columns and not flagged.empty:
            paths = flagged["http.request.full_uri"].map(_uri_path).replace("", "(no URI)").value_counts().head(6)
            st.plotly_chart(bar_h(paths.index.tolist(), paths.tolist(), "Most targeted endpoints", THEME["accent"],
                                  [f"{n:,}" for n in paths]), width="stretch")

    # content-length outlier chart (HTTP requests only)
    section("Content-length outliers (HTTP requests)")
    if "http.content_length" in scored.columns and "http.request.method" in scored.columns:
        req = scored[~scored["http.request.method"].isin(["", "0", "0.0", "nan"])].copy()
        req["content_length"] = pd.to_numeric(req["http.content_length"], errors="coerce").fillna(0)
        if not req.empty:
            base = req.loc[req["prediction"] == OTHER, "content_length"]
            base = base if len(base) >= 10 else req["content_length"]
            q1, q3 = base.quantile([0.25, 0.75])
            fence = q3 + 1.5 * (q3 - q1)
            req["outlier"] = req["content_length"] > fence
            fig = px.strip(req, x="prediction", y="content_length", color="prediction",
                           color_discrete_map=TYPE_COLORS, hover_data=["incident_id", "attack_probability"],
                           category_orders={"prediction": [OTHER] + [W.DISPLAY[t] for t in W.ATTACK_TYPES]})
            fig.add_hline(y=fence, line_dash="dash", line_color=THEME["warn"],
                          annotation_text=f"outlier fence {fence:,.0f} (Q3 + 1.5·IQR of non-attack requests)")
            fig.update_layout(xaxis_title="", yaxis_title="http.content_length (bytes)")
            st.plotly_chart(style_fig(fig, 340, legend=False), width="stretch")
            out = req[req["outlier"]]
            st.caption(f"{len(out):,} of {len(req):,} HTTP requests exceed the fence; "
                       f"{int(out['is_attack'].sum()):,} of them are flagged as web injection.")

    section("Suspicious requests")
    only_flagged = st.toggle("Show flagged requests only", value=True, key="sqli_only_flagged")
    view = (flagged if only_flagged else scored[cand]).sort_values("attack_probability", ascending=False, kind="stable")
    st.dataframe(view.drop(columns=["is_attack"]).head(5000), width="stretch", height=360, hide_index=True,
                 column_config={"attack_probability": st.column_config.ProgressColumn(
                     "P(attack type)", min_value=0.0, max_value=1.0, format="%.3f")})
    st.download_button("Download verdicts (CSV)", view.to_csv(index=False).encode(), "web_injection_verdicts.csv",
                       "text/csv")


# =============================================================================
# ★ Explanation Trust — NOVELTY (SQLi: N3 trust score, N4 counterfactual, N5 techniques) over many incidents
# =============================================================================
@st.cache_data(show_spinner=False, max_entries=4)
def trust_triage(_engine: X.SQLiXAIEngine, _df: pd.DataFrame, index: tuple, use_shap: bool, key: tuple) -> pd.DataFrame:
    rows = []
    for i in index:
        e = _engine.explain(_df.loc[i], use_shap=use_shap, use_lime=False)
        r = e.summary_row()
        r.update(priority_level=e.priority["level"], max_technique_severity=e.priority["max_technique_severity"])
        rows.append(r)
    return pd.DataFrame(rows)


def novelty_banner() -> None:
    st.markdown(NOVELTY_CSS + """<div class="xai-novelty">
      <div class="tag">★ NOVELTY · COMPONENT 2 · SQL INJECTION</div>
      <h3>Evidence-Grounded Explanation Trust</h3>
      <p>Every flagged SQL-injection request is explained by <b>Payload-Span Shapley</b> (evidence groups are really
      removed from the request text and the model is re-scored), cross-checked against <b>rule-detected SQLi
      techniques</b> and <b>SHAP</b>, and stress-tested with a <b>deletion test</b> against random characters. The
      result is an <b>Explanation Trust Score</b> per incident: low-trust verdicts go to analyst review instead of
      automatic blocking. XSS and upload incidents are explained with SHAP + rule evidence in the 🔎 Incident XAI tab.</p>
      <div class="chips"><span>N1 · Payload-Span Shapley</span><span>N2 · Span heat-map</span>
      <span>N3 · Explanation Trust Score</span><span>N4 · Minimal sanitisation counterfactual</span>
      <span>N5 · Technique profile (CWE-89 · CAPEC-66/7 · T1190)</span></div>
    </div>""", unsafe_allow_html=True)


def tab_trust(engine: X.SQLiXAIEngine, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
              use_shap: bool, key: tuple) -> None:
    novelty_banner()
    flagged = scored[scored["is_attack"] & (scored["prediction"] == W.DISPLAY[W.SQLI]) & cand]
    flagged = flagged.sort_values("attack_probability", ascending=False, kind="stable")
    if flagged.empty:
        st.info("No SQL-injection requests are flagged at the current threshold.")
        return
    n = st.slider("Flagged SQLi incidents to triage (highest probability first)", 10, min(200, max(len(flagged), 10)),
                  min(40, len(flagged)), 10, key="sqli_triage_n",
                  help="Each incident gets the full PSS + trust + counterfactual explanation (LIME off here for "
                       "speed). Results are cached.")
    idx = tuple(flagged.index[:n])
    with st.spinner(f"Explaining {len(idx)} flagged SQLi incidents (PSS, trust, counterfactual, techniques)..."):
        tri = trust_triage(engine, df, idx, use_shap, key)

    counts = tri["trust_level"].value_counts()
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        card("Mean trust score", f"{tri['trust_score'].mean():.2f}", f"{len(tri)} incidents")
    for col, lvl, sub in [(k2, "High", "safe to act"), (k3, "Medium", "corroborate"),
                          (k4, "Low", f"analyst review · {int(counts.get('Not assessed', 0))} not assessed")]:
        with col:
            card(f"{lvl} trust", f"{int(counts.get(lvl, 0)):,}", sub)
    with k5:
        card("Counterfactual found", f"{tri['counterfactual_found'].mean():.0%}",
             "decision flips by sanitising payload only")

    c1, c2 = st.columns(2)
    with c1:
        fig = px.histogram(tri, x="trust_score", color="trust_level", nbins=20, color_discrete_map=TRUST_COLORS,
                           title="Explanation trust of flagged SQLi incidents")
        st.plotly_chart(style_fig(fig, 320), width="stretch")
    with c2:
        fig = px.scatter(tri, x="attack_probability", y="trust_score", color="trust_level",
                         color_discrete_map=TRUST_COLORS, hover_data=["incident_id", "techniques"],
                         title="Model confidence vs. explanation trust")
        st.plotly_chart(style_fig(fig, 320), width="stretch")

    c1, c2 = st.columns(2)
    with c1:
        tech = tri["techniques"].str.split("; ").explode().replace("", np.nan).dropna().value_counts()
        if not tech.empty:
            st.plotly_chart(bar_h(tech.index.tolist(), tech.tolist(), "SQLi techniques detected", THEME["attack"],
                                  [f"{v:,}" for v in tech]), width="stretch")
    with c2:
        fam = tri["pss_top_family"].replace("", np.nan).dropna().map(lambda k: X.FAMILY_LABELS.get(k, k)).value_counts()
        if not fam.empty:
            st.plotly_chart(bar_h(fam.index.tolist(), fam.tolist(), "Top Payload-Span Shapley evidence group",
                                  THEME["accent"], [f"{v:,}" for v in fam]), width="stretch")

    section("Escalated for analyst review (low explanation trust)")
    st.caption(f"{int((tri['trust_level'] == 'Low').sum()):,} of {len(tri):,} triaged incidents. "
               "Open one in the 🔎 Incident XAI tab by searching its ID.")
    st.dataframe(tri.sort_values("trust_score"), width="stretch", hide_index=True, height=320,
                 column_config={"trust_score": st.column_config.ProgressColumn(
                     "trust", min_value=0.0, max_value=1.0, format="%.2f")})
    st.download_button("Download trust triage (CSV)", tri.to_csv(index=False).encode(), "sqli_trust_triage.csv", "text/csv")


# =============================================================================
# 🌐 Global Explainability — what the model relies on, per attack type
# =============================================================================
@st.cache_data(show_spinner=False, max_entries=4)
def technique_profile(_df: pd.DataFrame, key: tuple) -> pd.DataFrame:
    res = X.ColumnResolver(_df.columns)
    rows = []
    for r in _df.to_dict("records"):
        for t in W.all_techniques(res.view(r)):
            rows.append({k: t[k] for k in ("technique", "cwe", "capec", "attack", "severity")})
    return pd.DataFrame(rows)


@st.cache_data(show_spinner="Computing global SHAP per attack type...", max_entries=4)
def global_class_shap(_explainer, _X: pd.DataFrame, classes: tuple, key: tuple) -> pd.DataFrame:
    rows = []
    for cls in W.ATTACK_TYPES:
        if cls in classes:
            v = np.abs(W.class_shap(_explainer, _X, list(classes).index(cls))).mean(axis=0)
            rows.append(pd.DataFrame({"feature": _X.columns, "mean |SHAP|": v, "attack type": W.DISPLAY[cls]}))
    return pd.concat(rows, ignore_index=True)


def tab_global(model, Xa: pd.DataFrame, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
               use_shap: bool, model_key: str, key: tuple) -> None:
    feats = list(Xa.columns)
    family = {f: X.feature_family(f) for f in feats}
    c1, c2 = st.columns(2)
    with c1:
        imp = getattr(model, "feature_importances_", None)
        if imp is not None:
            gi = pd.DataFrame({"feature": feats, "importance": imp, "group": [family[f] for f in feats]})
            gi = gi.sort_values("importance", ascending=False).head(15)
            fig = px.bar(gi, x="importance", y="feature", color="group", orientation="h",
                         title="Model feature importance (Gini, top 15)")
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(style_fig(fig, 460), width="stretch")
    with c2:
        explainer = tree_explainer(model, model_key) if use_shap else None
        if explainer is not None:
            flagged = scored[scored["is_attack"]].index[:600]
            sample = Xa.loc[flagged.union(scored.index.to_series().sample(min(400, len(scored)), random_state=42).index)]
            gs = global_class_shap(explainer, sample, tuple(str(c) for c in model.classes_), key)
            top = gs.groupby("feature")["mean |SHAP|"].sum().sort_values(ascending=False).head(12).index
            fig = px.bar(gs[gs["feature"].isin(top)], x="mean |SHAP|", y="feature", color="attack type",
                         orientation="h", color_discrete_map=TYPE_COLORS, barmode="group",
                         category_orders={"feature": list(top)},
                         title=f"Mean |SHAP| per attack type ({len(sample):,} requests: flagged + random)")
            st.plotly_chart(style_fig(fig, 460), width="stretch")
        else:
            st.info("Turn on **Compute SHAP** in the sidebar (and install `shap`) to see global SHAP per attack type.")

    section("Technique profile of flagged traffic (CWE-89 SQLi · CWE-79 XSS · CWE-434 upload)")
    flagged = scored[scored["is_attack"]]
    tp = technique_profile(df.loc[flagged.index[cand[flagged.index] | (flagged["prediction"] == W.DISPLAY[W.UPLOAD])]],
                           key) if not flagged.empty else pd.DataFrame()
    if tp.empty:
        st.info("No technique patterns found in the flagged requests.")
        return
    summary = (tp.groupby(["technique", "cwe", "capec", "attack"]).agg(requests=("severity", "size"),
                                                                      severity=("severity", "max"))
               .reset_index().sort_values("requests", ascending=False))
    c1, c2 = st.columns([1, 1.2])
    with c1:
        colors = [W.INSPECT_COLORS["sql"] if c == "CWE-89" else W.INSPECT_COLORS["xss"] if c == "CWE-79"
                  else W.INSPECT_COLORS["upload"] for c in summary["cwe"]]
        st.plotly_chart(bar_h(summary["technique"].tolist(), summary["requests"].tolist(),
                              f"Techniques in {len(flagged):,} flagged requests", colors,
                              [f"{v:,}" for v in summary["requests"]], height=420), width="stretch")
    with c2:
        st.dataframe(summary.rename(columns={"attack": "MITRE ATT&CK"}), width="stretch", hide_index=True,
                     column_config={"severity": st.column_config.ProgressColumn(
                         "max severity", min_value=0.0, max_value=1.0, format="%.2f")})


# =============================================================================
# 📊 Model Performance — multi-class scores vs. the label rules
# =============================================================================
@st.cache_data(show_spinner=False, max_entries=8)
def performance(_y: pd.Series, _pred: pd.Series, order: tuple, key: tuple) -> tuple[float, float, dict, np.ndarray]:
    """Accuracy, macro-F1, per-class report and confusion matrix (cached: 126k string labels are slow)."""
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
    labels = list(order)
    return (accuracy_score(_y, _pred), f1_score(_y, _pred, labels=labels, average="macro", zero_division=0),
            classification_report(_y, _pred, labels=labels, output_dict=True, zero_division=0),
            confusion_matrix(_y, _pred, labels=labels))


def tab_performance(scored: pd.DataFrame, key: tuple) -> None:
    model_card = json.loads(C.WEB_MODEL_CARD.read_text()) if C.WEB_MODEL_CARD.exists() else None
    if "actual" not in scored.columns:
        st.info("The dataset has no `Attack_label` / request columns, so performance can't be measured.")
    else:
        order = [OTHER] + [W.DISPLAY[t] for t in W.ATTACK_TYPES]
        acc, macro, rep, cm = performance(scored["actual"], scored["prediction"], tuple(order), key)
        cols = st.columns(5)
        with cols[0]:
            card("Accuracy", f"{acc:.4f}")
        with cols[1]:
            card("Macro F1", f"{macro:.4f}")
        for col, t in zip(cols[2:], W.ATTACK_TYPES):
            with col:
                card(f"F1 · {W.DISPLAY[t]}", f"{rep[W.DISPLAY[t]]['f1-score']:.4f}",
                     f"P {rep[W.DISPLAY[t]]['precision']:.3f} · R {rep[W.DISPLAY[t]]['recall']:.3f}")
        st.caption("Measured on the loaded dataset with the label rules from the model card. The delivered model was "
                   "refit on all rows, so these are in-sample scores; see the model card for the 20% hold-out.")
        c1, c2 = st.columns([1.1, 1])
        with c1:
            fig = go.Figure(go.Heatmap(z=np.log10(cm + 1), x=[f"Pred {c}" for c in order], y=[f"True {c}" for c in order],
                                       text=cm, texttemplate="%{text:,}", showscale=False,
                                       colorscale=[[0, S.COLORS["soft_bg"]], [1, THEME["accent"]]]))
            fig.update_yaxes(autorange="reversed")
            fig.update_layout(title="Confusion matrix (colour = log count)")
            st.plotly_chart(style_fig(fig, 380, legend=False), width="stretch")
        with c2:
            section("Classification report")
            st.dataframe(pd.DataFrame(rep).T.style.format("{:.4f}"), width="stretch")
    if model_card:
        with st.expander("Model card (web_injection_model_card.json)", expanded="actual" not in scored.columns):
            st.json(model_card)


# =============================================================================
# Page
# =============================================================================
def main() -> None:
    st.set_page_config(page_title="Web Injection XAI", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="expanded")
    S.apply_theme(st)

    # =========================================================================
    # [SCREEN-1] SIDEBAR - uploads + explanation settings (same layout as the DDoS pages)
    # =========================================================================
    with st.sidebar:
        st.header("Inputs")
        data_up = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="d")
        model_up = st.file_uploader("Trained web-injection model (.pkl)", type=["pkl", "pickle"], key="m")
        feat_up = st.file_uploader("Feature columns (.pkl, optional)", type=["pkl", "pickle"], key="f")
        st.caption("Only load pickle files you trust - loading a pickle can run code.")
        st.header("Explanation settings")
        bg_size = st.slider("Background sample (rows)", 100, 1000, 300, 50,
                            help="Real dataset rows used by LIME and the random-deletion baseline.")
        use_shap = st.toggle("Compute SHAP", True)
        use_lime = st.toggle("Compute LIME", True)
        threshold = st.slider("Decision threshold", 0.1, 0.9, 0.5, 0.05,
                              help="Requests whose most likely attack type has P ≥ threshold are flagged; also used "
                                   "by the SQLi sanitisation counterfactual.")

    # [NO SCREEN] load dataset
    dataset_path = C.first_existing(C.DATASET_PATHS)
    if data_up is not None:
        df, data_name = load_csv(data_up), data_up.name
    elif dataset_path:
        df, data_name = load_csv(str(dataset_path)), dataset_path.name
    else:
        st.error("Dataset not found. Upload it in the sidebar or place it at:")
        st.code(str(C.DATASET_PATHS[0]))
        st.stop()

    # [NO SCREEN] load model + feature list
    try:
        model = C.load_artifact(model_up or C.first_existing(C.WEB_MODEL_PATHS))
        feature_names = C.load_artifact(feat_up or C.first_existing(C.WEB_FEATURE_PATHS)) or W.WEB_FEATURES
    except Exception as exc:
        st.error(f"Could not load model/feature file: {type(exc).__name__}: {exc}")
        st.stop()
    if model is None:
        st.warning(f"No web-injection model found in {C.MODEL_DIR}. Build it with "
                   "`python backend/component2_xai/model/train_web_injection_rf.py` (from dev/) or upload "
                   "`web_injection_rf.pkl` in the sidebar. This page never shows explanations without a real model.")
        st.stop()
    classes = [str(c) for c in getattr(model, "classes_", [])]
    if W.SQLI not in classes:
        st.error(f"The model's classes {classes} don't include '{W.SQLI}'. Upload the multi-class web-injection model.")
        st.stop()

    # [SCREEN-1] SIDEBAR (bottom) - attack types to list
    with st.sidebar:
        types = st.multiselect("Attack types to list", [W.DISPLAY[t] for t in W.ATTACK_TYPES if t in classes],
                               default=[W.DISPLAY[t] for t in W.ATTACK_TYPES if t in classes],
                               help="Filters the incident list; scoring always uses every class.")

    # [NO SCREEN] build the SQLi evidence engine over the multi-class model (rebuilt only when inputs change)
    model_key = getattr(model_up, "name", "default-model")
    data_key = (data_name, len(df))
    signature = data_key + (model_key, str(feature_names)[:200], bg_size)
    if st.session_state.get("engine_sig") != signature:
        try:
            with st.spinner("Building explanation engine and background sample..."):
                background = W.build_matrix(df.sample(min(bg_size, len(df)), random_state=42), feature_names)
                engine = W.make_sqli_engine(model, feature_names, background=background, threshold=threshold)
        except Exception as exc:
            st.error(f"Could not build the explanation engine: {type(exc).__name__}: {exc}")
            st.stop()
        st.session_state.update(engine=engine, engine_sig=signature)
    engine: X.SQLiXAIEngine = st.session_state["engine"]
    engine.threshold = threshold       # used by the counterfactual; no rebuild needed

    # [SCREEN-2] page title + dataset info line
    st.markdown(S.page_header(
        "Web Injection - Evidence-Grounded Hybrid XAI (SQLi · XSS · Upload)",
        f"Dataset {data_name} · {len(df):,} rows · model classes: {', '.join(classes)} · "
        f"SHAP {'on' if use_shap else 'off'} · LIME {'on' if use_lime else 'off'}"), unsafe_allow_html=True)

    # score once per (data, model); verdicts follow the threshold slider
    score_key = data_key + (model_key, str(feature_names)[:200])
    Xa = features_all(df, tuple(feature_names), data_key)
    scored = with_verdicts(score_all(model, df, Xa, score_key), threshold)
    if "incident_id" not in scored.columns:
        st.error("No Incident ID column found (expected 'Incident_ID').")
        st.stop()
    cand = candidates(df, data_key)

    t0, t1, t2, t3, t4 = st.tabs(["🔎 Incident XAI", "🛡️ Live Detection", "★ Explanation Trust (SQLi)",
                                  "🌐 Global Explainability", "📊 Model Performance"])
    with t0:
        tab_incident(engine, model, df, scored, cand, types, use_shap, use_lime, threshold, model_key)
    with t1:
        tab_detection(scored, cand, threshold)
    with t2:
        tab_trust(engine, df, scored, cand, use_shap, signature)   # the triaged ids are part of the cache key
    with t3:
        tab_global(model, Xa, df, scored, cand, use_shap, model_key, score_key + (threshold,))
    with t4:
        tab_performance(scored, score_key + (threshold,))


main()
