"""
Component 2 - Evidence-Grounded Hybrid XAI for SQL Injection (Streamlit page - FRONTEND)

FILE LOCATION : dev/frontend/pages/com2_attack/sqli_xai_novelty_page.py
BACKEND FILES : dev/backend/component2_xai/
                sqli_xai_config.py  (file paths: dataset, model, outputs)
                sqli_xai_engine.py  (XAI logic)
                sqli_xai_styles.py  (colours, fonts, CSS)
DATASET       : dev/data/EdgeIIoT_train_80_with_incident_id.csv
MODEL         : dev/backend/component2_xai/model/sql_injection_rf.pkl (+ sql_feature_columns.pkl)

Same architecture as the DDoS HTTP Flood page (ddos_http.py):
  theme + chart helpers -> cached loaders -> one function per tab -> main()
  Tabs: Incident XAI | Live Detection | ★ Explanation Trust | Global Explainability | Model Performance

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
 |  - Attack      |     [SCREEN-6..12] heat-map, techniques, counterfact., |
 |    class       |                 trust table | PSS, SHAP, LIME charts   |
 |                |     [SCREEN-13/14] expanders, JSON download            |
 |                |  🛡️ Live Detection        (tab_detection)              |
 |                |  ★ Explanation Trust      (tab_trust)  - novelty N3-N5 |
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
#   backend   : dev/backend/component2_xai/   (config, engine, styles)
# =============================================================================
BACKEND_DIR = Path(__file__).resolve().parents[3] / "backend" / "component2_xai"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import sqli_xai_config as C  # noqa: E402   -> file paths + model loading
import sqli_xai_engine as X  # noqa: E402   -> XAI logic (model, PSS, SHAP, LIME, trust)
import sqli_xai_styles as S  # noqa: E402   -> colours, fonts, CSS

# --------------------------------------------------------------------------- #
# Theme — the SQLi page keeps its own blue & white look (sqli_xai_styles.py);
# these names mirror ddos_http.py so both pages read the same way.
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
ATTACK, NORMAL = "SQL injection", "Not SQLi"
CLASS_COLORS = {ATTACK: THEME["attack"], NORMAL: THEME["normal"]}
RISK_LEVELS = ["Low", "Elevated", "High", "Critical"]
RISK_COLORS = [THEME["good"], THEME["accent"], THEME["warn"], THEME["attack"]]
TRUST_COLORS = {"High": THEME["good"], "Medium": THEME["warn"], "Low": THEME["attack"], "Not assessed": THEME["muted"]}
IDS_URL = os.environ.get("XAI_IDS_URL", "http://127.0.0.1:5000").rstrip("/")
# Label rule used to build sql_injection_rf.pkl (see model/sql_model_card.json).
LABEL_URI_REGEX = r"/vulnerabilities/sqli"

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


# =============================================================================
# [NO SCREEN] Data / model loading (cached)
# =============================================================================
@st.cache_data(show_spinner="Loading dataset...")
def load_csv(source) -> pd.DataFrame:
    """Read the dataset CSV once and cache it (fast reloads)."""
    return pd.read_csv(source, low_memory=False)


@st.cache_data(show_spinner="Scoring every request with the SQLi model...", max_entries=4)
def score_all(_engine: X.SQLiXAIEngine, _df: pd.DataFrame, key: tuple) -> pd.DataFrame:
    """One row per dataset record: P(attack), verdict, risk level + context columns. Cached per key."""
    p = _engine._proba(_engine.build_feature_matrix(_df))[:, _engine.attack_idx]
    res = _engine.resolver(_df.columns)
    out = pd.DataFrame({"attack_probability": p}, index=_df.index)
    out["risk_level"] = pd.cut(p, [-0.01, 0.3, 0.5, 0.8, 1.01], labels=RISK_LEVELS).astype(str)
    if res.id_col:
        out.insert(0, "incident_id", _df[res.id_col].astype(str).values)
    for col in ("ip.src_host", "http.request.method", "http.request.full_uri"):
        if col in _df.columns:
            out[col] = _df[col].astype(str).values
    labels = sqli_labels(_df)
    if labels is not None:
        out["actual"] = np.where(labels, ATTACK, NORMAL)
    return out


@st.cache_data(show_spinner=False, max_entries=4)
def candidates(_df: pd.DataFrame, key: tuple) -> pd.Series:
    return X.candidate_mask(_df)


def sqli_labels(df: pd.DataFrame) -> pd.Series | None:
    """Ground truth used to train the model: Attack_label == 1 AND URI targets DVWA's SQLi page."""
    if "Attack_label" not in df.columns or "http.request.full_uri" not in df.columns:
        return None
    attack = pd.to_numeric(df["Attack_label"], errors="coerce").fillna(0).astype(int) == 1
    return attack & df["http.request.full_uri"].astype(str).str.contains(LABEL_URI_REGEX, case=False, regex=True)


def with_verdicts(scored: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """Threshold-dependent columns (cheap; recomputed when the slider moves)."""
    out = scored.copy()
    out["is_attack"] = out["attack_probability"] >= threshold
    out.insert(2, "prediction", np.where(out["is_attack"], ATTACK, NORMAL))
    return out


# =============================================================================
# 🔎 Incident XAI — one incident explained end-to-end (unique SQLi evidence view)
# =============================================================================
def tab_incident(engine: X.SQLiXAIEngine, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
                 use_shap: bool, use_lime: bool, threshold: float) -> None:
    res = engine.resolver(df.columns)
    if not res.id_col:
        st.error("No Incident ID column found (expected 'Incident_ID').")
        return

    # [NO SCREEN] the IDS opens this page as ?incident=ALR-000024 -> select it once
    incoming_id = st.query_params.get("incident", "").strip()
    if incoming_id and st.session_state.get("_applied_incident") != incoming_id:
        st.session_state["_applied_incident"] = incoming_id
        st.session_state["incident_select"] = incoming_id

    # =========================================================================
    # [SCREEN-3] filter toggle, Incident ID search box, incident dropdown + IDS button
    # =========================================================================
    only_candidates = st.toggle("Show only requests containing SQL-like text", True, key="sqli_only_candidates",
                                help="Fast text pre-filter to find interesting incidents. It is not a classifier.")
    view = scored[cand] if only_candidates else scored
    if view.empty:
        st.warning("No incidents match the filter.")
        return
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
    # keep the URL in sync (shareable, refresh-safe) without re-triggering the IDS link above
    st.query_params["incident"] = selected
    st.session_state["_applied_incident"] = selected
    with btn_col:
        st.link_button("← Back to XAI IDS", f"{IDS_URL}/?incident={selected}", width="stretch")
    record = df.loc[id_to_row[selected]]

    with st.spinner("Explaining incident (PSS, SHAP, LIME, trust, counterfactual)..."):
        e = engine.explain(record, incident_id=selected, use_shap=use_shap, use_lime=use_lime)

    # =========================================================================
    # [SCREEN-4] ROW OF 4 KPI CARDS: prediction | P(attack) | priority | trust
    # =========================================================================
    actual = scored.loc[id_to_row[selected]].get("actual")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        card("Model prediction", ATTACK if e.is_attack else NORMAL,
             f"dataset label: {actual}" if actual else "no label in file")
    with c2:
        card(f"P({e.attack_class})", f"{e.attack_probability:.1%}", f"threshold {threshold:.2f}")
    with c3:
        card("Analyst priority", e.priority["level"], f"score {e.priority['score']:.2f}")
    with c4:
        card("Explanation trust", e.trust["level"],
             "score -" if e.trust["score"] is None else f"score {e.trust['score']:.2f}")
    if e.priority.get("note"):
        st.warning(e.priority["note"])

    # [SCREEN-5] "Analyst summary" narrative box (full width)
    st.markdown(S.narrative_box(e.narrative), unsafe_allow_html=True)
    st.write("")

    left, right = st.columns([1.15, 1], gap="large")
    with left:
        # [SCREEN-6] payload heat-map (red/blue highlighted request)
        section("Where in the request the decision comes from")
        st.markdown(S.heat_legend(), unsafe_allow_html=True)
        st.markdown(S.heat_box(X.render_attribution_html(e)), unsafe_allow_html=True)
        st.caption("Payload-Span Shapley: each evidence group is really removed from the request text, features are "
                   "re-extracted and the model is re-scored for every combination. Hover a highlight to see its value.")

        # [SCREEN-7] SQLi technique cards (CWE / CAPEC / ATT&CK)
        section("SQLi technique profile")
        if e.techniques:
            for t in e.techniques:
                st.markdown(S.technique_card(t), unsafe_allow_html=True)
        else:
            st.info("No known SQLi technique pattern in this request.")

        # [SCREEN-8] minimal sanitisation counterfactual
        section("Minimal sanitisation counterfactual")
        cf = e.counterfactual
        if cf.get("found"):
            st.success("Removing only **" + "**, **".join(cf["removed_labels"]) +
                       f"** lowers P({e.attack_class}) to **{cf['probability_after']:.1%}** (below the threshold).")
            st.code(cf["sanitized_preview"], language="text")
        else:
            st.info(cf.get("reason", "Not available."))

        # [SCREEN-12] explanation trust breakdown table
        section("Explanation trust breakdown")
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
        # [SCREEN-9] Payload-Span Shapley bar chart
        section("Payload-Span Shapley (evidence groups)")
        if e.pss:
            pss_df = pd.DataFrame({"Evidence group": [X.FAMILY_LABELS.get(k, k) for k in e.pss],
                                   "Shapley value": list(e.pss.values())}).sort_values("Shapley value", ascending=False)
            st.bar_chart(pss_df.set_index("Evidence group"), color=S.CHART["primary"])
            st.caption(f"P({e.attack_class}) with all payload evidence removed: {e.pss_base:.1%} → actual "
                       f"{e.attack_probability:.1%}. Values add up exactly to this difference.")
        else:
            st.info("No SQL-relevant payload evidence in this request.")

        # [SCREEN-10] SHAP bar chart (only if SHAP is installed and switched on)
        if e.shap_values:
            section("SHAP (model features)")
            sdf = (pd.DataFrame({"Feature": list(e.shap_values), "SHAP value": list(e.shap_values.values())})
                   .assign(abs=lambda d: d["SHAP value"].abs()).sort_values("abs", ascending=False).head(12))
            st.bar_chart(sdf.set_index("Feature")["SHAP value"], color=S.CHART["primary"])

        # [SCREEN-11] LIME bar chart (only if LIME is installed and switched on)
        if e.lime_weights:
            section("LIME (local surrogate)")
            ldf = pd.DataFrame({"Feature": list(e.lime_weights), "LIME weight": list(e.lime_weights.values())})
            st.bar_chart(ldf.set_index("Feature")["LIME weight"], color=S.CHART["secondary"])

    # [SCREEN-13] collapsible sections
    with st.expander("Model input features for this incident"):
        st.dataframe(pd.DataFrame({"Feature": list(e.features), "Value": list(e.features.values()),
                                   "Group": [X.feature_family(f) for f in e.features]}),
                     hide_index=True, width="stretch")
    if e.messages:
        with st.expander("Diagnostics"):
            for m in e.messages:
                st.write("•", m)

    # [SCREEN-14] download JSON button + footer note
    st.download_button("Download incident explanation (JSON)", e.to_json(),
                       file_name=f"sqli_xai_{selected}.json", mime="application/json")
    st.caption("All probabilities and attributions come from the loaded model. Explanations describe model behaviour; "
               "they do not prove that an attack succeeded.")


# =============================================================================
# 🛡️ Live Detection — the whole dataset scored at once
# =============================================================================
def _uri_path(uri: str) -> str:
    m = re.match(r"https?://[^/]+(/[^?]*)", str(uri))
    return m.group(1) if m else ""


def tab_detection(scored: pd.DataFrame, cand: pd.Series, threshold: float) -> None:
    flagged = scored[scored["is_attack"]]
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        card("Requests analysed", f"{len(scored):,}")
    with c2:
        card("Flagged as SQL injection", f"{len(flagged):,}", f"{len(flagged) / max(len(scored), 1):.2%} of traffic")
    with c3:
        card("SQL-like requests", f"{int(cand.sum()):,}", "text pre-filter (not a classifier)")
    with c4:
        n_src = flagged["ip.src_host"].nunique() if "ip.src_host" in flagged.columns else 0
        card("Flagged sources", f"{n_src:,}", "distinct source IPs")
    with c5:
        if "actual" in scored.columns:
            card("Agreement with labels", f"{(scored['prediction'] == scored['actual']).mean():.1%}",
                 "label rule from the model card")
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
            st.plotly_chart(bar_h(top.index.tolist(), top.tolist(), "Top flagged source IPs", THEME["attack"],
                                  [f"{n:,}" for n in top]), width="stretch")
        else:
            st.info("No requests flagged — no source IPs to rank.")
    with c3:
        if "http.request.full_uri" in flagged.columns and not flagged.empty:
            paths = flagged["http.request.full_uri"].map(_uri_path).replace("", "(no URI)").value_counts().head(6)
            st.plotly_chart(bar_h(paths.index.tolist(), paths.tolist(), "Most targeted endpoints", THEME["accent"],
                                  [f"{n:,}" for n in paths]), width="stretch")
        else:
            st.info("No flagged requests with a URI.")

    section("Probability distribution of SQL-like requests")
    sub = scored[cand]
    if not sub.empty:
        fig = px.histogram(sub, x="attack_probability", color="prediction", nbins=40,
                           color_discrete_map=CLASS_COLORS)
        fig.add_vline(x=threshold, line_dash="dash", line_color=THEME["warn"], annotation_text="threshold")
        fig.update_layout(xaxis_title="P(SQL injection)", yaxis_title="requests", bargap=0.05)
        st.plotly_chart(style_fig(fig, 300), width="stretch")

    section("Request verdicts")
    only_flagged = st.toggle("Show flagged requests only", value=True, key="sqli_only_flagged")
    view = (flagged if only_flagged else scored).sort_values("attack_probability", ascending=False, kind="stable")
    st.dataframe(view.drop(columns=["is_attack"]).head(5000), width="stretch", height=360, hide_index=True,
                 column_config={"attack_probability": st.column_config.ProgressColumn(
                     "P(SQL injection)", min_value=0.0, max_value=1.0, format="%.3f")})
    st.download_button("Download verdicts (CSV)", view.to_csv(index=False).encode(), "sqli_verdicts.csv", "text/csv")


# =============================================================================
# ★ Explanation Trust — NOVELTY (N3 trust score, N4 counterfactual, N5 techniques) over many incidents
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
      <div class="tag">★ NOVELTY · COMPONENT 2</div>
      <h3>Evidence-Grounded Explanation Trust</h3>
      <p>Every flagged request is explained by <b>Payload-Span Shapley</b> (evidence groups are really removed
      from the request text and the model is re-scored), cross-checked against <b>rule-detected SQLi techniques</b>
      and <b>SHAP</b>, and stress-tested with a <b>deletion test</b> against random characters. The result is an
      <b>Explanation Trust Score</b> per incident: low-trust verdicts go to analyst review instead of automatic blocking.</p>
      <div class="chips"><span>N1 · Payload-Span Shapley</span><span>N2 · Span heat-map</span>
      <span>N3 · Explanation Trust Score</span><span>N4 · Minimal sanitisation counterfactual</span>
      <span>N5 · Technique profile (CWE-89 · CAPEC-66/7 · T1190)</span></div>
    </div>""", unsafe_allow_html=True)


def tab_trust(engine: X.SQLiXAIEngine, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
              use_shap: bool, key: tuple) -> None:
    novelty_banner()
    all_flagged = scored[scored["is_attack"]]
    # the trust score is grounded in payload evidence, so only SQL-like flagged requests can be assessed
    flagged = all_flagged[cand[all_flagged.index]].sort_values("attack_probability", ascending=False, kind="stable")
    no_payload = len(all_flagged) - len(flagged)
    if no_payload:
        st.warning(f"{no_payload:,} of {len(all_flagged):,} flagged requests contain no SQL-like text, so their verdict "
                   "cannot come from payload evidence (network/size features only). They are excluded from trust "
                   "triage and are likely false positives worth reviewing in 🛡️ Live Detection.")
    if flagged.empty:
        st.info("No SQL-like requests are flagged at the current threshold.")
        return
    n = st.slider("Flagged SQL-like incidents to triage (highest probability first)", 10, min(200, max(len(flagged), 10)),
                  min(40, len(flagged)), 10, key="sqli_triage_n",
                  help="Each incident gets the full PSS + trust + counterfactual explanation (~0.4 s each; LIME off "
                       "here for speed). Results are cached.")
    idx = tuple(flagged.index[:n])
    with st.spinner(f"Explaining {len(idx)} flagged incidents (PSS, trust, counterfactual, techniques)..."):
        tri = trust_triage(engine, df, idx, use_shap, key + (n,))

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
                           title="Explanation trust of flagged incidents")
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
        else:
            st.info("No technique patterns detected in the triaged incidents.")
    with c2:
        fam = tri["pss_top_family"].replace("", np.nan).dropna().map(lambda k: X.FAMILY_LABELS.get(k, k)).value_counts()
        if not fam.empty:
            st.plotly_chart(bar_h(fam.index.tolist(), fam.tolist(), "Top Payload-Span Shapley evidence group",
                                  THEME["accent"], [f"{v:,}" for v in fam]), width="stretch")

    section("Escalated for analyst review (low explanation trust)")
    review = tri[tri["trust_level"] == "Low"]
    st.caption(f"{len(review):,} of {len(tri):,} triaged incidents. Open one in the 🔎 Incident XAI tab by searching its ID.")
    st.dataframe(tri.sort_values("trust_score"), width="stretch", hide_index=True, height=320,
                 column_config={"trust_score": st.column_config.ProgressColumn(
                     "trust", min_value=0.0, max_value=1.0, format="%.2f")})
    st.download_button("Download trust triage (CSV)", tri.to_csv(index=False).encode(), "sqli_trust_triage.csv", "text/csv")


# =============================================================================
# 🌐 Global Explainability — what the model relies on overall
# =============================================================================
@st.cache_data(show_spinner="Computing global SHAP...", max_entries=4)
def global_shap(_engine: X.SQLiXAIEngine, _X: pd.DataFrame, key: tuple) -> np.ndarray | None:
    try:
        import shap
    except ImportError:
        return None
    vals = shap.TreeExplainer(_engine.model).shap_values(_X)
    if isinstance(vals, list):
        return np.asarray(vals[_engine.attack_idx])
    vals = np.asarray(vals)
    return vals[:, :, _engine.attack_idx] if vals.ndim == 3 else vals


@st.cache_data(show_spinner=False, max_entries=4)
def technique_profile(_engine: X.SQLiXAIEngine, _df: pd.DataFrame, key: tuple) -> pd.DataFrame:
    res = _engine.resolver(_df.columns)
    rows = []
    for r in _df.to_dict("records"):
        for t in X.detect_techniques(res.view(r)):
            rows.append({k: t[k] for k in ("technique", "cwe", "capec", "attack", "severity")})
    return pd.DataFrame(rows)


def tab_global(engine: X.SQLiXAIEngine, df: pd.DataFrame, scored: pd.DataFrame, cand: pd.Series,
               use_shap: bool, key: tuple) -> None:
    feats = engine.feature_names
    family = {f: X.feature_family(f) for f in feats}
    c1, c2 = st.columns(2)
    with c1:
        imp = getattr(engine.model, "feature_importances_", None)
        if imp is not None:
            gi = pd.DataFrame({"feature": feats, "importance": imp, "group": [family[f] for f in feats]})
            gi = gi.sort_values("importance", ascending=False).head(15)
            fig = px.bar(gi, x="importance", y="feature", color="group", orientation="h",
                         title="Model feature importance (Gini, top 15)")
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(style_fig(fig, 440), width="stretch")
    with c2:
        flagged = scored[scored["is_attack"]].sort_values("attack_probability", ascending=False, kind="stable").head(300)
        Xs = pd.concat([engine.background, engine.build_feature_matrix(df.loc[flagged.index])], ignore_index=True) \
            if engine.background is not None else engine.build_feature_matrix(df.loc[flagged.index])
        sv = global_shap(engine, Xs, key) if use_shap else None
        if sv is not None:
            ma = pd.DataFrame({"feature": feats, "mean |SHAP|": np.abs(sv).mean(axis=0),
                               "group": [family[f] for f in feats]}).sort_values("mean |SHAP|", ascending=False).head(15)
            fig = px.bar(ma, x="mean |SHAP|", y="feature", color="group", orientation="h",
                         title=f"Mean |SHAP| on {len(Xs):,} requests (background + flagged)")
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(style_fig(fig, 440), width="stretch")
        else:
            st.info("Turn on **Compute SHAP** in the sidebar (and install `shap`) to see global SHAP importance.")

    section("SQLi technique profile of flagged traffic")
    flagged = scored[scored["is_attack"]]
    sql_like = flagged.index[cand[flagged.index]]          # technique rules only match SQL-like text
    tp = technique_profile(engine, df.loc[sql_like], key) if len(sql_like) else pd.DataFrame()
    if tp.empty:
        st.info("No technique patterns found in the flagged requests.")
        return
    summary = (tp.groupby(["technique", "cwe", "capec", "attack"]).agg(requests=("severity", "size"),
                                                                      severity=("severity", "max"))
               .reset_index().sort_values("requests", ascending=False))
    c1, c2 = st.columns([1, 1.2])
    with c1:
        st.plotly_chart(bar_h(summary["technique"].tolist(), summary["requests"].tolist(),
                              f"Techniques in {len(flagged):,} flagged requests", THEME["attack"],
                              [f"{v:,}" for v in summary["requests"]], height=340), width="stretch")
    with c2:
        st.dataframe(summary.rename(columns={"attack": "MITRE ATT&CK"}), width="stretch", hide_index=True,
                     column_config={"severity": st.column_config.ProgressColumn(
                         "max severity", min_value=0.0, max_value=1.0, format="%.2f")})


# =============================================================================
# 📊 Model Performance — scores vs. the training label rule
# =============================================================================
def tab_performance(scored: pd.DataFrame) -> None:
    from sklearn.metrics import (accuracy_score, average_precision_score, classification_report,
                                 confusion_matrix, f1_score, precision_recall_curve, precision_score,
                                 recall_score, roc_auc_score, roc_curve)
    card_path = C.MODEL_DIR / "sql_model_card.json"
    model_card = json.loads(card_path.read_text()) if card_path.exists() else None
    if "actual" not in scored.columns:
        st.info("The dataset has no `Attack_label` / `http.request.full_uri` columns, so performance can't be measured.")
    else:
        y = (scored["actual"] == ATTACK).astype(int).to_numpy()
        p = scored["attack_probability"].to_numpy()
        pred = scored["is_attack"].astype(int).to_numpy()
        cm = confusion_matrix(y, pred, labels=[0, 1])
        cols = st.columns(6)
        metrics = [("Accuracy", f"{accuracy_score(y, pred):.4f}"),
                   ("Precision", f"{precision_score(y, pred, zero_division=0):.4f}"),
                   ("Recall", f"{recall_score(y, pred, zero_division=0):.4f}"),
                   ("F1-score", f"{f1_score(y, pred, zero_division=0):.4f}"),
                   ("ROC-AUC", f"{roc_auc_score(y, p):.4f}" if 0 < y.sum() < len(y) else "—"),
                   ("False-positive rate", f"{cm[0, 1] / max(cm[0].sum(), 1):.2%}")]
        for col, (lab, val) in zip(cols, metrics):
            with col:
                card(lab, val)
        st.caption("Measured on the loaded dataset with the training label rule (Attack_label = 1 AND URI targets "
                   "/vulnerabilities/sqli). The delivered model was refit on all rows, so these are in-sample scores.")

        c1, c2, c3 = st.columns(3)
        with c1:
            fig = go.Figure(go.Heatmap(z=cm, x=[f"Pred {NORMAL}", f"Pred {ATTACK}"], y=[f"True {NORMAL}", f"True {ATTACK}"],
                                       text=cm, texttemplate="%{text:,}", showscale=False,
                                       colorscale=[[0, S.COLORS["soft_bg"]], [1, THEME["accent"]]]))
            fig.update_yaxes(autorange="reversed")
            fig.update_layout(title="Confusion matrix")
            st.plotly_chart(style_fig(fig, 320, legend=False), width="stretch")
        if 0 < y.sum() < len(y):
            with c2:
                fpr, tpr, _ = roc_curve(y, p)
                fig = go.Figure(go.Scatter(x=fpr, y=tpr, mode="lines", line=dict(color=THEME["attack"], width=2),
                                           name=f"AUC {roc_auc_score(y, p):.4f}"))
                fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines",
                                         line=dict(dash="dot", color=THEME["muted"]), name="chance"))
                fig.update_layout(title="ROC curve", xaxis_title="False-positive rate", yaxis_title="True-positive rate")
                st.plotly_chart(style_fig(fig, 320), width="stretch")
            with c3:
                prec, rec, _ = precision_recall_curve(y, p)
                fig = go.Figure(go.Scatter(x=rec, y=prec, mode="lines", line=dict(color=THEME["accent"], width=2),
                                           name=f"AP {average_precision_score(y, p):.4f}"))
                fig.update_layout(title="Precision–recall curve", xaxis_title="Recall", yaxis_title="Precision",
                                  yaxis_range=[0, 1.02])
                st.plotly_chart(style_fig(fig, 320), width="stretch")
        section("Classification report")
        rep = pd.DataFrame(classification_report(y, pred, target_names=[NORMAL, ATTACK],
                                                 output_dict=True, zero_division=0)).T
        st.dataframe(rep.style.format("{:.4f}"), width="stretch")

    if model_card:
        with st.expander("Model card (sql_model_card.json)", expanded="actual" not in scored.columns):
            st.json(model_card)


# =============================================================================
# Page
# =============================================================================
def main() -> None:
    st.set_page_config(page_title="SQLi Evidence-Grounded XAI", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="expanded")
    S.apply_theme(st)

    # =========================================================================
    # [SCREEN-1] SIDEBAR - uploads + explanation settings (same layout as ddos_http.py)
    # =========================================================================
    with st.sidebar:
        st.header("Inputs")
        data_up = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="d")
        model_up = st.file_uploader("Trained SQLi model (.pkl)", type=["pkl", "pickle"], key="m")
        feat_up = st.file_uploader("Feature columns (.pkl, optional)", type=["pkl", "pickle"], key="f")
        st.caption("Only load pickle files you trust - loading a pickle can run code.")
        st.header("Explanation settings")
        bg_size = st.slider("Background sample (rows)", 100, 1000, 300, 50,
                            help="Real dataset rows used by SHAP/LIME and the random-deletion baseline.")
        use_shap = st.toggle("Compute SHAP", True)
        use_lime = st.toggle("Compute LIME", True)
        threshold = st.slider("Decision threshold", 0.1, 0.9, 0.5, 0.05,
                              help="Requests with P(SQL injection) ≥ threshold are flagged; also used by the "
                                   "sanitisation counterfactual.")

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
        model = C.load_artifact(model_up or C.first_existing(C.MODEL_PATHS))
        feature_names = C.load_artifact(feat_up or C.first_existing(C.FEATURE_PATHS))
    except Exception as exc:
        st.error(f"Could not load model/feature file: {type(exc).__name__}: {exc}")
        st.stop()
    if model is None:
        st.warning(f"No trained model found in {C.MODEL_DIR}. Upload `sql_injection_rf.pkl` (and its feature column "
                   "list) in the sidebar. This page never shows explanations without a real model.")
        st.stop()

    # [SCREEN-1] SIDEBAR (bottom) - attack class
    classes = [str(c) for c in getattr(model, "classes_", [])]
    with st.sidebar:
        default_attack = X.infer_attack_index(classes) if classes else 0
        attack_class = st.selectbox("Class that means 'SQL injection / attack'", classes or ["1"],
                                    index=min(default_attack, max(len(classes) - 1, 0)))

    # [NO SCREEN] build the XAI engine (only rebuilt when inputs/settings change)
    signature = (data_name, len(df), getattr(model_up, "name", "default-model"), str(feature_names)[:200],
                 bg_size, attack_class)
    if st.session_state.get("engine_sig") != signature:
        try:
            with st.spinner("Building explanation engine and background sample..."):
                tmp = X.SQLiXAIEngine(model, feature_names=feature_names, attack_class=attack_class, threshold=threshold)
                background = tmp.build_feature_matrix(df.sample(min(bg_size, len(df)), random_state=42))
                engine = X.SQLiXAIEngine(model, feature_names=feature_names, background=background,
                                         attack_class=attack_class, threshold=threshold)
        except Exception as exc:
            st.error(f"Could not build the explanation engine: {type(exc).__name__}: {exc}")
            st.stop()
        st.session_state.update(engine=engine, engine_sig=signature)
    engine: X.SQLiXAIEngine = st.session_state["engine"]
    engine.threshold = threshold       # used by the counterfactual; no rebuild needed

    # [SCREEN-2] page title + dataset info line
    st.markdown(S.page_header(
        "SQL Injection - Evidence-Grounded Hybrid XAI",
        f"Dataset {data_name} · {len(df):,} rows · model classes: {', '.join(classes)} · "
        f"explaining class {engine.attack_class} · SHAP {'on' if use_shap else 'off'} · "
        f"LIME {'on' if use_lime else 'off'}"), unsafe_allow_html=True)

    # score once per (data, model, attack class); verdicts follow the threshold slider
    score_key = (data_name, len(df), getattr(model_up, "name", "default-model"), str(feature_names)[:200], attack_class)
    scored = with_verdicts(score_all(engine, df, score_key), threshold)
    if "incident_id" not in scored.columns:
        st.error("No Incident ID column found (expected 'Incident_ID').")
        st.stop()
    cand = candidates(df, score_key[:2])

    t0, t1, t2, t3, t4 = st.tabs(["🔎 Incident XAI", "🛡️ Live Detection", "★ Explanation Trust",
                                  "🌐 Global Explainability", "📊 Model Performance"])
    with t0:
        tab_incident(engine, df, scored, cand, use_shap, use_lime, threshold)
    with t1:
        tab_detection(scored, cand, threshold)
    with t2:
        tab_trust(engine, df, scored, cand, use_shap, signature)   # the triaged ids are part of the cache key
    with t3:
        tab_global(engine, df, scored, cand, use_shap, signature + (threshold,))   # flagged set depends on it
    with t4:
        tab_performance(scored)


main()
