"""
Component 3 - SOC Alert Prioritisation dashboard (Streamlit page - FRONTEND)

FILE LOCATION : dev/frontend/pages/soc_ dash/app.py
STYLES        : dev/frontend/pages/soc_ dash/soc_styles.py  (colours, fonts, CSS - same palette as Component 2)
BACKEND FILES : dev/backend/component3_soc/
                soc_logic.py, scoring.py, factors.py  (all the thinking - this page only DISPLAYS)
                config.py                             (levels, weights, file paths)
DATA          : dev/outputs/component3_soc/scored_alerts.csv  (written by: python -m backend.component3_soc.pipeline)

Run from the repo's dev folder:
  python -m streamlit run "frontend\\pages\\soc_ dash\\app.py"

==============================================================================
SCREEN MAP - where each part of the page is in this code
(search for the tag, e.g. "[SCREEN-3]", to jump to that block)
==============================================================================

 +----------------+--------------------------------------------------------+
 |  SIDEBAR       |  [SCREEN-2] Page title + queue info                    |
 |  [SCREEN-1]    |  [SCREEN-3] 4 KPI cards: alerts | critical | high |    |
 |  - Queue       |             top score                                  |
 |    filters     |--------------------------------------------------------|
 |  - Weights     |  TABS                                                  |
 |  - Service     |  [SCREEN-4] Alert queue   (level chart + table)        |
 |    info        |  [SCREEN-5] Why this score? (factor points + steps)    |
 |                |  [SCREEN-6] What-if calculator                         |
 |                |  [SCREEN-7] Live feed (needs the service running)      |
 |                |--------------------------------------------------------|
 |                |  [SCREEN-8] Footer note                                |
 +----------------+--------------------------------------------------------+

Advice is only a suggestion: a human analyst decides and approves any action.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# =============================================================================
# [NO SCREEN] CONNECT TO THE BACKEND
#   this page : dev/frontend/pages/soc_ dash/
#   backend   : dev/backend/component3_soc/
# =============================================================================
HERE = Path(__file__).resolve().parent
DEV = HERE.parents[2]                               # the dev folder (the one that contains backend/)
for path in (DEV, HERE):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import soc_styles as S  # noqa: E402   -> colours, fonts, CSS
from backend.component3_soc import factors, soc_logic  # noqa: E402
from backend.component3_soc.config import LEVELS, WEIGHTS  # noqa: E402
from frontend.shared.api_client import C3_URL, get_json  # noqa: E402

# =============================================================================
# [SCREEN: BROWSER TAB + WHOLE PAGE] page title in browser tab, wide layout, theme
# Colours/fonts come from S.apply_theme() -> edit soc_styles.py to change them
# =============================================================================
st.set_page_config(page_title="SOC Alert Prioritisation", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
S.apply_theme(st)

# =============================================================================
# [NO SCREEN] LOAD THE SCORED QUEUE - shows a red error box only if the pipeline has not been run
# =============================================================================
try:
    queue = soc_logic.load_queue()
except FileNotFoundError as error:
    st.error(str(error))
    st.stop()

# =============================================================================
# [SCREEN-1] SIDEBAR (left panel) - queue filters, factor weights, service info
# =============================================================================
with st.sidebar:
    st.header("Queue filters")
    chosen = st.multiselect("Show levels", LEVELS, default=["Critical", "High"])
    kinds = st.multiselect("Attack types", sorted(queue["predicted_type"].unique()))
    max_rows = st.slider("Rows in the table", 50, 2000, 500, 50)
    st.header("Factor weights")
    for name, weight in WEIGHTS.items():
        st.write(f"{name.capitalize()}: **{weight:.4f}**")
    st.caption("From the AHP survey (n = 15), consistency ratio 0.031.")
    st.header("Live service")
    st.caption(f"`python -m backend.component3_soc.service` listens on {C3_URL}.")

# =============================================================================
# [SCREEN-2] TOP OF MAIN AREA - page title + queue info line
# =============================================================================
st.markdown(S.page_header(
    "Component 3: SOC Alert Prioritisation",
    f"{len(queue):,} scored alerts · risk score 0-100 from four factors (severity, confidence, asset, frequency) · "
    "levels use the FIRST CVSS v3.1 bands on score / 10 (Critical 90+, High 70+, Medium 40+)"),
    unsafe_allow_html=True)

# =============================================================================
# [SCREEN-3] ROW OF 4 KPI CARDS
# =============================================================================
counts = soc_logic.level_counts(queue)["alerts"]
k1, k2, k3, k4 = st.columns(4)
k1.metric("Alerts in queue", f"{len(queue):,}")
k2.metric("Critical", f"{counts['Critical']:,}", f"{counts['Critical'] / len(queue):.1%} of queue", delta_color="off")
k3.metric("High", f"{counts['High']:,}", f"{counts['High'] / len(queue):.1%} of queue", delta_color="off")
k4.metric("Top risk score", f"{queue['risk_score'].max():.2f}", queue.iloc[0]["predicted_type"], delta_color="off")
st.write("")

tab_queue, tab_why, tab_whatif, tab_live = st.tabs(["Alert queue", "Why this score?", "What-if calculator", "Live feed"])

# =============================================================================
# [SCREEN-4] TAB "Alert queue" - level chart (left) + filtered table (right)
# =============================================================================
with tab_queue:
    left, right = st.columns([1, 2.4], gap="large")
    with left:
        st.markdown(S.section_title("Alerts per level"), unsafe_allow_html=True)
        st.bar_chart(counts, color=S.CHART["primary"], horizontal=True)
        st.markdown("".join(S.level_pill(f"{level}: {counts[level]:,}") for level in LEVELS), unsafe_allow_html=True)
    with right:
        view = queue[queue["priority"].isin(chosen)]
        if kinds:
            view = view[view["predicted_type"].isin(kinds)]
        st.markdown(S.section_title(f"Ranked alerts ({len(view):,} match the filters)"), unsafe_allow_html=True)
        st.dataframe(
            view[["alert_id", "predicted_type", "asset_name", "detection_confidence", "attack_frequency",
                  "risk_score", "priority"]].head(max_rows),
            hide_index=True, width="stretch",
            column_config={
                "alert_id": "Alert", "predicted_type": "Attack type", "asset_name": "Asset",
                "detection_confidence": st.column_config.NumberColumn("Confidence", format="%.2f"),
                "attack_frequency": st.column_config.NumberColumn("Frequency", format="%.2f"),
                "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100,
                                                              format="%.2f"),
                "priority": "Level",
            })

# =============================================================================
# [SCREEN-5] TAB "Why this score?" - alert card, factor points chart, suggested steps
# =============================================================================
with tab_why:
    top = queue.head(200)
    pick = st.selectbox("Pick one of the 200 highest-ranked alerts", top["alert_id"])
    row = top[top["alert_id"] == pick].iloc[0]
    st.markdown(S.alert_card(row["predicted_type"], row["asset_name"], row["risk_score"], row["priority"],
                             f"Frequency basis: {row['frequency_basis']} · asset: {row['asset_status']}"),
                unsafe_allow_html=True)
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown(S.section_title("Points from each factor"), unsafe_allow_html=True)
        st.bar_chart(soc_logic.why(row), color=S.CHART["primary"])
        st.caption("Points add up to the risk score. Each factor = 100 × weight × scaled value.")
    with right:
        st.markdown(S.section_title("Suggested steps"), unsafe_allow_html=True)
        st.markdown(S.steps_list(row["recommendations"].split(" | ")), unsafe_allow_html=True)

# =============================================================================
# [SCREEN-6] TAB "What-if calculator" - inputs (top), result cards, points chart, advice
# =============================================================================
with tab_whatif:
    st.markdown(S.narrative_box("Make up an alert and see how it would be scored. The same steps as the "
                                "pipeline are used, one alert at a time.", "What-if."), unsafe_allow_html=True)
    st.write("")
    c1, c2 = st.columns(2, gap="large")
    attack = c1.selectbox("Attack type", sorted(factors.severity_table()))
    confidence = c1.slider("Detector confidence", 0.0, 1.0, 0.9, 0.01)
    by_ip, by_id = factors.registry()
    target = c2.selectbox("Target IP", list(by_ip) + ["10.9.9.9 (not in registry)"])
    repeats = c2.number_input("Alerts of this type on this target in the last 60 s", 1, 100000, 20)
    result = soc_logic.what_if(attack, confidence, target.split(" ")[0], int(repeats))

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk score", result["score"], result["level"], delta_color="off")
    m2.metric("Severity", result["severity"])
    m3.metric("Asset criticality", result["asset"], result["asset_name"], delta_color="off")
    m4.metric("Frequency", f"{result['frequency']:.2f}")
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown(S.section_title("Points from each factor"), unsafe_allow_html=True)
        st.bar_chart(pd.Series(result["points"]).round(2), color=S.CHART["primary"])
    with right:
        st.markdown(S.section_title("Suggested steps"), unsafe_allow_html=True)
        st.markdown(S.steps_list(result["advice"]), unsafe_allow_html=True)

# =============================================================================
# [SCREEN-7] TAB "Live feed" - service health + latest scored alerts
# =============================================================================
with tab_live:
    st.markdown(S.narrative_box(f"Needs the service running: python -m backend.component3_soc.service "
                                f"(listens on {C3_URL}), then the replay sender in a second window.",
                                "Live feed."), unsafe_allow_html=True)
    st.write("")
    st.button("Refresh")
    try:
        health = get_json(C3_URL + "/health")
        st.markdown(S.section_title("Service health"), unsafe_allow_html=True)
        st.json(health)
        recent = get_json(C3_URL + "/alerts?limit=50")
        st.markdown(S.section_title("Latest scored alerts"), unsafe_allow_html=True)
        if recent:
            st.dataframe(pd.DataFrame(recent)[["alert_id", "received_at", "predicted_type", "asset_name",
                                                "frequency_count", "risk_score", "priority"]][::-1],
                         hide_index=True, width="stretch")
        else:
            st.info("No alerts received yet. Run the replay sender, then press Refresh.")
    except OSError:
        st.warning("Service not running. Start it, then run the replay sender, then press Refresh.")

# =============================================================================
# [SCREEN-8] VERY BOTTOM - footer note
# =============================================================================
st.caption("Advice is only a suggestion: a human analyst decides and approves any action.")
