"""
Component 2 - Evidence-Grounded Hybrid XAI for SQL Injection (Streamlit page - FRONTEND)

FILE LOCATION : dev/frontend/pages/com2_attack/sqli_xai_novelty_page.py
BACKEND FILES : dev/backend/component2_xai/
                sqli_xai_config.py  (file paths: dataset, model, outputs)
                sqli_xai_engine.py  (XAI logic)
                sqli_xai_styles.py  (colours, fonts, CSS)
DATASET       : dev/data/EdgeIIoT_train_80_with_incident_id.csv
MODEL         : dev/backend/component2_xai/model/sql_injection_rf.pkl (+ sql_feature_columns.pkl)

Run from the repo's dev folder:
  python -m streamlit run frontend\\pages\\com2_attack\\sqli_xai_novelty_page.py

==============================================================================
SCREEN MAP - where each part of the page is in this code
(search for the tag, e.g. "[SCREEN-3]", to jump to that block)
==============================================================================

 +----------------+--------------------------------------------------------+
 |  SIDEBAR       |  [SCREEN-2] Page title + dataset info                  |
 |  [SCREEN-1]    |  [SCREEN-3] Filter toggle / search box / incident list |
 |  - Inputs      |--------------------------------------------------------|
 |    (uploads)   |  [SCREEN-4] 4 KPI cards: prediction | probability |    |
 |  - Explanation |             priority | trust                           |
 |    settings    |  [SCREEN-5] Analyst summary (narrative box)            |
 |  - Attack      |--------------------------------------------------------|
 |    class       |  LEFT COLUMN               |  RIGHT COLUMN             |
 |                |  [SCREEN-6]  Heat-map      |  [SCREEN-9]  PSS chart    |
 |                |  [SCREEN-7]  Technique     |  [SCREEN-10] SHAP chart   |
 |                |              cards         |  [SCREEN-11] LIME chart   |
 |                |  [SCREEN-8]  Counterfact.  |                           |
 |                |  [SCREEN-12] Trust table   |                           |
 |                |--------------------------------------------------------|
 |                |  [SCREEN-13] Expanders: input features, diagnostics    |
 |                |  [SCREEN-14] Download JSON button + footer note        |
 +----------------+--------------------------------------------------------+

Blocks marked [NO SCREEN] are setup/logic only - they show nothing unless
there is an error message.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
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

# =============================================================================
# [SCREEN: BROWSER TAB + WHOLE PAGE] page title in browser tab, wide layout, theme
# Colours/fonts come from S.apply_theme() -> edit sqli_xai_styles.py to change them
# =============================================================================
st.set_page_config(page_title="SQLi Evidence-Grounded XAI", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
S.apply_theme(st)

# =============================================================================
# [NO SCREEN] LINK FROM THE XAI-IDS DASHBOARD
#   the IDS opens this page as  ?incident=ALR-000024  -> that incident is selected below
# =============================================================================
IDS_URL = os.environ.get("XAI_IDS_URL", "http://127.0.0.1:5000").rstrip("/")
incoming_id = st.query_params.get("incident", "").strip()
# apply it only once, so the user can still change the dropdown afterwards
if incoming_id and st.session_state.get("_applied_incident") != incoming_id:
    st.session_state["_applied_incident"] = incoming_id
    st.session_state["incident_select"] = incoming_id


# =============================================================================
# [NO SCREEN] dataset cache (the only helper kept in the frontend)
# =============================================================================
@st.cache_data(show_spinner="Loading dataset...")
def load_csv(source) -> pd.DataFrame:
    """Read the dataset CSV once and cache it (fast reloads)."""
    return pd.read_csv(source, low_memory=False)


# =============================================================================
# [SCREEN-1] SIDEBAR (left panel) - upload boxes + explanation settings
# =============================================================================
with st.sidebar:
    # --- Sidebar: "Inputs" heading and 3 upload boxes
    st.header("Inputs")
    data_up = st.file_uploader("Dataset CSV (optional)", type=["csv"], key="d")
    model_up = st.file_uploader("Trained SQLi model (.pkl)", type=["pkl", "pickle"], key="m")
    feat_up = st.file_uploader("Feature columns (.pkl, optional)", type=["pkl", "pickle"], key="f")
    st.caption("Only load pickle files you trust - loading a pickle can run code.")
    # --- Sidebar: "Explanation settings" heading, sliders and SHAP/LIME switches
    st.header("Explanation settings")
    bg_size = st.slider("Background sample (rows)", 100, 1000, 300, 50,
                        help="Real dataset rows used by SHAP/LIME and the random-deletion baseline.")
    use_shap = st.toggle("Compute SHAP", True)
    use_lime = st.toggle("Compute LIME", True)
    threshold = st.slider("Decision threshold for counterfactual", 0.1, 0.9, 0.5, 0.05)

# =============================================================================
# [NO SCREEN] LOAD DATASET - shows a red error box at the top only if no dataset is found
# =============================================================================
dataset_path = C.first_existing(C.DATASET_PATHS)
if data_up is not None:
    df, data_name = load_csv(data_up), data_up.name
elif dataset_path:
    df, data_name = load_csv(str(dataset_path)), dataset_path.name
else:
    st.error("Dataset not found. Upload it in the sidebar or place it at:")
    st.code(str(C.DATASET_PATHS[0]))
    st.stop()

# =============================================================================
# [NO SCREEN] LOAD MODEL + FEATURE LIST - shows a warning box only if the model is missing
# =============================================================================
try:
    model = C.load_artifact(model_up or C.first_existing(C.MODEL_PATHS))
    feature_names = C.load_artifact(feat_up or C.first_existing(C.FEATURE_PATHS))
except Exception as exc:
    st.error(f"Could not load model/feature file: {type(exc).__name__}: {exc}")
    st.stop()
if model is None:
    st.warning(f"No trained model found in {C.MODEL_DIR}. Upload `sql_injection_rf.pkl` (and its feature column list) in the sidebar. "
               "This page never shows explanations without a real model.")
    st.stop()

# =============================================================================
# [SCREEN-1] SIDEBAR (bottom) - "Class that means SQL injection / attack" dropdown
# =============================================================================
classes = [str(c) for c in getattr(model, "classes_", [])]
with st.sidebar:
    default_attack = X.infer_attack_index(classes) if classes else 0
    attack_class = st.selectbox("Class that means 'SQL injection / attack'", classes or ["1"],
                                index=min(default_attack, max(len(classes) - 1, 0)))

# =============================================================================
# [NO SCREEN] BUILD THE XAI ENGINE (only rebuilt when inputs/settings change)
# Shows a spinner "Building explanation engine..." while it runs
# =============================================================================
signature = (data_name, len(df), getattr(model_up, "name", "default-model"), str(feature_names)[:200],
             bg_size, attack_class, threshold)
if st.session_state.get("engine_sig") != signature:
    try:
        with st.spinner("Building explanation engine and background sample..."):
            tmp = X.SQLiXAIEngine(model, feature_names=feature_names, attack_class=attack_class, threshold=threshold)
            sample = df.sample(min(bg_size, len(df)), random_state=42)
            background = tmp.build_feature_matrix(sample)
            engine = X.SQLiXAIEngine(model, feature_names=feature_names, background=background,
                                     attack_class=attack_class, threshold=threshold)
    except Exception as exc:
        st.error(f"Could not build the explanation engine: {type(exc).__name__}: {exc}")
        st.stop()
    st.session_state.update(engine=engine, engine_sig=signature)
engine: X.SQLiXAIEngine = st.session_state["engine"]

# =============================================================================
# [SCREEN-2] TOP OF MAIN AREA - page title + dataset info line
# =============================================================================
st.markdown(S.page_header(
    "SQL Injection - Evidence-Grounded Hybrid XAI",
    f"Dataset {data_name} · {len(df):,} rows · model classes: {', '.join(classes)} · "
    f"explaining class {engine.attack_class}"), unsafe_allow_html=True)

res = engine.resolver(df.columns)
if not res.id_col:
    st.error("No Incident ID column found (expected 'Incident_ID').")
    st.stop()

# =============================================================================
# [SCREEN-3] BELOW THE TITLE - filter toggle, Incident ID search box, incident dropdown
# =============================================================================
# --- "Show only requests containing SQL-like text" switch
only_candidates = st.toggle("Show only requests containing SQL-like text", True,
                            help="Fast text pre-filter to find interesting incidents. It is not a classifier.")
view_df = df[X.candidate_mask(df)] if only_candidates else df
if view_df.empty:
    st.warning("No incidents match the filter.")
    st.stop()
# --- "Search Incident ID" text box
search = st.text_input("Search Incident ID (optional)")
ids = view_df[res.id_col].astype(str)
if search:
    ids = ids[ids.str.contains(search, case=False, regex=False)]
options = ids.drop_duplicates().head(5000).tolist()
# the incident sent by the IDS is always listed, even if the filter/search would hide it
all_ids = df[res.id_col].astype(str)
if incoming_id and incoming_id not in options and (all_ids == incoming_id).any():
    options = [incoming_id] + options
if not options:
    st.warning("No Incident ID matches the search.")
    st.stop()
# avoid an error if the remembered selection is not in the current list
if st.session_state.get("incident_select") not in options:
    st.session_state.pop("incident_select", None)
# --- "Incident (N shown)" dropdown - the selected incident is explained below
selected = st.selectbox(f"Incident ({len(options):,} shown)", options, key="incident_select")
record = df[all_ids == selected].iloc[0]
# keep the URL in sync (shareable, refresh-safe) without re-triggering the IDS link above
st.query_params["incident"] = selected
st.session_state["_applied_incident"] = selected
# --- "Back to XAI IDS" button - opens this incident on the IDS dashboard
st.link_button("← Back to XAI IDS", f"{IDS_URL}/?incident={selected}")

# [NO SCREEN] run the explanation for the selected incident (spinner while it runs)
with st.spinner("Explaining incident (PSS, SHAP, LIME, trust, counterfactual)..."):
    e = engine.explain(record, incident_id=selected, use_shap=use_shap, use_lime=use_lime)

# =============================================================================
# [SCREEN-4] ROW OF 4 KPI CARDS (left to right)
#   c1 = Model prediction | c2 = P(attack) | c3 = Analyst priority | c4 = Explanation trust
# =============================================================================
c1, c2, c3, c4 = st.columns(4)
c1.metric("Model prediction", e.predicted_label)
c2.metric(f"P({e.attack_class})", f"{e.attack_probability:.1%}")
c3.metric("Analyst priority", e.priority["level"], f"score {e.priority['score']:.2f}", delta_color="off")
trust_val = "-" if e.trust["score"] is None else f"{e.trust['score']:.2f}"
c4.metric("Explanation trust", e.trust["level"], trust_val, delta_color="off")
# --- yellow warning under the cards (only when explanation trust is low)
if e.priority.get("note"):
    st.warning(e.priority["note"])

# =============================================================================
# [SCREEN-5] UNDER THE KPI CARDS - "Analyst summary" narrative box (full width)
# =============================================================================
st.markdown(S.narrative_box(e.narrative), unsafe_allow_html=True)
st.write("")

# =============================================================================
# MAIN CONTENT - two columns: left (wider) and right
# =============================================================================
left, right = st.columns([1.15, 1], gap="large")

with left:
    # =========================================================================
    # [SCREEN-6] LEFT COLUMN, TOP - payload heat-map (red/blue highlighted request)
    # =========================================================================
    st.markdown(S.section_title("Where in the request the decision comes from"), unsafe_allow_html=True)
    st.markdown(S.heat_legend(), unsafe_allow_html=True)                             # red/blue legend
    st.markdown(S.heat_box(X.render_attribution_html(e)), unsafe_allow_html=True)   # highlighted request text
    st.caption("Payload-Span Shapley: each evidence group is really removed from the request text, features are "
               "re-extracted and the model is re-scored for every combination. Hover a highlight to see its value.")

    # =========================================================================
    # [SCREEN-7] LEFT COLUMN, MIDDLE - SQLi technique cards (CWE / CAPEC / ATT&CK)
    # =========================================================================
    st.markdown(S.section_title("SQLi technique profile"), unsafe_allow_html=True)
    if e.techniques:
        for t in e.techniques:
            st.markdown(S.technique_card(t), unsafe_allow_html=True)               # one card per technique
    else:
        st.info("No known SQLi technique pattern in this request.")

    # =========================================================================
    # [SCREEN-8] LEFT COLUMN, BOTTOM - minimal sanitisation counterfactual
    # =========================================================================
    st.markdown(S.section_title("Minimal sanitisation counterfactual"), unsafe_allow_html=True)
    cf = e.counterfactual
    if cf.get("found"):
        st.success("Removing only **" + "**, **".join(cf["removed_labels"]) +              # green box
                   f"** lowers P({e.attack_class}) to **{cf['probability_after']:.1%}** (below the threshold).")
        st.code(cf["sanitized_preview"], language="text")                              # sanitised request
    else:
        st.info(cf.get("reason", "Not available."))                                    # blue info box

    # =========================================================================
    # [SCREEN-12] LEFT COLUMN, BOTTOM - Explanation trust breakdown table (under counterfactual)
    # =========================================================================
    st.markdown(S.section_title("Explanation trust breakdown"), unsafe_allow_html=True)
    fmt = lambda v: "n/a" if v is None else f"{v:.2f}"
    trust_rows = [
        ("Rules ↔ PSS agreement", fmt(e.trust["rule_pss_agreement"]), "Do the rule-detected techniques match what drove the model?"),
        ("PSS ↔ SHAP agreement", fmt(e.trust["pss_shap_agreement"]), "Same top evidence groups?"),
        ("PSS ↔ LIME agreement", fmt(e.trust["pss_lime_agreement"]), "Same top evidence groups?"),
        ("Deletion fidelity gain", fmt(e.trust["fidelity_gain"]),
         f"Removing top evidence drops P by {fmt(e.trust['deletion_drop_top'])} vs "
         f"{fmt(e.trust['deletion_drop_random'])} for random characters"),
        ("Payload share", fmt(e.trust["payload_share"]), "Part of the attack probability explained by the payload text"),
    ]
    st.dataframe(pd.DataFrame(trust_rows, columns=["Check", "Value", "Meaning"]),
                 hide_index=True, use_container_width=True)

with right:
    # =========================================================================
    # [SCREEN-9] RIGHT COLUMN, TOP - Payload-Span Shapley bar chart
    # =========================================================================
    st.markdown(S.section_title("Payload-Span Shapley (evidence groups)"), unsafe_allow_html=True)
    if e.pss:
        pss_df = pd.DataFrame({"Evidence group": [X.FAMILY_LABELS.get(k, k) for k in e.pss],
                               "Shapley value": list(e.pss.values())}).sort_values("Shapley value", ascending=False)
        st.bar_chart(pss_df.set_index("Evidence group"), color=S.CHART["primary"])
        st.caption(f"P({e.attack_class}) with all payload evidence removed: {e.pss_base:.1%} → actual "
                   f"{e.attack_probability:.1%}. Values add up exactly to this difference.")
    else:
        st.info("No SQL-relevant payload evidence in this request.")

    # =========================================================================
    # [SCREEN-10] RIGHT COLUMN - SHAP bar chart (only if SHAP is installed and switched on)
    # =========================================================================
    if e.shap_values:
        st.markdown(S.section_title("SHAP (model features)"), unsafe_allow_html=True)
        sdf = (pd.DataFrame({"Feature": list(e.shap_values), "SHAP value": list(e.shap_values.values())})
               .assign(abs=lambda d: d["SHAP value"].abs()).sort_values("abs", ascending=False).head(12))
        st.bar_chart(sdf.set_index("Feature")["SHAP value"], color=S.CHART["primary"])

    # =========================================================================
    # [SCREEN-11] RIGHT COLUMN - LIME bar chart (only if LIME is installed and switched on)
    # =========================================================================
    if e.lime_weights:
        st.markdown(S.section_title("LIME (local surrogate)"), unsafe_allow_html=True)
        ldf = pd.DataFrame({"Feature": list(e.lime_weights), "LIME weight": list(e.lime_weights.values())})
        st.bar_chart(ldf.set_index("Feature")["LIME weight"], color=S.CHART["secondary"])

# =============================================================================
# [SCREEN-13] BOTTOM OF PAGE (full width) - collapsible sections
# =============================================================================
# --- "Model input features for this incident" expander (feature values table)
with st.expander("Model input features for this incident"):
    st.dataframe(pd.DataFrame({"Feature": list(e.features), "Value": list(e.features.values()),
                               "Group": [X.feature_family(f) for f in e.features]}),
                 hide_index=True, use_container_width=True)
# --- "Diagnostics" expander (only shown when there are messages, e.g. SHAP not installed)
if e.messages:
    with st.expander("Diagnostics"):
        for m in e.messages:
            st.write("•", m)

# =============================================================================
# [SCREEN-14] VERY BOTTOM - download JSON button + footer note
# =============================================================================
st.download_button("Download incident explanation (JSON)", e.to_json(),
                   file_name=f"sqli_xai_{selected}.json", mime="application/json")
st.caption("All probabilities and attributions come from the loaded model. Explanations describe model behaviour; "
           "they do not prove that an attack succeeded.")
