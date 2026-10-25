"""
Component 2 - Web Injection XAI (SQL injection · XSS · Uploading) (Streamlit page - FRONTEND)

FILE LOCATION : dev/frontend/pages/com2_attack/web_injection.py
BACKEND FILES : dev/backend/component2_xai/
                sqli_xai_config.py  (file paths: dataset, model, outputs)
                sqli_xai_engine.py  (XAI logic)
                sqli_xai_styles.py  (colours, fonts, CSS)
                web_injection_xai.py (multi-class: SQLi + XSS + Upload)
DATASET       : dev/data/EdgeIIoT_train_80_with_incident_id.csv
MODEL         : dev/backend/component2_xai/model/sql_injection_rf.pkl (+ sql_feature_columns.pkl)

Run from the repo's dev folder:
  python -m streamlit run frontend\\pages\\com2_attack\\web_injection.py

==============================================================================
TAB LAYOUT (matches the DDoS page structure)
==============================================================================

 +----------------+--------------------------------------------------------+
 |  SIDEBAR       |  Page title + dataset info line                        |
 |  - Inputs      |  Filter toggle / search box / incident dropdown        |
 |    (uploads)   |--------------------------------------------------------|
 |  - Explanation |  TABS:                                                 |
 |    settings    |  [Incident XAI] KPI cards, analyst summary, heat-map,  |
 |  - Attack      |                 technique cards, counterfactual        |
 |    class       |  [Feature Explanation] PSS, payload vs network, SHAP,  |
 |                |                        LIME charts                     |
 |                |  [Trust Analysis] trust breakdown, diagnostics         |
 |                |  [Model Details] features, taxonomy, download          |
 +----------------+--------------------------------------------------------+
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# =============================================================================
# CONNECT TO THE BACKEND
# =============================================================================
BACKEND_DIR = Path(__file__).resolve().parents[3] / "backend" / "component2_xai"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import sqli_xai_config as C  # noqa: E402
import sqli_xai_engine as X  # noqa: E402
import sqli_xai_styles as S  # noqa: E402

# =============================================================================
# PAGE CONFIG + THEME
# =============================================================================
st.set_page_config(page_title="Web Injection XAI", page_icon="\U0001f6e1️",
                   layout="wide", initial_sidebar_state="expanded")
S.apply_theme(st)


@st.cache_data(show_spinner="Loading dataset...")
def load_csv(source) -> pd.DataFrame:
    return pd.read_csv(source, low_memory=False)


# =============================================================================
# SIDEBAR
# =============================================================================
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
    threshold = st.slider("Decision threshold for counterfactual", 0.1, 0.9, 0.5, 0.05)

# =============================================================================
# LOAD DATASET
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
# LOAD MODEL + FEATURE LIST
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
# SIDEBAR (bottom) - attack class
# =============================================================================
classes = [str(c) for c in getattr(model, "classes_", [])]
with st.sidebar:
    default_attack = X.infer_attack_index(classes) if classes else 0
    attack_class = st.selectbox("Class that means 'SQL injection / attack'", classes or ["1"],
                                index=min(default_attack, max(len(classes) - 1, 0)))

# =============================================================================
# BUILD THE XAI ENGINE
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
# PAGE HEADER + DATASET INFO
# =============================================================================
st.markdown(S.page_header(
    "Web Injection — Evidence-Grounded Hybrid XAI",
    f"Dataset {data_name} \xb7 {len(df):,} rows \xb7 model classes: {', '.join(classes)} \xb7 "
    f"explaining class {engine.attack_class}"), unsafe_allow_html=True)

res = engine.resolver(df.columns)
if not res.id_col:
    st.error("No Incident ID column found (expected 'Incident_ID').")
    st.stop()

st.caption(f"Dataset **{data_name}** \xb7 {len(df):,} rows \xb7 model classes: "
           f"{', '.join(classes)} \xb7 attack class: {attack_class} \xb7 "
           f"SHAP {'on' if use_shap else 'off'} \xb7 LIME {'on' if use_lime else 'off'}")

# =============================================================================
# INCIDENT SELECTION (above tabs, shared by all)
# =============================================================================
only_candidates = st.toggle("Show only requests containing SQL-like text", True,
                            help="Fast text pre-filter to find interesting incidents. It is not a classifier.")
view_df = df[X.candidate_mask(df)] if only_candidates else df
if view_df.empty:
    st.warning("No incidents match the filter.")
    st.stop()

search = st.text_input("Search Incident ID (optional)", placeholder="e.g. ALR-057314")
ids = view_df[res.id_col].astype(str)
if search:
    ids = ids[ids.str.contains(search, case=False, regex=False)]
options = ids.drop_duplicates().head(5000).tolist()
if not options:
    st.warning("No Incident ID matches the search.")
    st.stop()

selected = st.selectbox(f"Incident ({len(options):,} shown)", options)
record = view_df[view_df[res.id_col].astype(str) == selected].iloc[0]

with st.spinner("Explaining incident (PSS, SHAP, LIME, trust, counterfactual)..."):
    e = engine.explain(record, incident_id=selected, use_shap=use_shap, use_lime=use_lime)

# =============================================================================
# TABS
# =============================================================================
t0, t1, t2, t3 = st.tabs([
    "\U0001f50e Incident XAI",
    "\U0001f50d Feature Explanation",
    "Trust Analysis",
    "\U0001f4ca Model Details",
])

# =============================================================================
# TAB 0: INCIDENT XAI
# =============================================================================
with t0:
    # --- KPI cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Model prediction", e.predicted_label)
    c2.metric(f"P({e.attack_class})", f"{e.attack_probability:.1%}")
    c3.metric("Analyst priority", e.priority["level"], f"score {e.priority['score']:.2f}", delta_color="off")
    trust_val = "-" if e.trust["score"] is None else f"{e.trust['score']:.2f}"
    c4.metric("Explanation trust", e.trust["level"], trust_val, delta_color="off")
    if e.priority.get("note"):
        st.warning(e.priority["note"])

    # --- Analyst summary
    st.markdown(S.narrative_box(e.narrative), unsafe_allow_html=True)
    st.write("")

    # --- Payload heat-map
    st.markdown(S.section_title("Where in the request the decision comes from"), unsafe_allow_html=True)
    st.markdown(S.heat_legend(), unsafe_allow_html=True)
    st.markdown(S.heat_box(X.render_attribution_html(e)), unsafe_allow_html=True)
    st.caption("Payload-Span Shapley: each evidence group is really removed from the request text, features are "
               "re-extracted and the model is re-scored for every combination. Hover a highlight to see its value.")
    if e.structure_spans:
        st.caption(f"{len(e.structure_spans)} normal parameter '=' sign(s) (name=) are request structure, "
                   "not SQL evidence: they are kept in every combination and get no colour.")

    # --- Technique profile
    st.markdown(S.section_title("SQLi technique profile"), unsafe_allow_html=True)
    if e.techniques:
        for t in e.techniques:
            st.markdown(S.technique_card(t), unsafe_allow_html=True)
    else:
        st.info("No known SQLi technique pattern in this request.")

    # --- Minimal sanitisation counterfactual
    st.markdown(S.section_title("Minimal sanitisation counterfactual"), unsafe_allow_html=True)
    cf = e.counterfactual
    if cf.get("found"):
        st.success("Removing only **" + "**, **".join(cf["removed_labels"]) +
                   f"** lowers P({e.attack_class}) to **{cf['probability_after']:.1%}** (below the threshold).")
        st.code(cf["sanitized_preview"], language="text")
    else:
        st.info(cf.get("reason", "Not available."))

# =============================================================================
# TAB 1: FEATURE EXPLANATION
# =============================================================================
with t1:
    left, right = st.columns([1.15, 1], gap="large")

    with left:
        # --- PSS chart
        st.markdown(S.section_title("Payload-Span Shapley (evidence groups)"), unsafe_allow_html=True)
        if e.pss:
            pss_df = pd.DataFrame({"Evidence group": [X.FAMILY_LABELS.get(k, k) for k in e.pss],
                                   "Shapley value": list(e.pss.values())}).sort_values("Shapley value", ascending=False)
            st.bar_chart(pss_df.set_index("Evidence group"), color=S.CHART["primary"])
            st.caption(f"P({e.attack_class}) with all payload evidence removed: {e.pss_base:.1%} → actual "
                       f"{e.attack_probability:.1%}. Values add up exactly to this difference.")
        else:
            st.info("No SQL-relevant payload evidence in this request.")

        # --- Payload vs network split
        st.markdown(S.section_title("Payload vs network split"), unsafe_allow_html=True)
        d = e.decomposition
        if d:
            b1, b2, b3 = st.columns(3)
            b1.metric("Average-request baseline", f"{d['base']:.1%}")
            b2.metric("SQL evidence in payload", f"{d['payload']:+.1%}")
            b3.metric("Network / size features", f"{d['network']:+.1%}")
            split_df = pd.DataFrame({"Part": ["Baseline", "SQL payload evidence", "Network / size features"],
                                     "Contribution": [d["base"], d["payload"], d["network"]]})
            st.bar_chart(split_df.set_index("Part"), color=S.CHART["primary"])
            st.caption(f"Two-player Shapley split: baseline + payload + network = P({e.attack_class}) = "
                       f"{d['p_attack']:.1%}. Network features are replaced with {d['background_rows']} real "
                       "background rows when 'removed'.")
        else:
            st.info("Needs a background sample to calculate.")

    with right:
        # --- SHAP chart
        if e.shap_values:
            st.markdown(S.section_title("SHAP (model features)"), unsafe_allow_html=True)
            sdf = (pd.DataFrame({"Feature": list(e.shap_values), "SHAP value": list(e.shap_values.values())})
                   .assign(abs=lambda d: d["SHAP value"].abs()).sort_values("abs", ascending=False).head(12))
            st.bar_chart(sdf.set_index("Feature")["SHAP value"], color=S.CHART["primary"])

        # --- LIME chart
        if e.lime_weights:
            st.markdown(S.section_title("LIME (local surrogate)"), unsafe_allow_html=True)
            ldf = pd.DataFrame({"Feature": list(e.lime_weights), "LIME weight": list(e.lime_weights.values())})
            st.bar_chart(ldf.set_index("Feature")["LIME weight"], color=S.CHART["secondary"])

        if not e.shap_values and not e.lime_weights:
            st.info("Enable SHAP and/or LIME in the sidebar to see feature-level charts.")

# =============================================================================
# TAB 2: TRUST ANALYSIS
# =============================================================================
with t2:
    st.markdown(S.section_title("Explanation trust breakdown"), unsafe_allow_html=True)
    fmt = lambda v: "n/a" if v is None else f"{v:.2f}"
    rob = e.robustness or {}
    trust_rows = [
        ("Rules ↔ PSS agreement", fmt(e.trust["rule_pss_agreement"]), "Do the rule-detected techniques match what drove the model?"),
        ("PSS ↔ SHAP agreement", fmt(e.trust["pss_shap_agreement"]), "Same top evidence groups?"),
        ("PSS ↔ LIME agreement", fmt(e.trust["pss_lime_agreement"]), "Same top evidence groups?"),
        ("Removal-method agreement", fmt(e.trust.get("removal_agreement")),
         f"Same top groups when characters are deleted instead of blanked "
         f"(rank correlation {fmt(rob.get('rank_corr'))})"),
        ("Deletion fidelity gain", fmt(e.trust["fidelity_gain"]),
         f"Removing top evidence drops P by {fmt(e.trust['deletion_drop_top'])} vs "
         f"{fmt(e.trust['deletion_drop_random'])} for random characters"),
        ("Deletion drop: PSS / SHAP / LIME",
         f"{fmt(e.trust['deletion_drop_top'])} / {fmt(e.trust.get('deletion_drop_shap_top'))} / "
         f"{fmt(e.trust.get('deletion_drop_lime_top'))}",
         "Probability drop when removing the top groups each method picks (higher = more faithful)"),
        ("Out-of-range sanitised inputs", fmt(rob.get("ood_fraction")),
         "Share of sanitised versions with features outside the background range (lower = safer)"),
        ("Payload share", fmt(e.trust["payload_share"]), "Part of the attack probability explained by the payload text"),
    ]
    st.dataframe(pd.DataFrame(trust_rows, columns=["Check", "Value", "Meaning"]),
                 hide_index=True, use_container_width=True)
    if rob.get("checked") and rob.get("top_agree") is False:
        st.warning("The top evidence group changes with the removal method - treat the ranking with care.")
    if (rob.get("ood_fraction") or 0) > 0.5:
        st.warning("Most sanitised versions are unlike the background data - the model is being asked about "
                   "unusual inputs, so the explanation is less reliable.")

    if e.messages:
        st.markdown(S.section_title("Diagnostics"), unsafe_allow_html=True)
        for m in e.messages:
            st.write("•", m)

# =============================================================================
# TAB 3: MODEL DETAILS
# =============================================================================
with t3:
    st.markdown(S.section_title("Model input features for this incident"), unsafe_allow_html=True)
    st.dataframe(pd.DataFrame({"Feature": list(e.features), "Value": list(e.features.values()),
                               "Group": [X.feature_family(f) for f in e.features]}),
                 hide_index=True, use_container_width=True)

    st.markdown(S.section_title("Evidence groups and their basis (taxonomy)"), unsafe_allow_html=True)
    st.dataframe(pd.DataFrame({"Group": [X.FAMILY_LABELS[k] for k in X.TAXONOMY],
                               "Basis": list(X.TAXONOMY.values())}),
                 hide_index=True, use_container_width=True)
    st.caption("Parameter '=' signs (name=), request size and TCP fields are never evidence groups.")

    st.download_button("Download incident explanation (JSON)", e.to_json(),
                       file_name=f"sqli_xai_{selected}.json", mime="application/json")
    st.caption("All probabilities and attributions come from the loaded model. Explanations describe model behaviour; "
               "they do not prove that an attack succeeded.")
