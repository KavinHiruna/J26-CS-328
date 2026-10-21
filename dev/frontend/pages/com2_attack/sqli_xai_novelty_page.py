"""
Component 2 - Evidence-Grounded Hybrid XAI for SQL Injection (Streamlit page)

Shows, for one incident:
  * the model prediction (from the real trained model)
  * Payload-Span Shapley heat-map over the actual request characters   (novelty N1, N2)
  * SHAP and LIME (when installed) for comparison
  * Explanation Trust Score: rule/PSS/SHAP/LIME agreement + deletion fidelity  (N3)
  * minimal sanitisation counterfactual                                 (N4)
  * SQLi technique profile, CWE/CAPEC/ATT&CK mapping and narrative      (N5)

Place this file next to sqli_xai_engine.py, then run from the repo's dev folder:
  python -m streamlit run frontend\\pages\\com2_attack\\sqli_xai_novelty_page.py
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqli_xai_engine as X  # noqa: E402

st.set_page_config(page_title="SQLi Evidence-Grounded XAI", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[2] if len(HERE.parents) > 2 else HERE   # .../dev
DATASET_PATHS = [
    PROJECT_ROOT / "data" / "raw" / "EdgeIIoT_train_80_with_incident_id.csv",
    PROJECT_ROOT / "data" / "EdgeIIoT_train_80_with_incident_id.csv",
    HERE / "data" / "EdgeIIoT_train_80_with_incident_id.csv",
]
MODEL_PATHS = [
    PROJECT_ROOT / "backend" / "component2_xai" / "model" / "sql_injection_rf.pkl",
    PROJECT_ROOT / "models" / "sql_injection_rf.pkl",
    HERE / "models" / "sql_injection_rf.pkl",
]
FEATURE_PATHS = [
    PROJECT_ROOT / "backend" / "component2_xai" / "model" / "sql_feature_columns.pkl",
    PROJECT_ROOT / "models" / "sql_feature_columns.pkl",
    HERE / "models" / "sql_feature_columns.pkl",
]
CANDIDATE_PATTERN = (r"(?i)(?:%27|'|%22|\bunion\b|union%20|\bselect\b|select%20|sleep|benchmark|"
                     r"%23|--|information_schema|extractvalue|updatexml|xmltype|0x[0-9a-f]{4})")

st.markdown("""
<style>
.stApp {background:#0b1119;color:#e7eef7}
[data-testid="stHeader"] {background:transparent}
.block-container {max-width:1500px;padding-top:1.2rem}
.heat {background:#08111b;border:1px solid #385069;border-radius:8px;padding:14px;
       font-family:Consolas,monospace;font-size:.92rem;line-height:1.9;overflow-wrap:anywhere}
.narrative {background:#101b28;border-left:4px solid #53bdf7;border-radius:6px;padding:14px 16px;line-height:1.6}
.tech {background:#101b28;border:1px solid #26384c;border-radius:8px;padding:10px 12px;margin-bottom:8px}
.tech b {color:#e7eef7} .tech .meta {color:#9fb2c7;font-size:.8rem}
.legend span {display:inline-block;padding:1px 8px;border-radius:4px;margin-right:8px;font-size:.8rem}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- loading
def first_existing(paths):
    return next((p for p in paths if p.is_file()), None)


@st.cache_data(show_spinner="Loading dataset...")
def load_csv(source) -> pd.DataFrame:
    return pd.read_csv(source, low_memory=False)


def load_artifact(upload, path):
    if upload is not None:
        return joblib.load(upload)
    if path is not None:
        return joblib.load(path)
    return None


def candidate_mask(df: pd.DataFrame) -> pd.Series:
    res = X.ColumnResolver(df.columns)
    cols = [c for c in res.target + res.body + [res.query, res.referer] if c]
    mask = pd.Series(False, index=df.index)
    for c in dict.fromkeys(cols):
        mask |= df[c].astype("string").str.contains(CANDIDATE_PATTERN, regex=True, na=False)
    return mask


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

dataset_path = first_existing(DATASET_PATHS)
if data_up is not None:
    df, data_name = load_csv(data_up), data_up.name
elif dataset_path:
    df, data_name = load_csv(str(dataset_path)), dataset_path.name
else:
    st.error("Dataset not found. Upload it in the sidebar or place it at:")
    st.code(str(DATASET_PATHS[0]))
    st.stop()

try:
    model = load_artifact(model_up, first_existing(MODEL_PATHS))
    feature_names = load_artifact(feat_up, first_existing(FEATURE_PATHS))
except Exception as exc:
    st.error(f"Could not load model/feature file: {type(exc).__name__}: {exc}")
    st.stop()
if model is None:
    st.warning("No trained model found. Upload `sql_injection_rf.pkl` (and its feature column list) in the sidebar. "
               "This page never shows explanations without a real model.")
    st.stop()

classes = [str(c) for c in getattr(model, "classes_", [])]
with st.sidebar:
    default_attack = X.infer_attack_index(classes) if classes else 0
    attack_class = st.selectbox("Class that means 'SQL injection / attack'", classes or ["1"],
                                index=min(default_attack, max(len(classes) - 1, 0)))

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

# ---------------------------------------------------------------- incident selection
st.title("SQL Injection - Evidence-Grounded Hybrid XAI")
st.caption(f"Dataset `{data_name}` · {len(df):,} rows · model classes: {', '.join(classes)} · "
           f"explaining class **{engine.attack_class}**")

res = engine.resolver(df.columns)
if not res.id_col:
    st.error("No Incident ID column found (expected 'Incident_ID').")
    st.stop()

only_candidates = st.toggle("Show only requests containing SQL-like text", True,
                            help="Fast text pre-filter to find interesting incidents. It is not a classifier.")
view_df = df[candidate_mask(df)] if only_candidates else df
if view_df.empty:
    st.warning("No incidents match the filter.")
    st.stop()
search = st.text_input("Search Incident ID (optional)")
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

# ---------------------------------------------------------------- headline
c1, c2, c3, c4 = st.columns(4)
c1.metric("Model prediction", e.predicted_label)
c2.metric(f"P({e.attack_class})", f"{e.attack_probability:.1%}")
c3.metric("Analyst priority", e.priority["level"], f"score {e.priority['score']:.2f}", delta_color="off")
trust_val = "-" if e.trust["score"] is None else f"{e.trust['score']:.2f}"
c4.metric("Explanation trust", e.trust["level"], trust_val, delta_color="off")
if e.priority.get("note"):
    st.warning(e.priority["note"])
st.markdown(f'<div class="narrative">{html.escape(e.narrative)}</div>', unsafe_allow_html=True)
st.write("")

left, right = st.columns([1.15, 1], gap="large")
with left:
    st.markdown("#### Where in the request the decision comes from")
    st.markdown('<div class="legend"><span style="background:rgba(239,68,68,.7)">pushes towards attack</span>'
                '<span style="background:rgba(59,130,246,.7)">pushes away from attack</span></div>',
                unsafe_allow_html=True)
    st.markdown(f'<div class="heat">{X.render_attribution_html(e)}</div>', unsafe_allow_html=True)
    st.caption("Payload-Span Shapley: each evidence group is really removed from the request text, features are "
               "re-extracted and the model is re-scored for every combination. Hover a highlight to see its value.")

    st.markdown("#### SQLi technique profile")
    if e.techniques:
        for t in e.techniques:
            st.markdown(
                f'<div class="tech"><b>{html.escape(t["technique"])}</b> '
                f'<span class="meta">· severity {t["severity"]:.2f} · {t["cwe"]} · {t["capec"]} · ATT&amp;CK {t["attack"]}</span><br>'
                f'<span class="meta">Evidence: <code>{html.escape(t["evidence"])}</code></span><br>'
                f'{html.escape(t["recommendation"])}</div>', unsafe_allow_html=True)
    else:
        st.info("No known SQLi technique pattern in this request.")

    st.markdown("#### Minimal sanitisation counterfactual")
    cf = e.counterfactual
    if cf.get("found"):
        st.success("Removing only **" + "**, **".join(cf["removed_labels"]) +
                   f"** lowers P({e.attack_class}) to **{cf['probability_after']:.1%}** (below the threshold).")
        st.code(cf["sanitized_preview"], language="text")
    else:
        st.info(cf.get("reason", "Not available."))

with right:
    st.markdown("#### Payload-Span Shapley (evidence groups)")
    if e.pss:
        pss_df = pd.DataFrame({"Evidence group": [X.FAMILY_LABELS.get(k, k) for k in e.pss],
                               "Shapley value": list(e.pss.values())}).sort_values("Shapley value", ascending=False)
        st.bar_chart(pss_df.set_index("Evidence group"))
        st.caption(f"P({e.attack_class}) with all payload evidence removed: {e.pss_base:.1%} → actual "
                   f"{e.attack_probability:.1%}. Values add up exactly to this difference.")
    else:
        st.info("No SQL-relevant payload evidence in this request.")

    if e.shap_values:
        st.markdown("#### SHAP (model features)")
        sdf = (pd.DataFrame({"Feature": list(e.shap_values), "SHAP value": list(e.shap_values.values())})
               .assign(abs=lambda d: d["SHAP value"].abs()).sort_values("abs", ascending=False).head(12))
        st.bar_chart(sdf.set_index("Feature")["SHAP value"])
    if e.lime_weights:
        st.markdown("#### LIME (local surrogate)")
        ldf = pd.DataFrame({"Feature": list(e.lime_weights), "LIME weight": list(e.lime_weights.values())})
        st.bar_chart(ldf.set_index("Feature")["LIME weight"])

    st.markdown("#### Explanation trust breakdown")
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

with st.expander("Model input features for this incident"):
    st.dataframe(pd.DataFrame({"Feature": list(e.features), "Value": list(e.features.values()),
                               "Group": [X.feature_family(f) for f in e.features]}),
                 hide_index=True, use_container_width=True)
if e.messages:
    with st.expander("Diagnostics"):
        for m in e.messages:
            st.write("•", m)
st.download_button("Download incident explanation (JSON)", e.to_json(),
                   file_name=f"sqli_xai_{selected}.json", mime="application/json")
st.caption("All probabilities and attributions come from the loaded model. Explanations describe model behaviour; "
           "they do not prove that an attack succeeded.")
