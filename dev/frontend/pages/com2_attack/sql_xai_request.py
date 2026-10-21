"""
SQL Injection Incident Analysis (XAI)
- Select records by Incident ID, not row number.
- By default, show records matching SQL-like request indicators.
- These are candidate records for analyst review, NOT confirmed SQL injection labels.
- Does not train a model or fabricate ML/SHAP/LIME results.
Run:
  python -m streamlit run .\SQL_injection\sql_injection_xai_dashboard_incident.py
"""
from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import unquote_plus

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SQL Injection Incident Analysis (XAI)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PROJECT_ROOT = Path(r"D:\4Y1S\research\xai_iiot_prototype")
DATASET_PATH = PROJECT_ROOT / "data" / "EdgeIIoT_train_80_with_incident_id.csv"
PREDICTION_PATHS = [
    PROJECT_ROOT / "data" / "Student1_prediction_results.csv",
    PROJECT_ROOT / "Student1_prediction_results.csv",
    Path(__file__).resolve().parent / "data" / "Student1_prediction_results.csv",
    Path(__file__).resolve().parent / "Student1_prediction_results.csv",
    Path.cwd() / "data" / "Student1_prediction_results.csv",
    Path.cwd() / "Student1_prediction_results.csv",
]
ID_COLUMNS = ["Incident ID", "Incident_ID", "incident_id", "incident id"]
TEXT_COLUMNS = [
    "http.request.uri.query", "http.request.full_uri", "http.request.uri",
    "http.referer", "http.file_data", "http.request.method",
    "http.host", "url", "query", "payload", "raw_http_request", "http.request",
]
DISPLAY_COLUMNS = [
    "Incident ID", "Incident_ID", "frame.time", "ip.src_host", "ip.dst_host",
    "http.request.method", "http.host", "http.request.uri",
    "http.request.uri.query", "http.request.full_uri", "http.file_data",
    "Attack_label",
]
PATTERNS = {
    "SQL keyword": re.compile(r"\b(select|union|insert|update|delete|drop|where|having|order\s+by)\b", re.I),
    "Boolean / logical expression": re.compile(r"\b(and|or)\b\s*(?:['\"\d(]|%27|%22)|\b\d+\s*=\s*\d+\b|\bcase\s+when\b", re.I),
    "SQL comment": re.compile(r"--|/\*|\*/|#"),
    "Database/time-delay function": re.compile(r"\b(chr|char|concat|xmltype|ascii|benchmark|sleep|pg_sleep|substring)\s*\(", re.I),
    "Nested query": re.compile(r"\(\s*select\b", re.I),
    "Quote with SQL-like operator": re.compile(r"""['"][^'"]{0,80}['"]\s*(?:or|and)\b""", re.I),
}

st.markdown("""
<style>
.stApp {background:#0b1119;color:#e7eef7}
[data-testid="stHeader"] {background:transparent}
.block-container {max-width:1500px;padding-top:1.2rem}
.panel {background:#101b28;border:1px solid #26384c;border-radius:10px;padding:16px;margin-bottom:12px}
.payload {background:#08111b;border:1px solid #385069;border-radius:8px;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:Consolas,monospace}
.small-muted {color:#9fb2c7;font-size:.85rem}\n.payload {background:#08111b;border:1px solid #385069;border-radius:8px;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:Consolas,monospace;font-size:.9rem}
</style>
""", unsafe_allow_html=True)


def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def find_col(df: pd.DataFrame, names: list[str]) -> str | None:
    lookup = {norm(c): c for c in df.columns}
    for name in names:
        if norm(name) in lookup:
            return lookup[norm(name)]
    return None


def usable(value: object) -> bool:
    if value is None or pd.isna(value):
        return False
    return str(value).strip().lower() not in {"", "nan", "none", "null"}


def row_text(row: pd.Series, df: pd.DataFrame) -> str:
    pieces = []
    for name in TEXT_COLUMNS:
        col = find_col(df, [name])
        if col and usable(row[col]):
            value = str(row[col]).strip()
            if value.lower() not in {"0", "nan", "none", "null"}:
                pieces.append(f"{col}: {unquote_plus(value)}")
    # De-duplicate identical field contents without losing which field matched.
    return "\n".join(pieces)


def get_indicators(text: str) -> list[str]:
    decoded = unquote_plus(text or "")
    return [name for name, pattern in PATTERNS.items() if pattern.search(decoded)]


st.title("🛡️ SQL Injection Incident Analysis (XAI)")
st.caption("Incident-level request inspection and SQL-like indicator filtering. Indicator matches are investigation candidates, not proof of SQL injection.")

with st.sidebar:
    st.header("Dataset")
    uploaded = st.file_uploader("Upload dataset CSV (optional)", type=["csv"], key="dataset_csv")
    prediction_upload = st.file_uploader(
        "Upload Student 1 prediction results CSV (optional override)", type=["csv"], key="student1_predictions_csv"
    )
    default_prediction_path = next((p for p in PREDICTION_PATHS if p.is_file()), None)
    if prediction_upload is not None:
        st.success(f"Prediction CSV uploaded: {prediction_upload.name}")
    elif default_prediction_path:
        st.success(f"Prediction CSV found: {default_prediction_path}")
    else:
        st.info("Prediction CSV not found automatically. Place Student1_prediction_results.csv in the project data folder or upload it here.")
    st.caption("Predictions are matched by Incident_ID. A prediction CSV alone cannot generate SHAP/LIME values.")
    st.caption(f"Default dataset path: {DATASET_PATH}")

if uploaded is not None:
    try:
        df = pd.read_csv(uploaded, low_memory=False)
        dataset_name = uploaded.name
    except Exception as exc:
        st.error(f"Could not read uploaded CSV: {exc}")
        st.stop()
elif DATASET_PATH.is_file():
    try:
        df = pd.read_csv(DATASET_PATH, low_memory=False)
        dataset_name = DATASET_PATH.name
    except Exception as exc:
        st.error(f"Could not read dataset: {exc}")
        st.stop()
else:
    st.error("Dataset not found. Upload EdgeIIoT_train_80_with_incident_id.csv using the sidebar, or place it in the project's data folder.")
    st.code(str(DATASET_PATH))
    st.stop()

if df.empty:
    st.error("The selected CSV is empty.")
    st.stop()

id_col = find_col(df, ID_COLUMNS)
if not id_col:
    st.error("No Incident ID column was found. Expected a column such as 'Incident ID' or 'Incident_ID'.")
    st.write("Available columns:", list(df.columns))
    st.stop()

st.caption(f"Dataset: `{dataset_name}` · {len(df):,} rows · {len(df.columns):,} columns · Incident ID column: `{id_col}`")

# Fast vectorized scan: only inspect existing HTTP/request text columns.
# Avoid DataFrame.apply(axis=1), which is slow for large packet datasets.
df = df.copy()
df["_source_row"] = range(len(df))

existing_text_cols = []
for name in TEXT_COLUMNS:
    col = find_col(df, [name])
    if col and col not in existing_text_cols:
        existing_text_cols.append(col)

if not existing_text_cols:
    st.error("No supported HTTP/request text columns were found.")
    st.write("Available columns:", list(df.columns))
    st.stop()

with st.spinner("Scanning HTTP/request fields for SQL-like indicators..."):
    # Build one searchable string per row from only the relevant text fields.
    # Vectorized column operations are much faster than row-wise Python callbacks.
    text_series = []
    for col in existing_text_cols:
        values = df[col].astype("string").fillna("")
        text_series.append(values)
    combined = text_series[0]
    for values in text_series[1:]:
        combined = combined.str.cat(values, sep=" ")
    df["_indicator_text"] = combined.str.replace(r"%27", "'", regex=True).str.replace(r"%22", '"', regex=True)
    df["_indicator_text"] = df["_indicator_text"].str.replace(r"\\+", " ", regex=True)

    indicator_masks = {}
    for indicator_name, pattern in PATTERNS.items():
        indicator_masks[indicator_name] = df["_indicator_text"].str.contains(
            pattern, na=False, regex=True
        )

    # Each row gets the names of the patterns matched. Apply only to the small
    # set of boolean indicator columns, rather than repeatedly parsing raw rows.
    indicator_names = list(indicator_masks.keys())
    mask_frame = pd.DataFrame(indicator_masks, index=df.index)
    any_match = mask_frame.any(axis=1)
    df["_indicators"] = [
        [name for name in indicator_names if bool(mask_frame.iloc[pos][name])]
        for pos in range(len(mask_frame))
    ]
    df["_sql_candidate"] = any_match.to_numpy()

# The binary Attack_label is a generic attack/benign label, not a SQLi-specific class.
attack_col = find_col(df, ["Attack_label", "attack_label", "label"])
default_candidates_only = True
only_candidates = st.toggle(
    "Filter records matching SQL-like indicators",
    value=default_candidates_only,
    help="On: show only records with at least one configured SQL-like text indicator. This is a candidate filter, not a confirmed SQL injection classifier.",
)
view = df[df["_sql_candidate"]] if only_candidates else df
if view.empty:
    st.warning("No records match the current filter.")
    st.stop()

m1, m2, m3 = st.columns(3)
m1.metric("Records in dataset", f"{len(df):,}")
m2.metric("SQL-like candidates", f"{int(df['_sql_candidate'].sum()):,}")
m3.metric("Records shown", f"{len(view):,}")

st.info("Important: this dataset's `Attack_label` is binary (attack/benign). It does not identify SQL injection specifically. The filter below selects SQL-like text indicators for investigation; do not describe all matches as confirmed SQL injection attacks.")

# Incident ID selection uses the ID values, not source row numbers.
ids = view[id_col].astype("string").fillna("").astype(str).tolist()
id_to_index = {}
for idx, incident_id in zip(view.index.tolist(), ids):
    if incident_id.strip():
        id_to_index.setdefault(incident_id, idx)
incident_ids = list(id_to_index.keys())
if not incident_ids:
    st.error("No usable Incident ID values exist in the records currently shown.")
    st.stop()

selected_id = st.selectbox(
    "Select incident by Incident ID",
    options=incident_ids,
    index=0,
    help="Only IDs from the currently displayed records appear here. Turn off the SQL-like filter to browse all incident IDs.",
)
row = df.loc[id_to_index[selected_id]]
indicators = row["_indicators"]

# Optional Student 1 prediction-results integration (display only; not enough for SHAP/LIME).
prediction_row = None
prediction_status = "No prediction results CSV found or uploaded"
prediction_source_name = None
if prediction_upload is not None or default_prediction_path is not None:
    try:
        if prediction_upload is not None:
            predictions_df = pd.read_csv(prediction_upload, low_memory=False)
            prediction_source_name = prediction_upload.name
        else:
            predictions_df = pd.read_csv(default_prediction_path, low_memory=False)
            prediction_source_name = default_prediction_path.name
        pred_id_col = find_col(predictions_df, ID_COLUMNS)
        pred_label_col = find_col(predictions_df, [
            "prediction", "predicted_label", "predicted_class", "predicted_attack",
            "prediction_label", "class_prediction", "y_pred", "attack_prediction"
        ])
        pred_conf_col = find_col(predictions_df, [
            "prediction_confidence", "confidence", "predicted_probability", "prediction_probability", "score"
        ])
        pred_source_col = find_col(predictions_df, ["prediction_source", "model_source", "source"])
        if not pred_id_col:
            prediction_status = "Prediction CSV loaded, but no Incident ID column was found."
        elif not pred_label_col:
            prediction_status = "Prediction CSV loaded, but no recognized prediction column was found."
        else:
            normalized_target_id = str(selected_id).strip().casefold()
            matches = predictions_df[
                predictions_df[pred_id_col].astype("string").fillna("").str.strip().str.casefold()
                == normalized_target_id
            ]
            if matches.empty:
                prediction_status = f"No Student 1 prediction found for Incident ID {selected_id}."
            else:
                prediction_row = matches.iloc[0]
                prediction_status = f"Matched {prediction_source_name} by {pred_id_col} → {pred_label_col}."
    except Exception as exc:
        prediction_status = f"Could not read prediction results: {type(exc).__name__}: {exc}"

request_fields = []
for col in TEXT_COLUMNS:
    actual = find_col(df, [col])
    if actual and usable(row[actual]):
        request_fields.append((actual, str(row[actual])))

st.subheader("Selected incident")
c1, c2, c3 = st.columns(3)
c1.metric("Incident ID", str(row[id_col]))
c2.metric("SQL-like indicator groups", str(len(indicators)))
if prediction_row is not None:
    pred_metric = str(prediction_row[pred_label_col])
    if pred_conf_col and usable(prediction_row[pred_conf_col]):
        try:
            conf_num = float(prediction_row[pred_conf_col])
            conf_text = f" · {conf_num:.1%}" if 0 <= conf_num <= 1 else f" · {conf_num}"
        except (TypeError, ValueError):
            conf_text = ""
        pred_metric += conf_text
    c3.metric("IDS prediction", pred_metric)
elif attack_col:
    c3.metric("Dataset Attack_label", str(row[attack_col]))
else:
    c3.metric("Dataset Attack_label", "Not available")

if prediction_upload is not None or default_prediction_path is not None:
    if prediction_row is not None:
        st.success(prediction_status)
        if pred_conf_col and usable(prediction_row[pred_conf_col]):
            conf_value = prediction_row[pred_conf_col]
            try:
                conf_num = float(conf_value)
                conf_display = f"{conf_num:.1%}" if 0 <= conf_num <= 1 else str(conf_value)
            except (TypeError, ValueError):
                conf_display = str(conf_value)
            st.caption(f"Prediction confidence field (`{pred_conf_col}`): {conf_display}")
        if pred_source_col and usable(prediction_row[pred_source_col]):
            source_text = str(prediction_row[pred_source_col])
            if "standin" in source_text.lower() or "baseline" in source_text.lower():
                st.warning(f"Prediction source: {source_text}. This is a stand-in baseline, not confirmed Student 1 model output.")
            else:
                st.caption(f"Prediction source: {source_text}")
        with st.expander("Matched prediction result fields"):
            st.dataframe(prediction_row.to_frame(name="Value"), use_container_width=True)
        st.info("This prediction is matched by Incident_ID. SHAP/LIME still require the fitted model or a compatible prediction interface.")
    else:
        st.info(prediction_status)

left, right = st.columns([1, 1], gap="large")
with left:
    st.markdown("#### HTTP / request details")
    details = []
    for col in DISPLAY_COLUMNS:
        actual = find_col(df, [col])
        if actual and usable(row[actual]):
            details.append({"Field": actual, "Value": str(row[actual])})
    if details:
        st.dataframe(pd.DataFrame(details), use_container_width=True, hide_index=True)
    else:
        st.warning("No common HTTP fields were populated for this record.")

    st.markdown("#### SQL-like indicator evidence")
    evidence_explanations = {
        "SQL keyword": "SQL query keyword observed. Common words such as SELECT or UPDATE can also appear in benign text.",
        "Boolean / logical expression": "A logical operator or boolean-like expression was observed; inspect its surrounding context.",
        "SQL comment": "A SQL-style comment marker was observed. Comments can be used to alter how a query is parsed.",
        "Database/time-delay function": "A database function name was observed. Delay functions can appear in time-based blind SQL injection attempts.",
        "Nested query": "A SELECT statement appears inside parentheses, which may indicate a nested query pattern.",
        "Quote with SQL-like operator": "A quote followed by AND/OR-like syntax was observed, which may indicate an attempt to change query logic.",
    }
    if indicators:
        for indicator in indicators:
            st.markdown(f"**{indicator}**")
            st.write(evidence_explanations.get(indicator, "Matching text pattern observed in request-related fields."))
            st.caption("Evidence source: actual request fields in the selected dataset record.")
            st.divider()
    else:
        st.success("No configured SQL-like indicators found in this record.")
    st.caption("Indicator matching is heuristic. Benign text can contain SQL keywords, and encoded or obfuscated attacks may evade these patterns.")

def highlight_payload(value: str) -> str:
    """HTML-escape the real payload, then highlight only observed text indicators."""
    text = html.escape(unquote_plus(value), quote=False)
    token_pattern = re.compile(
        r"(?P<quote>'[^']*'|&quot;[^&]*&quot;)|"
        r"(?P<keyword>\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|WHERE|FROM|HAVING|ORDER\s+BY)\b)|"
        r"(?P<logic>\b(?:AND|OR)\b)|"
        r"(?P<function>\b(?:CHR|CHAR|XMLTYPE|UPPER|SLEEP|PG_SLEEP|BENCHMARK)\s*\([^)]*\))|"
        r"(?P<boolean>\b\d+\s*=\s*\d+\b|\bCASE\s+WHEN\b)|"
        r"(?P<comment>--|/\*|\*/|#)",
        re.I,
    )
    colors = {
        "quote": "#ff626b", "keyword": "#35b8ff", "logic": "#f6a23a",
        "function": "#35d07f", "boolean": "#b77aff", "comment": "#e0b84d",
    }
    out, last = [], 0
    for match in token_pattern.finditer(text):
        out.append(text[last:match.start()])
        color = colors[match.lastgroup]
        out.append(
            f'<span style="color:{color};border:1px solid {color};'
            f'border-radius:4px;padding:1px 3px;background:{color}18">'
            f'{match.group(0)}</span>'
        )
        last = match.end()
    out.append(text[last:])
    return "".join(out)


with right:
    st.markdown("#### Payload with highlighted indicators")
    payload_values = [(name, value) for name, value in request_fields
                      if any(token in name.lower() for token in
                             ("query", "full_uri", "uri", "file_data", "payload", "request"))]
    if payload_values:
        for field_name, value in payload_values:
            st.markdown(f"**{field_name}**")
            st.markdown(
                f'<div class="payload">{highlight_payload(value)}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.warning("This incident has no usable payload/query text in the selected request fields.")
    st.caption("Highlights show rule-based text matches only; they are not model explanations.")

    st.markdown("#### SHAP model explanation")
    st.info(
        "Pending integration with the research team's trained IDS model. "
        "Real SHAP values require that model and its exact preprocessing/features; "
        "this dashboard does not generate placeholder values."
    )

    st.markdown("#### LIME local explanation")
    st.info(
        "Pending integration with the research team's trained IDS model and prediction function. "
        "Real LIME weights require a callable model prediction interface; "
        "no synthetic weights are displayed."
    )

with st.expander("Browse currently filtered incidents"):
    preview_cols = [id_col]
    for col in ["frame.time", "ip.src_host", "ip.dst_host", "http.request.method", "Attack_label"]:
        actual = find_col(df, [col])
        if actual and actual not in preview_cols:
            preview_cols.append(actual)
    preview = view[preview_cols + ["_indicators"]].copy()
    preview = preview.rename(columns={"_indicators": "SQL-like indicators"})
    preview["SQL-like indicators"] = preview["SQL-like indicators"].map(lambda x: ", ".join(x) if x else "None")
    st.dataframe(preview, use_container_width=True, hide_index=True)

st.markdown("---")
st.caption("Student 1 prediction-result CSVs can be displayed by Incident ID. Genuine SHAP/LIME still require the trained IDS model or a compatible callable prediction interface plus its exact feature preprocessing.")
