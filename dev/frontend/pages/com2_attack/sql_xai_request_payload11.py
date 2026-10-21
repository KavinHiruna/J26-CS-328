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
ID_COLUMNS = ["Incident ID", "incident_id"]
TEXT_COLUMNS = [
    "http.request.uri.query", "http.request.full_uri", "http.request.uri",
    "http.referer", "http.file_data", "http.request.method",
    "http.host", "url", "query", "payload", "raw_http_request", "http.request",
]
DISPLAY_COLUMNS = [
    "Incident ID", "frame.time", "ip.src_host", "ip.dst_host",
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
.small-muted {color:#9fb2c7;font-size:.85rem}
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
    uploaded = st.file_uploader("Upload dataset CSV (optional)", type=["csv"])
    st.caption(f"Default path: {DATASET_PATH}")

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

# Calculate candidate indicators over request-related text columns only.
with st.spinner("Scanning HTTP/request fields for SQL-like indicators..."):
    df = df.copy()
    df["_source_row"] = range(len(df))
    df["_indicator_text"] = df.apply(lambda row: row_text(row, df), axis=1)
    df["_indicators"] = df["_indicator_text"].map(get_indicators)
    df["_sql_candidate"] = df["_indicators"].map(bool)

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
request_fields = []
for col in TEXT_COLUMNS:
    actual = find_col(df, [col])
    if actual and usable(row[actual]):
        request_fields.append((actual, str(row[actual])))

st.subheader("Selected incident")
c1, c2, c3 = st.columns(3)
c1.metric("Incident ID", str(row[id_col]))
c2.metric("SQL-like indicator groups", str(len(indicators)))
if attack_col:
    c3.metric("Dataset Attack_label", str(row[attack_col]))
else:
    c3.metric("Dataset Attack_label", "Not available")

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
    if indicators:
        for indicator in indicators:
            st.markdown(f"- **{indicator}** — matching text pattern observed in request-related fields.")
    else:
        st.success("No configured SQL-like indicators found in this record.")
    st.caption("Indicator matching is heuristic. Benign text can contain SQL keywords, and encoded or obfuscated attacks may evade these patterns.")

with right:
    st.markdown("#### Request text")
    if request_fields:
        for field_name, value in request_fields:
            st.markdown(f"**{field_name}**")
            st.code(unquote_plus(value), language="text")
    else:
        st.warning("This incident has no usable text in the configured HTTP/request columns.")

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
st.caption("Model prediction, SHAP, and LIME are intentionally not shown here. Integrate the research team's trained IDS model and its exact preprocessing pipeline before displaying model-derived explanations.")
