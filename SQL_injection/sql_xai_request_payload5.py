import html
import re
from pathlib import Path
from urllib.parse import urlsplit, unquote_plus
import pandas as pd
import streamlit as st


# ============================================================
# SQL INJECTION XAI — REQUEST & PAYLOAD ONLY
# Expected dataset: D:\4Y1S\research\xai_iiot_prototype\data\EdgeIIoT_train_80.csv
# ============================================================

st.set_page_config(
    page_title="SQL Injection XAI — Request & Payload",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)

PROJECT_ROOT = Path(r"D:\4Y1S\research\xai_iiot_prototype")
DATASET_PATH = PROJECT_ROOT / "data" / "EdgeIIoT_train_80.csv"
UNAVAILABLE = "Not available in dataset"

# Exact SQL-injection example supplied for the highlighted-payload panel.
# URL decoding is done only for display; the encoded source remains unchanged here.
SAMPLE_SQLI_PAYLOAD = (
    "id=2&Submit=Submitid%3D53%27%20AND%202161%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%282161%3D2161%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27cBFZ%27%3D%27cBFZ"
)


def normalise_name(value):
    """Normalise column names for case/space/punctuation-insensitive matching."""
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def get_value(row, candidates, default=UNAVAILABLE):
    """Return a real value from the selected CSV row, if a matching field exists."""
    normalised_columns = {normalise_name(col): col for col in row.index}
    for candidate in candidates:
        actual = normalised_columns.get(normalise_name(candidate))
        if actual is None:
            continue
        value = row[actual]
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text and text.lower() not in {"nan", "none", "null"}:
            return text
    return default


def extract_query(value):
    if not value or value == UNAVAILABLE:
        return ""
    parsed = urlsplit(value)
    if parsed.query:
        return parsed.query
    if "?" in value:
        return value.split("?", 1)[1].split("#", 1)[0]
    return ""


def build_request(row):
    method = get_value(
        row,
        ["http.request.method", "http.request_method", "request.method", "method"],
    )

    full_url = get_value(
        row,
        [
            "http.request.full_uri", "http.request_full_uri", "http.full_uri",
            "full_uri", "url", "URL",
        ],
        default="",
    )
    host = get_value(row, ["http.host", "http.host.header", "http_host", "host"], default="")
    uri = get_value(
        row,
        ["http.request.uri", "http.request_uri", "request.uri", "http.uri", "uri"],
        default="",
    )

    if full_url:
        url = full_url
    elif host and uri:
        url = f"http://{host}{uri}"
    elif uri:
        url = uri
    else:
        url = UNAVAILABLE

    query = get_value(
        row,
        [
            "http.request.uri.query", "http.request_uri_query", "http.query",
            "query_string", "query", "Query String",
        ],
        default="",
    )
    if not query:
        query = extract_query(full_url) or extract_query(uri) or UNAVAILABLE

    source_ip = get_value(
        row,
        ["ip.src_host", "ip.src", "ip.src_host.ip", "Source IP", "source_ip"],
    )
    user_agent = get_value(
        row,
        [
            "http.user_agent", "http.user_agent.header", "http_user_agent",
            "user_agent", "User-Agent", "http.user-agent",
        ],
    )
    timestamp = get_value(
        row,
        ["frame.time", "DateTime", "Timestamp", "timestamp", "time"],
    )
    if timestamp != UNAVAILABLE:
        try:
            timestamp = pd.to_datetime(timestamp, errors="raise").strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OverflowError):
            pass

    return {
        "method": method,
        "url": url,
        "query": query,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "timestamp": timestamp,
    }


def build_payload(row, request):
    # Prefer the actual query string captured in the dataset.
    query = request.get("query", "")
    if query and query != UNAVAILABLE:
        return query

    raw_request = get_value(
        row,
        [
            "http.request", "raw_http_request", "Raw HTTP Request",
            "payload", "Payload", "http.request.line",
        ],
        default="",
    )
    if raw_request:
        return raw_request

    return "Raw HTTP query/payload is not available in this dataset record."


def highlight_payload(payload):
    """Decode URL-encoded payloads and safely highlight SQLi indicators."""
    decoded = unquote_plus(str(payload))
    text = html.escape(decoded, quote=False)
    pattern = re.compile(
        r"(?P<quote>'[^']*')|"
        r"(?P<delay>\b(?:PG_SLEEP|SLEEP|BENCHMARK)\s*\([^)]*\)|"
        r"\bWAITFOR\s+DELAY\b(?:\s+'[^']*')?)|"
        r"(?P<select>\bSELECT\b|\bXMLType\b|\bUPPER\b)|"
        r"(?P<operator>\b(?:AND|OR|UNION)\b)|"
        r"(?P<boolean>\b\d+\s*=\s*\d+\b|\bCASE\s+WHEN\b)|"
        r"(?P<chr>\bCHR\s*\(\s*\d+\s*\)|\|\|)",
        re.IGNORECASE,
    )
    colors = {
        "quote": ("#ff4d4d", "Quote / string"),
        "operator": ("#f6a23a", "Logical operator"),
        "select": ("#25a7f0", "SELECT / nested query"),
        "delay": ("#35d07f", "Time-delay function"),
        "boolean": ("#a85cf5", "Boolean condition"),
        "chr": ("#35d7a0", "CHR() / string construction"),
    }

    result, last = [], 0
    for match in pattern.finditer(text):
        result.append(text[last:match.start()])
        kind = match.lastgroup
        color, label = colors[kind]
        token = match.group(0)
        result.append(
            f'<span class="sql-token" title="{label}" '
            f'style="background:{color}22;border-color:{color};color:{color}">'
            f'{token}</span>'
        )
        last = match.end()
    result.append(text[last:])
    return "".join(result)


def choose_sqli_record(data):
    """Prefer rows labelled SQL injection; otherwise use a row with SQL-like request text."""
    label_column = None
    label_candidates = {
        normalise_name(name)
        for name in ["Attack_type", "Attack Type", "attack_type", "label", "class"]
    }
    for column in data.columns:
        if normalise_name(column) in label_candidates:
            label_column = column
            break

    if label_column:
        labels = data[label_column].astype(str)
        mask = labels.str.contains(r"sql[\s_-]*injection|sqli", case=False, na=False)
        matches = data.loc[mask]
        if not matches.empty:
            return matches.iloc[0], len(matches), "labelled SQL-injection records"

    # If there is no usable SQL-injection label, look for a captured HTTP query/payload
    # containing SQL indicators. This is only a fallback, not a model classification.
    candidate_columns = [
        col for col in data.columns
        if any(term in normalise_name(col) for term in ["query", "payload", "fulluri", "requesturi", "httprequest"])
    ]
    for _, row in data.iterrows():
        sample = " ".join(str(row[col]) for col in candidate_columns if pd.notna(row[col]))
        if re.search(r"\b(select|union|sleep|pg_sleep|benchmark)\b|('|%27)\s*(and|or)\b", sample, re.I):
            return row, 1, "records with SQL-like request indicators"

    return data.iloc[0], 0, "dataset records (no SQL-injection label or raw SQL payload found)"


# Dark theme and two-panel layout only — no extra dashboard widgets.
st.markdown(
    """
    <style>
    .stApp { background: #0b1119; color: #e7eef7; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .block-container { max-width: 1500px; padding: 1rem 1rem 1.5rem; }
    .request-grid {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(0, 1.05fr);
        gap: 12px;
        align-items: stretch;
    }
    .xai-panel {
        min-width: 0;
        background: #101b28;
        border: 1px solid #26384c;
        border-radius: 10px;
        padding: 16px 18px;
        box-sizing: border-box;
    }
    .panel-title {
        color: #e7eef7;
        font-size: 16px;
        font-weight: 700;
        padding-bottom: 13px;
        margin-bottom: 9px;
        border-bottom: 1px solid #2b3e52;
    }
    .panel-icon { color: #53bdf7; margin-right: 8px; }
    .detail-row {
        display: grid;
        grid-template-columns: 112px minmax(0, 1fr);
        gap: 10px;
        padding: 7px 0;
        border-bottom: 1px solid #1d2b3b;
    }
    .detail-row:last-child { border-bottom: 0; }
    .detail-label { color: #93a8bd; font-size: 13px; }
    .detail-value {
        color: #e7eef7;
        font-size: 13px;
        overflow-wrap: anywhere;
        line-height: 1.45;
    }
    .method {
        display: inline-block;
        background: #4b2530;
        color: #ff6870;
        border: 1px solid #79333d;
        border-radius: 5px;
        padding: 2px 8px;
        font-size: 12px;
        font-weight: 700;
    }
    .payload-box {
        background: #0a111b;
        border: 1px solid #385069;
        border-radius: 9px;
        padding: 16px 14px;
        min-height: 76px;
        overflow-x: auto;
    }
    .payload-text {
        color: #e9f1f9;
        font-family: Consolas, "Courier New", monospace;
        font-size: 14px;
        line-height: 1.8;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
    }
    .sql-token {
        display: inline-block;
        padding: 1px 5px;
        margin: 0 1px;
        border: 1px solid;
        border-radius: 5px;
        font-weight: 700;
    }
    .legend { display: flex; flex-wrap: wrap; gap: 10px 14px; margin-top: 14px; }
    .legend-item { color: #c4d0dd; font-size: 11px; display: flex; align-items: center; gap: 6px; }
    .legend-dot { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
    .notice {
        color: #aebed0; background: #111d2a; border: 1px solid #293b4e;
        border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; font-size: 13px;
    }
    @media (max-width: 760px) {
        .request-grid { grid-template-columns: 1fr; }
        .detail-row { grid-template-columns: 100px minmax(0, 1fr); }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Resolve the CSV from common project locations first. If it is not there,
# let the user select the dataset in the app instead of crashing.
def find_dataset_path():
    script_dir = Path(__file__).resolve().parent
    candidates = [
        PROJECT_ROOT / "data" / "SQL_injection_train_80.csv",
        script_dir / "data" / "SQL_injection_train_80.csv",
        script_dir / "SQL_injection_train_80.csv",
        script_dir.parent / "data" / "SQL_injection_train_80.csv",
        script_dir.parent / "SQL_injection_train_80.csv",
        Path.cwd() / "data" / "SQL_injection_train_80.csv",
        Path.cwd() / "SQL_injection_train_80.csv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return DATASET_PATH if DATASET_PATH.is_file() else None


resolved_dataset_path = find_dataset_path()

if resolved_dataset_path is not None:
    try:
        dataset = pd.read_csv(resolved_dataset_path, low_memory=False)
        st.caption(f"Dataset: `{resolved_dataset_path}`")
    except Exception as exc:
        st.error(f"Could not read the dataset at `{resolved_dataset_path}`: {exc}")
        st.stop()
else:
    st.warning(
        "EdgeIIoT_train_80.csv was not found automatically. "
        "Choose the CSV file below, or place it in a `data` folder next to this script."
    )
    uploaded_dataset = st.file_uploader(
        "Select EdgeIIoT_train_80.csv",
        type=["csv"],
        key="edgeiiot_dataset_upload",
    )
    if uploaded_dataset is None:
        st.stop()
    try:
        dataset = pd.read_csv(uploaded_dataset, low_memory=False)
        st.caption(f"Dataset loaded from upload: `{uploaded_dataset.name}`")
    except Exception as exc:
        st.error(f"Could not read the uploaded CSV: {exc}")
        st.stop()

if dataset.empty:
    st.error("The dataset is empty.")
    st.stop()

selected_row, sqli_count, selection_reason = choose_sqli_record(dataset)
request = build_request(selected_row)
payload = SAMPLE_SQLI_PAYLOAD  # display the exact payload supplied for this UI example

if sqli_count:
    st.markdown(
        f'<div class="notice">Showing one of {sqli_count:,} {html.escape(selection_reason)} '
        f'from <code>EdgeIIoT_train_80.csv</code>.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        f'<div class="notice">Showing a dataset record from <code>EdgeIIoT_train_80.csv</code>. '
        f'{html.escape(selection_reason.capitalize())}. Missing raw HTTP fields are not fabricated.</div>',
        unsafe_allow_html=True,
    )

# Render each panel as one HTML block inside Streamlit columns.
left_col, right_col = st.columns([1, 1.05], gap="small")

# Panel 1: HTTP request details
with left_col:
    detail_rows = []
    for label, value, is_method in [
        ("Method", request["method"], True),
        ("URL", request["url"], False),
        ("Query String", request["query"], False),
        ("Source IP", request["source_ip"], False),
        ("User-Agent", request["user_agent"], False),
        ("Timestamp", request["timestamp"], False),
    ]:
        shown = (
            f'<span class="method">{html.escape(value)}</span>'
            if is_method else html.escape(value)
        )
        detail_rows.append(
            f'<div class="detail-row"><div class="detail-label">{label}</div>'
            f'<div class="detail-value">{shown}</div></div>'
        )

    request_panel_html = (
        '<section class="xai-panel">'
        '<div class="panel-title"><span class="panel-icon">▤</span>HTTP Request Details</div>'
        + "".join(detail_rows)
        + '</section>'
    )
    st.markdown(request_panel_html, unsafe_allow_html=True)

# Panel 2: highlighted SQL payload
with right_col:
    payload_panel_html = (
        '<section class="xai-panel">'
        '<div class="panel-title"><span class="panel-icon">&lt;/&gt;</span>'
        'Payload with Highlighted Indicators</div>'
        f'<div class="payload-box"><div class="payload-text">{highlight_payload(payload)}</div></div>'
        '<div class="legend">'
        '<div class="legend-item"><span class="legend-dot" style="background:#ff4d4d"></span>Quote / string</div>'
        '<div class="legend-item"><span class="legend-dot" style="background:#f6a23a"></span>Logical operator</div>'
        '<div class="legend-item"><span class="legend-dot" style="background:#25a7f0"></span>SELECT / nested query</div>'
        '<div class="legend-item"><span class="legend-dot" style="background:#35d07f"></span>CHR() / string construction</div>'
        '<div class="legend-item"><span class="legend-dot" style="background:#a85cf5"></span>Boolean condition</div>'
        '</div></section>'
    )
    st.markdown(payload_panel_html, unsafe_allow_html=True)
