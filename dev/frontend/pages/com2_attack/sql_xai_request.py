import streamlit as st
import pandas as pd
from datetime import date, time, datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import re
import html


# ============================================================
# STREAMLIT PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Network Intrusion Detection System (IDS)",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CURRENT DATE & TIME
# ============================================================

@st.fragment(run_every="30s")
def display_current_datetime():

    # Sri Lanka Time
    sri_lanka_time = datetime.now(
        ZoneInfo("Asia/Colombo")
    )

    current_date = sri_lanka_time.strftime("%b %d, %Y")
    current_time = sri_lanka_time.strftime("%H:%M:%S")

    st.markdown(
        f"""
        <div style="
            position: fixed;
            top: 12px;
            right: 30px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 15px;
            color: #cbd5e1;
            font-weight: 500;
            z-index: 999999;
            background: #0e1117;
            padding: 6px 12px;
            border-radius: 8px;
        ">
            <span style="font-size: 20px;">🗓️</span>
            <span>{current_date}</span>
            <span>{current_time}</span>
        </div>
        """,
        unsafe_allow_html=True
    )


display_current_datetime()


# ============================================================
# SIDEBAR → MAIN DASHBOARD ATTACK TYPE MAPPING
# ============================================================

ATTACK_TYPE_MAPPING = {

    "SQL Injection": [
        "sql_injection",
        "sql injection",
        "sqlinjection"
    ],

    "Port Scanning": [
        "port_scanning",
        "port scanning",
        "port_scan",
        "port scan"
    ],

    "MITM": [
        "mitm",
        "man_in_the_middle",
        "man in the middle",
        "mitm_attack"
    ],

    "DDoS HTTP Flood": [
        "ddos_http",
        "ddos http",
        "ddos_http_flood",
        "ddos http flood",
        "ddos_http_flooding",
        "ddos http flooding"
    ],

    "OS Fingerprinting": [
        "os_fingerprinting",
        "os fingerprinting",
        "osfingerprinting"
    ],

    "XSS": [
        "xss",
        "cross_site_scripting",
        "cross site scripting"
    ],

    "Uploading": [
        "uploading",
        "upload"
    ],

    "Vulnerability Scanner": [
        "vulnerability_scanner",
        "vulnerability scanner",
        "vulnerabilityscanner"
    ],

    "Backdoor": [
        "backdoor"
    ],

    "Ransomware": [
        "ransomware"
    ],

    "Normal/Benign": [
        "normal",
        "normal/benign",
        "normal_benign",
        "benign"
    ]
}


# ============================================================
# HELPER FUNCTION
# NORMALIZE ATTACK TYPE VALUES
# ============================================================

def normalize_attack_type(value):

    return re.sub(
        r"[^a-z0-9]+",
        "",
        str(value).strip().lower()
    )


# ============================================================
# CREATE NORMALIZED ATTACK TYPE MAPPING
# ============================================================

NORMALIZED_ATTACK_TYPE_MAPPING = {
    key: {
        normalize_attack_type(value)
        for value in values
    }
    for key, values in ATTACK_TYPE_MAPPING.items()
}


# ============================================================
# DETECTION MODULE SIDEBAR
# ============================================================

with st.sidebar:

    # --------------------------------------------------------
    # Back button
    # --------------------------------------------------------

    if st.button(
        "‹‹",
        key="back_btn",
        use_container_width=False
    ):
        st.session_state["detection_page"] = False

    st.markdown("## DETECTION MODULE")

    st.markdown("---")


    # --------------------------------------------------------
    # Attack / Traffic Type
    # --------------------------------------------------------

    st.markdown("**Attack / Traffic Type**")

    detection_type = st.selectbox(
        "Attack / Traffic Type",
        [
            "All",
            "SQL Injection",
            "Port Scanning",
            "MITM",
            "DDoS HTTP Flood",
            "OS Fingerprinting",
            "XSS",
            "Uploading",
            "Vulnerability Scanner",
            "Backdoor",
            "Ransomware",
            "Normal/Benign"
        ],
        index=0,
        label_visibility="collapsed",
        key="detection_type"
    )


    # --------------------------------------------------------
    # Traffic Source
    # --------------------------------------------------------

    st.markdown("**Traffic Source**")

    traffic_source = st.selectbox(
        "Traffic Source",
        [
            "Dataset",
            "Uploaded CSV",
            "Live Traffic"
        ],
        index=0,
        label_visibility="collapsed",
        key="traffic_source"
    )


    # --------------------------------------------------------
    # Dataset
    # --------------------------------------------------------

    if traffic_source == "Dataset":

        st.markdown("**Dataset**")

        dataset = st.selectbox(
            "Dataset",
            [
                "IDS Test Dataset",
                "IDS Validation Dataset"
            ],
            index=0,
            label_visibility="collapsed",
            key="dataset_select"
        )


    elif traffic_source == "Uploaded CSV":

        st.markdown("**Upload Dataset**")

        uploaded_file = st.file_uploader(
            "Upload CSV",
            type=["csv"],
            label_visibility="collapsed",
            key="uploaded_csv"
        )


    # --------------------------------------------------------
    # Traffic Record
    # --------------------------------------------------------

    st.markdown("**Traffic Record**")

    if "traffic_record" not in st.session_state:
        st.session_state["traffic_record"] = 0

    total_records = 10000

    col1, col2, col3 = st.columns([1, 3, 1])


    with col1:

        if st.button(
            "−",
            key="previous_record",
            use_container_width=True
        ):

            if st.session_state["traffic_record"] > 0:

                st.session_state["traffic_record"] -= 1


    with col2:

        record_number = st.session_state["traffic_record"] + 1

        st.markdown(
            f"""
            <div style="
             text-align:center;
             padding-top:8px;
            ">
             <b>Record {record_number:03d}</b>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:

        if st.button(
            "+",
            key="next_record",
            use_container_width=True
        ):

            if (
                st.session_state["traffic_record"]
                < total_records - 1
            ):

                st.session_state["traffic_record"] += 1


    # --------------------------------------------------------
    # Record counter
    # --------------------------------------------------------

    st.markdown(
        f"""
        <div style="
            text-align:center;
            color:#888;
            margin-top:5px;
        ">
            {
                st.session_state["traffic_record"] + 1
            :,} / {total_records:,}
        </div>
        """,
        unsafe_allow_html=True
    )


    st.markdown("<br>", unsafe_allow_html=True)


    # --------------------------------------------------------
    # Analyze Traffic
    # --------------------------------------------------------

    analyze_clicked = st.button(
        "🔍  Analyze Traffic",
        use_container_width=True,
        type="primary",
        key="analyze_traffic"
    )


    # --------------------------------------------------------
    # Explain Prediction
    # --------------------------------------------------------

    explain_clicked = st.button(
        "✨  Explain Prediction",
        use_container_width=True,
        key="explain_prediction"
    )


    st.markdown("---")


    # --------------------------------------------------------
    # Analysis Status
    # --------------------------------------------------------

    st.markdown("**Analysis Status**")

    if "analysis_status" not in st.session_state:

        st.session_state["analysis_status"] = "Ready"


    status = st.session_state["analysis_status"]


    if status == "Ready":

        st.markdown("🟢 **Ready**")


    elif status == "Analyzing":

        st.markdown("🔵 **Analyzing**")


    elif status == "Complete":

        st.markdown("🟢 **Analysis Complete**")


    elif status == "Explanation Pending":

        st.markdown("🟠 **Explanation Pending**")


    elif status == "Error":

        st.markdown("🔴 **Error**")


    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    st.markdown("**Prediction**")

    prediction = st.session_state.get(
        "prediction",
        "—"
    )

    st.markdown(
        f"""
        <div style="
            font-size:18px;
            font-weight:600;
        ">
            {prediction}
        </div>
        """,
        unsafe_allow_html=True
    )


    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    st.markdown("**Confidence**")

    confidence = st.session_state.get(
        "confidence",
        None
    )


    if confidence is None:

        st.markdown("—")

    else:

        st.markdown(
            f"""
            <div style="
                font-size:18px;
                font-weight:600;
            ">
                {confidence:.1f}%
            </div>
            """,
            unsafe_allow_html=True
        )


    st.markdown("<br>", unsafe_allow_html=True)


    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    reset_clicked = st.button(
        "↻  Reset Analysis",
        use_container_width=True,
        key="reset_analysis"
    )


# ============================================================
# SIDEBAR ACTIONS
# ============================================================

if analyze_clicked:

    st.session_state["analysis_status"] = "Analyzing"

    st.session_state["prediction"] = "—"

    st.session_state["confidence"] = None

    st.rerun()


if explain_clicked:

    if st.session_state.get(
        "prediction"
    ) in [None, "—"]:

        st.warning(
            "Please analyze the traffic record "
            "before requesting an explanation."
        )

    else:

        st.session_state[
            "analysis_status"
        ] = "Explanation Pending"

        st.rerun()


if reset_clicked:

    st.session_state["traffic_record"] = 0

    st.session_state[
        "analysis_status"
    ] = "Ready"

    st.session_state["prediction"] = "—"

    st.session_state["confidence"] = None

    st.session_state.pop(
        "shap_values",
        None
    )

    st.session_state.pop(
        "lime_explanation",
        None
    )

    st.session_state.pop(
        "current_record",
        None
    )

    st.session_state["incident_selected"] = False
    st.session_state.pop(
        "selected_incident_data",
        None
    )

    st.rerun()



# ============================================================
# SQL INJECTION XAI → REQUEST / PAYLOAD HELPERS
# ============================================================

def get_first_value(row, column_names, default="—"):
    """Return the first usable value from a row using candidate column names."""
    for column in column_names:
        if column in row.index:
            value = row[column]
            if pd.notna(value) and str(value).strip() not in {"", "nan", "None"}:
                return str(value).strip()
    return default


def build_request_details(row):
    """Read HTTP request metadata only from fields present in the selected dataset row.

    Missing packet-level fields are labelled as unavailable instead of being
    filled with fabricated demo values.
    """
    unavailable = "Not available in dataset"

    method = get_first_value(
        row,
        [
            "http.request.method", "http.request_method",
            "request.method", "Method", "method"
        ],
        unavailable
    )

    full_uri = get_first_value(
        row,
        [
            "http.request.full_uri", "http.request_full_uri",
            "http.full_uri", "Full URI", "full_uri", "url", "URL"
        ],
        ""
    )
    host = get_first_value(
        row,
        ["http.host", "http.host.header", "http_host", "Host", "host"],
        ""
    )
    uri = get_first_value(
        row,
        [
            "http.request.uri", "http.request_uri", "request.uri",
            "URI", "uri", "http.uri"
        ],
        ""
    )
    query = get_first_value(
        row,
        [
            "http.request.uri.query", "http.request_uri_query",
            "http.query", "query", "Query String", "query_string"
        ],
        ""
    )

    if full_uri:
        url = full_uri
    elif host and uri:
        url = f"http://{host}{uri}"
    elif uri:
        # A URI/path is shown as-is if the dataset has no host/scheme.
        url = uri
    elif host:
        url = host
    else:
        url = unavailable

    if not query and full_uri and "?" in full_uri:
        query = extract_query_from_url(full_uri)
    elif not query and uri and "?" in uri:
        query = extract_query_from_url(uri)

    source_ip = get_first_value(
        row,
        ["ip.src_host", "ip.src", "ip.src_host.ip", "Source IP", "source_ip"],
        unavailable
    )
    user_agent = get_first_value(
        row,
        [
            "http.user_agent", "http.user_agent.header", "http_user_agent",
            "User-Agent", "user_agent", "http.user-agent"
        ],
        unavailable
    )
    timestamp = get_first_value(
        row,
        ["frame.time", "DateTime", "Timestamp", "timestamp"],
        unavailable
    )

    if timestamp != unavailable:
        try:
            timestamp = pd.to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            pass

    return {
        "method": method,
        "url": url,
        "query": query if query else unavailable,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "timestamp": timestamp,
    }


def extract_query_from_url(url):
    """Extract a query string from a URL/URI, if one exists."""
    if not url or "?" not in str(url):
        return ""
    return str(url).split("?", 1)[1]


def build_payload(row, request_details):
    """Use only the selected dataset row's raw query/payload fields."""
    query = request_details.get("query", "")
    if query and query != "Not available in dataset":
        return query

    for column in [
        "http.request.uri.query", "http.request_uri_query", "http.query",
        "query", "Query String", "query_string", "payload", "Payload",
        "http.request", "raw_http_request", "Raw HTTP Request"
    ]:
        if column in row.index:
            value = row[column]
            if pd.notna(value) and str(value).strip() not in {"", "nan", "None"}:
                return str(value).strip()

    return "Raw HTTP query/payload is not available in this dataset record."


def highlight_sql_payload(payload):
    """
    Highlight SQL-Injection indicators with category-specific colors.
    The HTML is escaped first so payload text cannot inject dashboard HTML.
    """
    text = html.escape(str(payload), quote=False)

    token_pattern = re.compile(
        r"(?P<delay>\b(?:PG_SLEEP|SLEEP|BENCHMARK)\s*\([^)]*\)|"
        r"\bWAITFOR\s+DELAY\b(?:\s+'[^']*')?)|"
        r"(?P<select>\bSELECT\b)|"
        r"(?P<operator>\b(?:AND|OR|UNION)\b)|"
        r"(?P<boolean>\b(?:\d+\s*=\s*\d+|[A-Za-z0-9_]+\s*=\s*'[A-Za-z0-9_]+'\s*))|"
        r"(?P<quote>'[^']*')",
        re.IGNORECASE
    )

    styles = {
        "quote": ("#ff4d4d", "Quote / String termination"),
        "operator": ("#f6a23a", "Logical operator"),
        "select": ("#25a7f0", "Nested query (SELECT)"),
        "delay": ("#35d07f", "Time-delay function"),
        "boolean": ("#a85cf5", "Boolean condition"),
    }

    output = []
    last = 0

    for match in token_pattern.finditer(text):
        output.append(text[last:match.start()])
        kind = match.lastgroup
        value = match.group(0)
        color, title = styles[kind]

        output.append(
            f'<span class="sql-token sql-{kind}" title="{title}" '
            f'style="background:{color}22;border-color:{color};color:{color};">'
            f'{value}</span>'
        )
        last = match.end()

    output.append(text[last:])
    return "".join(output)


def render_request_payload_section(row):
    """Render the first Request & Payload section of the SQL-Injection XAI page."""
    request = build_request_details(row)
    payload = build_payload(row, request)

    st.markdown(
        """
        <style>
        .xai-request-card {
            background: #0e1722;
            border: 1px solid #26384c;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 8px;
        }

        .xai-request-grid {
            display: grid;
            grid-template-columns: 1fr 1.05fr;
            gap: 12px;
        }

        .xai-panel {
            background: #101b28;
            border: 1px solid #26384c;
            border-radius: 10px;
            padding: 16px 18px;
        }

        .xai-panel-title {
            color: #dce8f5;
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 12px;
        }

        .xai-panel-title .icon {
            color: #53bdf7;
            margin-right: 7px;
        }

        .xai-detail-row {
            display: grid;
            grid-template-columns: 125px 1fr;
            gap: 12px;
            padding: 7px 0;
            border-bottom: 1px solid #1d2b3b;
        }

        .xai-detail-row:last-child {
            border-bottom: 0;
        }

        .xai-detail-label {
            color: #93a8bd;
            font-size: 13px;
            font-weight: 600;
        }

        .xai-detail-value {
            color: #e7eef7;
            font-size: 13px;
            word-break: break-word;
        }

        .xai-method {
            display: inline-block;
            background: #4b2530;
            color: #ff6870;
            border: 1px solid #79333d;
            border-radius: 5px;
            padding: 2px 9px;
            font-weight: 700;
            font-size: 12px;
        }

        .xai-payload-box {
            background: #0a111b;
            border: 1px solid #385069;
            border-radius: 9px;
            padding: 17px 15px;
            min-height: 58px;
            display: flex;
            align-items: center;
            overflow-x: auto;
        }

        .xai-payload-text {
            color: #e9f1f9;
            font-family: Consolas, "Courier New", monospace;
            font-size: 14px;
            line-height: 1.65;
            white-space: nowrap;
        }

        .sql-token {
            display: inline-block;
            padding: 1px 5px;
            margin: 0 1px;
            border: 1px solid;
            border-radius: 4px;
            font-weight: 700;
        }

        .xai-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 9px 15px;
            margin-top: 12px;
        }

        .xai-legend-item {
            color: #9fb0c1;
            font-size: 11px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .xai-legend-dot {
            width: 9px;
            height: 9px;
            border-radius: 2px;
            display: inline-block;
        }

        @media (max-width: 900px) {
            .xai-request-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="xai-request-grid">',
        unsafe_allow_html=True
    )

    # ---------------- HTTP Request Details ----------------
    st.markdown(
        '<div class="xai-panel">'
        '<div class="xai-panel-title"><span class="icon">▣</span>'
        'HTTP Request Details</div>',
        unsafe_allow_html=True
    )

    rows = [
        ("Method", f'<span class="xai-method">{html.escape(request["method"])}</span>'),
        ("URL", html.escape(request["url"])),
        ("Query String", html.escape(request["query"])),
        ("Source IP", html.escape(request["source_ip"])),
        ("User-Agent", html.escape(request["user_agent"])),
        ("Timestamp", html.escape(request["timestamp"])),
    ]

    for label, value in rows:
        st.markdown(
            f'<div class="xai-detail-row">'
            f'<div class="xai-detail-label">{label}</div>'
            f'<div class="xai-detail-value">{value}</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------- Highlighted Payload ----------------
    st.markdown(
        '<div class="xai-panel">'
        '<div class="xai-panel-title"><span class="icon">⌘</span>'
        'Payload with Highlighted Indicators</div>'
        f'<div class="xai-payload-box">'
        f'<div class="xai-payload-text">{highlight_sql_payload(payload)}</div>'
        f'</div>'
        '<div class="xai-legend">'
        '<div class="xai-legend-item"><span class="xai-legend-dot" style="background:#ff4d4d"></span>Quote / String termination</div>'
        '<div class="xai-legend-item"><span class="xai-legend-dot" style="background:#f6a23a"></span>Logical operator</div>'
        '<div class="xai-legend-item"><span class="xai-legend-dot" style="background:#25a7f0"></span>Nested query (SELECT)</div>'
        '<div class="xai-legend-item"><span class="xai-legend-dot" style="background:#35d07f"></span>Time-delay function</div>'
        '<div class="xai-legend-item"><span class="xai-legend-dot" style="background:#a85cf5"></span>Boolean condition</div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("</div>", unsafe_allow_html=True)



# ============================================================
# MAIN DASHBOARD
# ============================================================


# ============================================================
# INCIDENT SEARCH MODULE CSS
# ============================================================

st.markdown(
    """
    <style>

    .incident-search-box {
        background-color: #ffffff;
        border: 1px solid #d9e2ec;
        border-radius: 12px;
        padding: 24px 26px 22px 26px;
        margin-bottom: 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }

    .incident-title {
        font-size: 25px;
        font-weight: 700;
        color: #123f73;
        margin-bottom: 2px;
    }

    .incident-subtitle {
        font-size: 16px;
        color: #718096;
        margin-bottom: 25px;
    }

    .section-label {
        font-size: 16px;
        font-weight: 700;
        color: #163d6b;
        margin-top: 5px;
        margin-bottom: 8px;
    }

    .search-divider {
        border-top: 1px solid #dfe7ef;
        margin: 20px 0;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# INCIDENT DATA
# ============================================================

# Define sidebar defaults before loading the dataset. If the CSV is missing,
# the rest of the page can still render without NameError exceptions.
selected_attack = st.session_state.get("detection_type", "All")
selected_source = st.session_state.get("traffic_source", "Dataset")

DATASET_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "EdgeIIoT_train_80.csv"
)


try:

    if DATASET_PATH.exists():
        incident_data = pd.read_csv(
            DATASET_PATH,
            low_memory=False
        )
    else:
        st.warning(
            f"Dataset file not found at: {DATASET_PATH}. "
            "Upload the CSV below, or place it in the project's data folder."
        )
        uploaded_dataset_fallback = st.file_uploader(
            "Upload EdgeIIoT_train_80.csv",
            type=["csv"],
            key="dataset_fallback_upload"
        )
        if uploaded_dataset_fallback is None:
            raise FileNotFoundError(DATASET_PATH)
        incident_data = pd.read_csv(
            uploaded_dataset_fallback,
            low_memory=False
        )


    # ========================================================
    # GENERATE INCIDENT IDs
    # ========================================================

    if "Incident ID" not in incident_data.columns:

        incident_data.insert(
            0,
            "Incident ID",
            [
                f"ALR-{i:06d}"
                for i in range(
                    1,
                    len(incident_data) + 1
                )
            ]
        )


    # ========================================================
    # CONVERT frame.time TO DATETIME
    # ========================================================

    if "frame.time" in incident_data.columns:

        incident_data["DateTime"] = pd.to_datetime(
            incident_data["frame.time"]
            .astype(str)
            .str.strip(),
            errors="coerce"
        )

    else:

        st.error(
            "The dataset does not contain the required "
            "'frame.time' column."
        )

        incident_data["DateTime"] = pd.NaT


    # ========================================================
    # CREATE DATE AND TIME
    # ========================================================

    incident_data["Date"] = (
        incident_data["DateTime"].dt.date
    )

    incident_data["Time"] = (
        incident_data["DateTime"].dt.time
    )


    # ========================================================
    # CREATE SOURCE IP
    # ========================================================

    if "ip.src_host" in incident_data.columns:

        incident_data["Source IP"] = (
            incident_data["ip.src_host"]
            .astype(str)
            .str.strip()
        )

    else:

        incident_data["Source IP"] = "Unknown"


    # ========================================================
    # CREATE TRAFFIC TYPE
    # Normal / Attack
    # ========================================================

    if "Attack_label" in incident_data.columns:

        incident_data["Type"] = (
            incident_data["Attack_label"]
            .apply(
                lambda x:
                "Normal"
                if str(x).strip()
                in ["0", "0.0"]
                else "Attack"
            )
        )

    else:

        # If Attack_label does not exist,
        # determine Type from Attack_type.

        if "Attack_type" in incident_data.columns:

            incident_data["Type"] = (
                incident_data["Attack_type"]
                .apply(
                    lambda x:
                    "Normal"
                    if normalize_attack_type(x)
                    in NORMALIZED_ATTACK_TYPE_MAPPING[
                        "Normal/Benign"
                    ]
                    else "Attack"
                )
            )

        else:

            incident_data["Type"] = "Unknown"


    # ========================================================
    # CREATE ATTACK TYPE
    # ========================================================

    # Find the attack type column regardless of capitalization
    # or small naming differences.

    attack_type_column = None

    possible_attack_columns = [
        "Attack_type",
        "Attack Type",
        "attack_type",
        "attack type",
        "AttackType",
        "attacktype"
    ]


    for column in incident_data.columns:

        normalized_column = (
            str(column)
            .strip()
            .lower()
            .replace(" ", "_")
        )

        if normalized_column in [
            "attack_type",
            "attacktype"
        ]:

            attack_type_column = column
            break


    if attack_type_column is not None:

        incident_data["Attack Type"] = (
            incident_data[attack_type_column]
            .astype(str)
            .str.strip()
        )

    else:

        incident_data["Attack Type"] = (
            incident_data["Type"]
            .apply(
                lambda x:
                "Normal"
                if x == "Normal"
                else "Unknown"
            )
        )


    # ========================================================
    # CREATE SEVERITY
    # ========================================================

    incident_data["Severity"] = (
        incident_data["Type"]
        .apply(
            lambda x:
            "Low"
            if x == "Normal"
            else "High"
        )
    )


    # ========================================================
    # CREATE STATUS
    # ========================================================

    incident_data["Status"] = (
        incident_data["Type"]
        .apply(
            lambda x:
            "Normal"
            if x == "Normal"
            else "Open"
        )
    )


    # ========================================================
    # REMOVE INVALID TIMESTAMPS
    # ========================================================

    incident_data = (
        incident_data
        .dropna(
            subset=["DateTime"]
        )
        .reset_index(drop=True)
    )


    # ========================================================
    # SUCCESS MESSAGE
    # ========================================================

    st.success(
        f"Loaded {len(incident_data):,} "
        f"incident records successfully."
    )


except FileNotFoundError:

    st.error(
        f"Dataset not found at:\n"
        f"{DATASET_PATH}\n\n"
        f"Make sure EdgeIIoT_train_80.csv "
        f"is inside the data folder."
    )

    incident_data = pd.DataFrame()


except Exception as e:

    st.error(
        f"Error loading incident dataset:\n{e}"
    )

    incident_data = pd.DataFrame()


# ============================================================
# APPLY SIDEBAR ATTACK TYPE FILTER
# ============================================================

if not incident_data.empty:

    # Keep the defaults in sync with the current sidebar controls.
    selected_attack = st.session_state.get("detection_type", selected_attack)
    selected_source = st.session_state.get("traffic_source", selected_source)


    # --------------------------------------------------------
    # DATASET SOURCE
    # --------------------------------------------------------

    if selected_source == "Dataset":

        # ----------------------------------------------------
        # ALL ATTACK TYPES
        # ----------------------------------------------------

        if selected_attack == "All":

            sidebar_filtered_data = (
                incident_data.copy()
            )


        # ----------------------------------------------------
        # SPECIFIC ATTACK TYPE
        # ----------------------------------------------------

        else:

            allowed_attack_types = (
                NORMALIZED_ATTACK_TYPE_MAPPING.get(
                    selected_attack,
                    set()
                )
            )


            sidebar_filtered_data = (
                incident_data[
                    incident_data["Attack Type"]
                    .apply(normalize_attack_type)
                    .isin(allowed_attack_types)
                ]
                .copy()
            )


    # --------------------------------------------------------
    # UPLOADED CSV
    # --------------------------------------------------------

    elif selected_source == "Uploaded CSV":

        uploaded_file = st.session_state.get(
            "uploaded_csv",
            None
        )

        if uploaded_file is not None:

            try:

                uploaded_data = pd.read_csv(
                    uploaded_file,
                    low_memory=False
                )

                sidebar_filtered_data = (
                    uploaded_data.copy()
                )

            except Exception:

                sidebar_filtered_data = (
                    incident_data.copy()
                )

        else:

            sidebar_filtered_data = (
                incident_data.copy()
            )


    # --------------------------------------------------------
    # LIVE TRAFFIC
    # --------------------------------------------------------

    else:

        sidebar_filtered_data = (
            incident_data.copy()
        )

else:

    sidebar_filtered_data = pd.DataFrame()


# ============================================================
# STORE CURRENT SIDEBAR FILTER
# ============================================================

current_sidebar_signature = (
    selected_source
    if "selected_source" in locals()
    else "Dataset",

    selected_attack
    if "selected_attack" in locals()
    else "All"
)


previous_sidebar_signature = (
    st.session_state.get(
        "previous_sidebar_signature"
    )
)


# ============================================================
# DETECT SIDEBAR FILTER CHANGE
# ============================================================

if (
    previous_sidebar_signature
    != current_sidebar_signature
):

    st.session_state[
        "previous_sidebar_signature"
    ] = current_sidebar_signature

    # Reset previous search results so the
    # newly selected sidebar attack immediately
    # controls the main dashboard.

    st.session_state[
        "incident_search_performed"
    ] = False

    st.session_state[
        "incident_results"
    ] = sidebar_filtered_data.copy()

    st.session_state[
        "incident_id_error"
    ] = ""

    st.session_state[
        "incident_id_found"
    ] = False


# ============================================================
# INCIDENT SEARCH UI
# ============================================================

    st.markdown(
        """
       
        <div class="incident-title">
                🔎 INCIDENT SEARCH
        </div>
        
        """,
        unsafe_allow_html=True
    )


# ============================================================
# SHOW ACTIVE SIDEBAR FILTER
# ============================================================

if selected_source == "Dataset":

    if selected_attack == "All":

        st.info(
            "📊 Showing incidents from the complete dataset."
        )

    else:

        st.info(
            f"🎯 Showing incidents filtered by sidebar: "
            f"**{selected_attack}**"
        )


# ============================================================
# INCIDENT ID SEARCH
# ============================================================

st.markdown("**Incident ID**")


id_col1, id_col2 = st.columns([4, 1])


with id_col1:

    incident_id = st.text_input(
        "Incident ID",
        placeholder="Search incident ID...",
        label_visibility="collapsed",
        key="incident_id_search"
    )


# ============================================================
# SEARCH INCIDENT BY ID
# ============================================================

def search_incident_by_id():

    query = (
        st.session_state
        .get(
            "incident_id_search",
            ""
        )
        .strip()
    )


    if not query:

        st.session_state[
            "incident_id_error"
        ] = "Please enter an Incident ID."

        st.session_state[
            "incident_id_found"
        ] = False

        return


    # Search inside the currently selected sidebar dataset
    search_data = sidebar_filtered_data


    if search_data.empty:

        st.session_state[
            "incident_id_error"
        ] = (
            "No incidents are available "
            "for the selected attack type."
        )

        st.session_state[
            "incident_id_found"
        ] = False

        return


    # Exact Incident ID match

    matches = search_data[
        search_data["Incident ID"]
        .astype(str)
        .str.strip()
        .str.upper()
        == query.upper()
    ]


    if matches.empty:

        st.session_state[
            "incident_id_error"
        ] = (
            f"Incident ID '{query}' "
            f"was not found in the selected data."
        )

        st.session_state[
            "incident_id_found"
        ] = False

        return


    selected = matches.iloc[0]

    incident_datetime = pd.to_datetime(
        selected["DateTime"]
    )


    # Automatically update time range

    st.session_state[
        "from_date"
    ] = incident_datetime.date()

    st.session_state[
        "from_time"
    ] = incident_datetime.time().replace(
        microsecond=0
    )

    st.session_state[
        "to_date"
    ] = incident_datetime.date()

    st.session_state[
        "to_time"
    ] = incident_datetime.time().replace(
        microsecond=0
    )


    # Save result

    st.session_state[
        "incident_results"
    ] = matches.copy()

    st.session_state[
        "incident_search_performed"
    ] = True

    st.session_state[
        "incident_id_found"
    ] = True

    st.session_state[
        "incident_id_error"
    ] = ""

    st.session_state[
        "selected_incident_data"
    ] = selected.to_dict()


with id_col2:

    st.button(
        "🔍  Search",
        use_container_width=True,
        key="incident_id_button",
        on_click=search_incident_by_id
    )


# ============================================================
# DIVIDER
# ============================================================

st.markdown(
    '<div class="search-divider"></div>',
    unsafe_allow_html=True
)


# ============================================================
# TIME RANGE
# ============================================================

st.markdown(
    '<div class="section-label">Time Range</div>',
    unsafe_allow_html=True
)


col1, col2, col3, col4 = st.columns(4)


# ------------------------------------------------------------
# From Date
# ------------------------------------------------------------

with col1:

    from_date = st.date_input(
        "From Date",
        value=datetime.now(
            ZoneInfo("Asia/Colombo")
        ).date(),
        key="from_date"
    )


# ------------------------------------------------------------
# From Time
# ------------------------------------------------------------

with col2:

    from_time = st.time_input(
        "From Time",
        value=time(8, 0),
        key="from_time"
    )


# ------------------------------------------------------------
# To Date
# ------------------------------------------------------------

with col3:

    to_date = st.date_input(
        "To Date",
        value=datetime.now(
            ZoneInfo("Asia/Colombo")
        ).date(),
        key="to_date"
    )


# ------------------------------------------------------------
# To Time
# ------------------------------------------------------------

with col4:

    to_time = st.time_input(
        "To Time",
        value=time(12, 0),
        key="to_time"
    )


# ============================================================
# FILTERS
# ============================================================

filter_col1, filter_col2, filter_col3, button_col = (
    st.columns(
        [1, 1, 1, 1.15]
    )
)


# ------------------------------------------------------------
# Traffic Type
# ------------------------------------------------------------

with filter_col1:

    traffic_type = st.selectbox(
        "Traffic Type",
        [
            "All",
            "Normal",
            "Attack"
        ],
        key="traffic_type_filter"
    )


# ------------------------------------------------------------
# Severity
# ------------------------------------------------------------

with filter_col2:

    severity = st.selectbox(
        "Severity",
        [
            "All",
            "Critical",
            "High",
            "Medium",
            "Low"
        ],
        key="severity_filter"
    )


# ------------------------------------------------------------
# Status
# ------------------------------------------------------------

with filter_col3:

    status = st.selectbox(
        "Status",
        [
            "All",
            "Open",
            "Investigating",
            "Resolved",
            "Normal"
        ],
        key="status_filter"
    )


# ============================================================
# SEARCH BUTTON
# ============================================================

with button_col:

    st.markdown(
        "<br>",
        unsafe_allow_html=True
    )

    search_clicked = st.button(
        "🔍  Search Incidents",
        type="primary",
        use_container_width=True,
        key="search_incidents"
    )


# ============================================================
# ID SEARCH FEEDBACK
# ============================================================

if st.session_state.get(
    "incident_id_error"
):

    st.error(
        f"⚠️ "
        f"{st.session_state['incident_id_error']}"
    )


elif st.session_state.get(
    "incident_id_found"
):

    found_data = st.session_state.get(
        "incident_results",
        pd.DataFrame()
    )


    if not found_data.empty:

        found_row = found_data.iloc[0]

        st.success(
            f"Incident "
            f"{found_row['Incident ID']} found. "
            f"Time Range updated to "
            f"{found_row['Date']} "
            f"{found_row['Time']}."
        )


# ============================================================
# SEARCH LOGIC
# ============================================================

if search_clicked:

    # --------------------------------------------------------
    # Create datetime range
    # --------------------------------------------------------

    start_datetime = datetime.combine(
        from_date,
        from_time
    )

    end_datetime = datetime.combine(
        to_date,
        to_time
    )


    # --------------------------------------------------------
    # Validate date/time
    # --------------------------------------------------------

    if start_datetime > end_datetime:

        st.error(
            "⚠️ From date/time cannot be later "
            "than To date/time."
        )

    else:

        # IMPORTANT:
        # Start from sidebar-filtered data.
        #
        # This is what connects the sidebar
        # to the main dashboard.

        filtered_data = (
            sidebar_filtered_data.copy()
        )


        # ----------------------------------------------------
        # Incident ID filter
        # ----------------------------------------------------

        if incident_id.strip():

            filtered_data = filtered_data[
                filtered_data["Incident ID"]
                .astype(str)
                .str.contains(
                    incident_id.strip(),
                    case=False,
                    na=False
                )
            ]


        # ----------------------------------------------------
        # Date/time filter
        # ----------------------------------------------------

        filtered_data = filtered_data[
            (
                filtered_data["DateTime"]
                >= start_datetime
            )
            &
            (
                filtered_data["DateTime"]
                <= end_datetime
            )
        ]


        # ----------------------------------------------------
        # Traffic Type filter
        # ----------------------------------------------------

        if traffic_type != "All":

            filtered_data = filtered_data[
                filtered_data["Type"]
                == traffic_type
            ]


        # ----------------------------------------------------
        # Severity filter
        # ----------------------------------------------------

        if severity != "All":

            filtered_data = filtered_data[
                filtered_data["Severity"]
                == severity
            ]


        # ----------------------------------------------------
        # Status filter
        # ----------------------------------------------------

        if status != "All":

            filtered_data = filtered_data[
                filtered_data["Status"]
                == status
            ]


        # ----------------------------------------------------
        # Save results
        # ----------------------------------------------------

        st.session_state[
            "incident_results"
        ] = filtered_data

        st.session_state[
            "incident_search_performed"
        ] = True


# ============================================================
# INCIDENT RESULTS
# ============================================================

# If the user has NOT pressed Search Incidents,
# automatically show the sidebar-filtered incidents.
#
# This is the main connection:
#
# Sidebar SQL Injection
#          ↓
# sidebar_filtered_data
#          ↓
# Main Dashboard list
# ============================================================

if st.session_state.get(
    "incident_search_performed",
    False
):

    results = st.session_state.get(
        "incident_results",
        sidebar_filtered_data
    )

else:

    results = sidebar_filtered_data


# Make sure results is always a DataFrame

if not isinstance(
    results,
    pd.DataFrame
):

    results = pd.DataFrame()


# ============================================================
# RESULTS HEADER
# ============================================================

st.markdown(
    '<div class="search-divider"></div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="section-label">'
    'INCIDENTS FOUND'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# RESULTS DESCRIPTION
# ============================================================

if selected_attack == "All":

    st.caption(
        "Showing incidents from all attack / "
        "traffic types."
    )

else:

    st.caption(
        f"Showing **{selected_attack}** incidents "
        "selected from the sidebar."
    )


# ============================================================
# RESULTS COUNT
# ============================================================

st.info(
    f"Found **{len(results):,}** incident(s)"
)


# ============================================================
# DISPLAY RESULTS
# ============================================================

if len(results) > 0:

    display_data = results[
        [
            "Incident ID",
            "Time",
            "Source IP",
            "Attack Type",
            "Type",
            "Severity",
            "Status"
        ]
    ].copy()


    # --------------------------------------------------------
    # Add row number
    # --------------------------------------------------------

    display_data.insert(
        0,
        "#",
        range(
            1,
            len(display_data) + 1
        )
    )


    # --------------------------------------------------------
    # Display table
    # --------------------------------------------------------

    st.dataframe(
        display_data,
        use_container_width=True,
        hide_index=True,
        column_config={

            "Incident ID":
                st.column_config.TextColumn(
                    "Incident ID",
                    width="medium"
                ),

            "Time":
                st.column_config.TextColumn(
                    "Time",
                    width="small"
                ),

            "Source IP":
                st.column_config.TextColumn(
                    "Source IP",
                    width="medium"
                ),

            "Attack Type":
                st.column_config.TextColumn(
                    "Attack Type",
                    width="medium"
                ),

            "Type":
                st.column_config.TextColumn(
                    "Type",
                    width="small"
                ),

            "Severity":
                st.column_config.TextColumn(
                    "Severity",
                    width="small"
                ),

            "Status":
                st.column_config.TextColumn(
                    "Status",
                    width="medium"
                )
        }
    )


    # ========================================================
    # SELECT INCIDENT
    # ========================================================

    st.markdown("### Select Incident")


    selected_incident = st.selectbox(
        "Select an incident to investigate",
        results["Incident ID"].tolist(),
        key="selected_incident"
    )


    # ========================================================
    # VIEW INCIDENT
    # ========================================================

    if st.button(
        "👁️  View Incident",
        type="primary",
        key="view_incident"
    ):

        selected_row = results[
            results["Incident ID"]
            == selected_incident
        ].iloc[0]


        # Save selected incident

        st.session_state[
            "selected_incident_data"
        ] = selected_row.to_dict()


        st.session_state[
            "incident_selected"
        ] = True

        st.success(
            f"Selected incident: "
            f"{selected_incident}"
        )

    # ========================================================
    # SQL INJECTION XAI → REQUEST & PAYLOAD
    # Keep the selected incident visible across reruns.
    # ========================================================

    if st.session_state.get("incident_selected", False):

        selected_detail = st.session_state.get(
            "selected_incident_data",
            {}
        )

        if selected_detail:

            st.markdown(
                '<div class="search-divider"></div>',
                unsafe_allow_html=True
            )

            st.markdown(
                "## SQL Injection Incident Analysis (XAI)"
            )

            st.caption(
                "Request and payload evidence for the selected incident."
            )

            render_request_payload_section(
                pd.Series(selected_detail)
            )


else:

    # ========================================================
    # NO RESULTS
    # ========================================================

    if selected_attack == "All":

        st.warning(
            "No incidents are available."
        )

    else:

        st.warning(
            f"No incidents were found for "
            f"**{selected_attack}**."
        )