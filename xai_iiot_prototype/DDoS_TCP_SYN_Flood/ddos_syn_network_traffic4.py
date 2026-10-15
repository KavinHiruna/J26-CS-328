import html
import re
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="DDoS TCP SYN Flood — Network Traffic Details",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

UNAVAILABLE = "Not available in dataset"
DEFAULT_FILE = Path(__file__).resolve().with_name("DDoS_TCP_SYN_Flood.xlsx")


def normalise_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def find_column(columns, candidates):
    lookup = {normalise_name(col): col for col in columns}
    for candidate in candidates:
        actual = lookup.get(normalise_name(candidate))
        if actual is not None:
            return actual
    return None


def value_from(row, candidates, default=UNAVAILABLE):
    col = find_column(row.index, candidates)
    if col is None:
        return default
    value = row[col]
    if pd.isna(value):
        return default
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return default
    # In this dataset, zero often represents a protocol field that was not captured.
    return text


def format_timestamp(value):
    if value == UNAVAILABLE:
        return value
    try:
        return pd.to_datetime(value, errors="raise").strftime("%Y-%m-%d %H:%M:%S.%f")
    except (TypeError, ValueError, OverflowError):
        return value


def format_tcp_flags(value, ack_value=None, syn_value=None, fin_value=None, rst_value=None):
    if value != UNAVAILABLE:
        raw = str(value).strip().lower()
        try:
            number = int(raw, 16) if raw.startswith("0x") else int(raw)
            names = []
            if number & 0x02:
                names.append("SYN")
            if number & 0x10:
                names.append("ACK")
            if number & 0x04:
                names.append("RST")
            if number & 0x01:
                names.append("FIN")
            if number & 0x08:
                names.append("PSH")
            if number & 0x20:
                names.append("URG")
            if names:
                return f"{', '.join(names)} ({value})"
        except (TypeError, ValueError):
            pass
        return value

    names = []
    for label, val in [
        ("SYN", syn_value), ("ACK", ack_value), ("RST", rst_value), ("FIN", fin_value)
    ]:
        if val not in (None, UNAVAILABLE, "", "0", "0.0", "False", "false"):
            names.append(label)
    return ", ".join(names) if names else UNAVAILABLE


st.markdown(
    """
    <style>
    .stApp { background: #0b1119; color: #e7eef7; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .block-container { max-width: 1450px; padding: 1.25rem 1.25rem 2rem; }
    .traffic-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 18px 20px; box-sizing: border-box;
    }
    .panel-title {
        color: #e7eef7; font-size: 17px; font-weight: 750;
        padding-bottom: 13px; margin-bottom: 8px; border-bottom: 1px solid #2b3e52;
    }
    .panel-icon { color: #53bdf7; margin-right: 9px; }
    .detail-row {
        display: grid; grid-template-columns: minmax(145px, 0.8fr) minmax(0, 1.5fr);
        gap: 14px; padding: 9px 0; border-bottom: 1px solid #1d2b3b;
    }
    .detail-row:last-child { border-bottom: 0; }
    .detail-label { color: #93a8bd; font-size: 13px; }
    .detail-value { color: #e7eef7; font-size: 13px; line-height: 1.45; overflow-wrap: anywhere; }
    .value-chip {
        display: inline-block; background: #132b3e; color: #72d0ff;
        border: 1px solid #245574; border-radius: 5px; padding: 2px 8px;
        font-weight: 700; font-size: 12px;
    }
    .notice {
        color: #b7c7d8; background: #111d2a; border: 1px solid #293b4e;
        border-radius: 8px; padding: 10px 12px; margin: 10px 0 14px; font-size: 12px;
    }
    .metric-card {
        background: #101b28; border: 1px solid #26384c; border-radius: 10px;
        padding: 12px 14px; min-height: 88px;
    }
    .metric-label { color: #93a8bd; font-size: 12px; margin-bottom: 7px; }
    .metric-value { color: #e7eef7; font-size: 19px; font-weight: 750; overflow-wrap: anywhere; }
    .metric-sub { color: #8fa6bc; font-size: 11px; margin-top: 4px; }
    .traffic-layout {
        display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        gap: 14px; align-items: start;
    }
    .indicator-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 14px 16px; box-sizing: border-box; min-width: 0;
    }
    .indicator-code {
        background: #08121e; border: 1px solid #31506a; border-radius: 7px;
        padding: 9px 10px; font-family: Consolas, "Courier New", monospace;
        font-size: 12px; line-height: 1.55; color: #b9cce0; overflow-wrap: anywhere;
    }
    .indicator-line { white-space: pre-wrap; }
    .indicator-num { color: #8ca6c1; display: inline-block; width: 18px; }
    .token-red { color: #ff465b; background: #451b27; padding: 1px 4px; border-radius: 3px; font-weight: 700; }
    .token-orange { color: #ff9d52; font-weight: 700; }
    .token-yellow { color: #ffd15c; font-weight: 700; }
    .token-blue { color: #47c2ff; background: #123149; padding: 1px 4px; border-radius: 3px; font-weight: 700; }
    .indicator-legend { display: flex; flex-wrap: wrap; gap: 7px 12px; margin-top: 10px; }
    .legend-item { color: #b6c8da; font-size: 10px; display: flex; align-items: center; gap: 5px; }
    .legend-swatch { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
    @media (max-width: 850px) {
        .traffic-layout { grid-template-columns: 1fr; }
        .detail-row { grid-template-columns: 1fr; gap: 3px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("DDoS TCP SYN Flood — Network Traffic Details")
st.caption("Network Traffic Details preview. Demo values are illustrative until a dataset is loaded.")

# Load the provided workbook by default; allow the project CSV or another workbook to be supplied.
dataset = None
dataset_name = None
if DEFAULT_FILE.is_file():
    try:
        dataset = pd.read_excel(DEFAULT_FILE)
        dataset_name = DEFAULT_FILE.name
    except Exception:
        dataset = None

with st.expander("Use another dataset", expanded=False):
    uploaded = st.file_uploader("Upload a CSV or Excel file", type=["csv", "xlsx", "xls"])
    if uploaded is not None:
        try:
            if uploaded.name.lower().endswith(".csv"):
                dataset = pd.read_csv(uploaded, low_memory=False)
            else:
                dataset = pd.read_excel(uploaded)
            dataset_name = uploaded.name
        except Exception as exc:
            st.error(f"Could not read the uploaded file: {exc}")
            st.stop()

if dataset is None:
    # Show the requested UI even when no dataset file is found.
    # DEMO_MODE below displays clearly labelled illustrative values.
    dataset = pd.DataFrame([{}])
    dataset_name = "Demo preview (no dataset loaded)"

if dataset.empty:
    st.error("The selected dataset contains no rows.")
    st.stop()

st.markdown(
    f'<div class="notice"><b>Dataset:</b> {html.escape(str(dataset_name))}'
    f' &nbsp; | &nbsp; <b>Rows:</b> {len(dataset):,}'
    f' &nbsp; | &nbsp; <b>Columns:</b> {len(dataset.columns):,}</div>',
    unsafe_allow_html=True,
)

# If an attack label is present, offer to focus on rows labelled as a SYN flood.
label_col = find_column(dataset.columns, ["Attack_type", "Attack Type", "Attack_label", "label", "class"])
view = dataset.copy()
if label_col:
    labels = view[label_col].astype(str)
    possible = view[labels.str.contains(r"ddos.*syn|syn.*flood", case=False, na=False)]
    if not possible.empty:
        use_matches = st.checkbox(
            f"Filter to rows whose label mentions DDoS/SYN flood ({len(possible):,} rows)",
            value=True,
        )
        if use_matches:
            view = possible

if view.empty:
    st.warning("No rows remain after filtering.")
    st.stop()

# Select a row so the UI can inspect an actual record from the dataset.
row_number = st.selectbox(
    "Select record",
    options=list(range(len(view))),
    format_func=lambda idx: f"Record {idx + 1} of {len(view)}",
)
row = view.iloc[row_number]

protocol = "TCP" if find_column(row.index, ["tcp.flags", "tcp.srcport", "tcp.dstport"]) else UNAVAILABLE
src_ip = value_from(row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
dst_ip = value_from(row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"])
src_port = value_from(row, ["tcp.srcport", "Source Port", "source_port"])
dst_port = value_from(row, ["tcp.dstport", "Destination Port", "destination_port"])
raw_flags = value_from(row, ["tcp.flags", "TCP Flags", "flags"])
syn_flag = value_from(row, ["tcp.connection.syn"])
synack_flag = value_from(row, ["tcp.connection.synack"])
ack_flag = value_from(row, ["tcp.flags.ack"])
rst_flag = value_from(row, ["tcp.connection.rst"])
fin_flag = value_from(row, ["tcp.connection.fin"])
flags = format_tcp_flags(raw_flags, ack_flag, syn_flag, fin_flag, rst_flag)
timestamp = format_timestamp(value_from(row, ["frame.time", "Timestamp", "DateTime", "timestamp", "time"]))

# Demo values matching the requested Network Traffic Details mockup.
# These are illustrative UI values, not calculated statistics from the selected dataset.
# Replace DEMO_MODE with False to show values extracted from the selected dataset record.
DEMO_MODE = True

if DEMO_MODE:
    protocol = "TCP"
    src_ip = "192.168.0.170"
    dst_ip = "192.168.0.10"
    src_port = "49152"
    dst_port = "80"
    flags = "SYN"
    syn_packets = "18,420"
    synack_packets = "214"
    ack_packets = "31"
    connection_attempts = "18,420"
    packet_rate = "2,305 packets/sec"
    flow_duration = "8.0 sec"
    timestamp = format_timestamp(value_from(row, ["frame.time", "Timestamp", "DateTime", "timestamp", "time"]))
else:
    protocol = "TCP" if find_column(row.index, ["tcp.flags", "tcp.srcport", "tcp.dstport"]) else UNAVAILABLE
    src_ip = value_from(row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
    dst_ip = value_from(row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"])
    src_port = value_from(row, ["tcp.srcport", "Source Port", "source_port"])
    dst_port = value_from(row, ["tcp.dstport", "Destination Port", "destination_port"])
    raw_flags = value_from(row, ["tcp.flags", "TCP Flags", "flags"])
    syn_flag = value_from(row, ["tcp.connection.syn"])
    synack_flag = value_from(row, ["tcp.connection.synack"])
    ack_flag = value_from(row, ["tcp.flags.ack"])
    rst_flag = value_from(row, ["tcp.connection.rst"])
    fin_flag = value_from(row, ["tcp.connection.fin"])
    flags = format_tcp_flags(raw_flags, ack_flag, syn_flag, fin_flag, rst_flag)
    timestamp = format_timestamp(value_from(row, ["frame.time", "Timestamp", "DateTime", "timestamp", "time"]))
    syn_packets = syn_flag
    synack_packets = synack_flag
    ack_packets = ack_flag
    connection_attempts = syn_flag if syn_flag != UNAVAILABLE else UNAVAILABLE
    packet_rate = value_from(row, ["packet_rate", "packets_per_second", "packets/sec", "packet rate"])
    flow_duration = value_from(row, ["flow_duration", "flow.duration", "duration", "flow_duration_sec"])

# Summary tiles
tiles = [
    ("Protocol", protocol, "Network protocol"),
    ("TCP Flags", flags, "Flags observed in this view"),
    ("Source IP", src_ip, "Traffic origin"),
    ("Destination IP", dst_ip, "Target host"),
]
cols = st.columns(4)
for col, (label, value, sub) in zip(cols, tiles):
    with col:
        st.markdown(
            '<div class="metric-card">'
            f'<div class="metric-label">{html.escape(label)}</div>'
            f'<div class="metric-value">{html.escape(value)}</div>'
            f'<div class="metric-sub">{html.escape(sub)}</div>'
            '</div>',
            unsafe_allow_html=True,
        )

st.markdown("")
detail_rows = [
    ("Method / Protocol", protocol, True),
    ("Source IP", src_ip, False),
    ("Destination IP", dst_ip, False),
    ("Source Port", src_port, False),
    ("Destination Port", dst_port, False),
    ("TCP Flags", flags, False),
    ("SYN Packets", syn_packets, False),
    ("SYN-ACK Packets", synack_packets, False),
    ("ACK Packets", ack_packets, False),
    ("Connection Attempts", connection_attempts, False),
    ("Packet Rate", packet_rate, False),
    ("Flow Duration", flow_duration, False),
    ("Timestamp", timestamp, False),
]

rows_html = []
for label, value, is_protocol in detail_rows:
    shown = (
        f'<span class="value-chip">{html.escape(str(value))}</span>'
        if is_protocol else html.escape(str(value))
    )
    rows_html.append(
        '<div class="detail-row">'
        f'<div class="detail-label">{html.escape(label)}</div>'
        f'<div class="detail-value">{shown}</div>'
        '</div>'
    )

# Traffic indicators are based on the same values shown in the details panel.
# In demo mode these match the supplied mockup; in dataset mode they reflect available fields.
indicator_items = [
    ("tcp.flags", flags, "syn"),
    ("tcp.connection.syn", syn_packets, "red"),
    ("tcp.connection.synack", synack_packets, "orange"),
    ("tcp.dstport", dst_port, "blue"),
    ("packet_rate", packet_rate, "red"),
    ("flow_duration", flow_duration, "blue"),
]

def indicator_value(value):
    if value in (None, "", UNAVAILABLE):
        return "not available"
    return str(value)

indicator_lines = []
for idx, (field, value, style) in enumerate(indicator_items, start=1):
    safe_field = html.escape(field)
    safe_value = html.escape(indicator_value(value))
    if style == "syn":
        rendered_value = f'<span class="token-red">{safe_value}</span>'
    elif style == "red":
        rendered_value = f'<span class="token-red">{safe_value}</span>'
    elif style == "orange":
        rendered_value = f'<span class="token-orange">{safe_value}</span>'
    elif style == "yellow":
        rendered_value = f'<span class="token-yellow">{safe_value}</span>'
    else:
        rendered_value = f'<span class="token-blue">{safe_value}</span>'
    indicator_lines.append(
        f'<div class="indicator-line"><span class="indicator-num">{idx}</span>'
        f'{safe_field} = {rendered_value}</div>'
    )

indicator_panel = (
    '<section class="indicator-panel">'
    '<div class="panel-title"><span class="panel-icon">&lt;/&gt;</span>Traffic Indicators Highlighted</div>'
    '<div class="indicator-code">' + "".join(indicator_lines) + '</div>'
    '<div class="indicator-legend">'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff465b"></span>SYN flag indicator</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff9d52"></span>High rate indicator</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ffd15c"></span>Incomplete handshake</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#47c2ff"></span>Repeated target / port</div>'
    '</div></section>'
)

st.markdown(
    '<div class="traffic-layout">'
    '<section class="traffic-panel">'
    '<div class="panel-title"><span class="panel-icon">▣</span>Network Traffic Details</div>'
    + "".join(rows_html)
    + '</section>'
    + indicator_panel
    + '</div>',
    unsafe_allow_html=True,
)

if DEMO_MODE:
    st.markdown(
        '<div class="notice"><b>Preview mode:</b> the network values shown above are illustrative '
        'mockup values matching the requested design, not verified measurements from the dataset. '
        'Set <code>DEMO_MODE = False</code> in the script to display values from the selected record.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="notice"><b>Data note:</b> values are taken from the selected dataset record. '
        'Packet totals, packet rate, and flow duration are only reliable when supported by the source fields '
        'or calculated from packet-level records over a defined time window.</div>',
        unsafe_allow_html=True,
    )

