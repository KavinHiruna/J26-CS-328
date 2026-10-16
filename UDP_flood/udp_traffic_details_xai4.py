import html
import re
from pathlib import Path

import pandas as pd
import streamlit as st

# UDP FLOOD XAI — UDP TRAFFIC DETAILS + TRAFFIC INDICATORS (side by side)
# Reads real values from the dataset; missing fields are not invented.

st.set_page_config(
    page_title="UDP Flood XAI — Traffic Details",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

UNAVAILABLE = "Not available in dataset"


def normalise_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def find_column(columns, candidates):
    lookup = {normalise_name(col): col for col in columns}
    for candidate in candidates:
        actual = lookup.get(normalise_name(candidate))
        if actual is not None:
            return actual
    return None


def get_value(row, candidates, default=UNAVAILABLE):
    column = find_column(row.index, candidates)
    if column is None:
        return default
    value = row[column]
    if pd.isna(value):
        return default
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return default
    return text


def format_number(value, suffix=""):
    if value == UNAVAILABLE:
        return value
    try:
        number = float(str(value).replace(",", "").strip())
        formatted = f"{number:,.3f}".rstrip("0").rstrip(".")
        return f"{formatted}{suffix}"
    except (TypeError, ValueError):
        return f"{value}{suffix}"


def select_udp_record(data):
    """Prefer a row labelled UDP Flood/DDoS UDP; otherwise use the first row."""
    attack_col = find_column(
        data.columns, ["Attack_type", "Attack Type", "attack_type", "label", "class"]
    )
    if attack_col:
        labels = data[attack_col].astype(str)
        mask = labels.str.contains(
            r"udp.*(flood|ddos)|ddos.*udp|udp_flood", case=False, na=False
        )
        matches = data.loc[mask]
        if not matches.empty:
            return matches.iloc[0], len(matches), True
    return data.iloc[0], 0, False


def build_details(row):
    protocol = get_value(row, ["ip.proto", "ip.proto_name", "Protocol", "protocol"])
    if protocol == UNAVAILABLE and find_column(
        row.index, ["udp.port", "udp.srcport", "udp.dstport", "udp.length"]
    ):
        protocol = "UDP"

    source_ip = get_value(row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
    destination_ip = get_value(
        row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"]
    )
    source_port = get_value(
        row, ["udp.srcport", "udp.src_port", "Source Port", "source_port"]
    )
    destination_port = get_value(
        row,
        ["udp.dstport", "udp.dst_port", "udp.destination_port", "Destination Port", "destination_port"],
    )
    generic_udp_port = get_value(row, ["udp.port", "udp_port"])
    if destination_port == UNAVAILABLE and generic_udp_port != UNAVAILABLE:
        destination_port = f"{generic_udp_port} (generic UDP port field)"

    udp_length = get_value(row, ["udp.length", "udp.len", "UDP Length", "udp_length"])
    if udp_length != UNAVAILABLE:
        udp_length = format_number(udp_length, " bytes")

    packet_rate = get_value(
        row,
        ["packets_per_second", "packet_rate", "packets/sec", "Packet Rate", "flow_packets_per_second"],
    )
    if packet_rate != UNAVAILABLE:
        packet_rate = format_number(packet_rate, " packets/sec")

    traffic_rate = get_value(
        row,
        ["bytes_per_second", "byte_rate", "traffic_rate", "bytes/sec", "Traffic Rate", "flow_bytes_per_second"],
    )
    if traffic_rate != UNAVAILABLE:
        traffic_rate = format_number(traffic_rate, " bytes/sec")

    inter_arrival = get_value(
        row,
        ["udp.time_delta", "udp_time_delta", "Average Inter-arrival Time", "avg_inter_arrival_time"],
    )
    if inter_arrival != UNAVAILABLE:
        # udp.time_delta may be an individual delta, not an average.
        inter_arrival = format_number(inter_arrival, " sec")

    timestamp = get_value(row, ["frame.time", "DateTime", "Timestamp", "timestamp", "time"])
    if timestamp != UNAVAILABLE:
        try:
            timestamp = pd.to_datetime(timestamp, errors="raise").strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OverflowError):
            pass

    return [
        ("Protocol", protocol, protocol == "UDP"),
        ("Source IP", source_ip, False),
        ("Destination IP", destination_ip, False),
        ("Source Port", source_port, False),
        ("Destination Port", destination_port, destination_port != UNAVAILABLE and "generic" not in destination_port.lower()),
        ("UDP Length", udp_length, False),
        ("Packet Rate", packet_rate, packet_rate != UNAVAILABLE),
        ("Traffic Rate", traffic_rate, traffic_rate != UNAVAILABLE),
        ("Average Inter-arrival Time", inter_arrival, inter_arrival != UNAVAILABLE),
        ("Timestamp", timestamp, False),
    ]


# Dark navy theme matching the supplied XAI UI reference.
st.markdown(
    """
    <style>
    .stApp { background: #0b1119; color: #e7eef7; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .block-container { max-width: 1400px; padding: 1.2rem 1rem 2rem; }

    /* ---------- shared panel look ---------- */
    .udp-panel, .indicator-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 10px;
        overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,.12); height: 100%;
    }
    .udp-panel-title, .indicator-title {
        display: flex; align-items: center; gap: 10px; color: #e7eef7;
        font-size: 17px; font-weight: 700; padding: 13px 16px;
        border-bottom: 1px solid #2b3e52;
    }
    .udp-icon { color: #53bdf7; font-size: 19px; }

    /* ---------- UDP Traffic Details rows ---------- */
    .udp-row { display: grid; grid-template-columns: minmax(170px, 35%) minmax(0, 1fr);
               gap: 12px; padding: 7px 14px; border-bottom: 1px solid #1d2b3b; align-items: center; }
    .udp-row:last-child { border-bottom: 0; }
    .udp-label { color: #b8c8d9; font-size: 13px; }
    .udp-value { color: #e7eef7; font-size: 13px; overflow-wrap: anywhere; line-height: 1.4; }
    .udp-alert { color: #ff4d57; font-weight: 700; }
    .udp-muted { color: #8799ac; font-style: italic; }
    .udp-note { color: #aebed0; background: #111d2a; border: 1px solid #293b4e;
                border-radius: 8px; padding: 10px 12px; margin: 0 0 12px; font-size: 12px; }

    /* ---------- Traffic Indicators ---------- */
    .indicator-body { padding: 14px; }
    .traffic-flow { background: #0c1621; border: 1px solid #26384c; border-radius: 10px;
                    padding: 22px 18px 16px; }
    .flow-grid { display: grid; grid-template-columns: auto minmax(0, 1fr) auto auto;
                 align-items: center; column-gap: 14px; }
    .endpoint-block { text-align: center; }
    .endpoint-label { color: #b8c8d9; font-size: 12px; margin-bottom: 8px; }
    .endpoint { color: #e7eef7; font-size: 13px; padding: 9px 14px; border-radius: 8px;
                background: #11263a; border: 1px solid #2f6ea3; white-space: nowrap; }
    .endpoint.target { background: #2a1520; border-color: #ff5364; }
    .packet-bars { display: flex; align-items: center; justify-content: space-between;
                   gap: 3px; height: 44px; margin-top: 18px; }
    .packet-bar { flex: 1 1 0; min-width: 2px; height: 100%; border-radius: 1px;
                  background: #ff5364; }
    .packet-bar:nth-child(3n)   { background: #ff8a95; height: 82%; }
    .packet-bar:nth-child(4n+1) { background: #d93a58; height: 92%; }
    .packet-bar:nth-child(5n)   { background: #ffb3ba; height: 70%; }
    .flow-arrows { color: #e7eef7; font-size: 18px; margin-top: 18px; white-space: nowrap; }
    .dest-block { margin-top: 0; }
    .flow-caption-wrap { display: grid; grid-template-columns: auto minmax(0, 1fr) auto auto;
                         column-gap: 14px; margin-top: 8px; }
    .flow-caption { grid-column: 2; text-align: center; color: #aebed0; font-size: 12px;
                    border: 1px solid #5b6f84; border-top: 0; border-radius: 0 0 4px 4px;
                    padding: 4px 6px 0; line-height: 1.2; position: relative; }
    .indicator-legend { display: grid; grid-template-columns: repeat(4, auto);
                        justify-content: space-between; gap: 10px; margin-top: 14px;
                        background: #0c1621; border: 1px solid #26384c; border-radius: 10px;
                        padding: 12px 16px; }
    .legend-item { display: flex; align-items: center; gap: 8px; color: #cfdbe8; font-size: 12.5px; }
    .legend-swatch { width: 14px; height: 14px; border-radius: 3px; display: inline-block; }

    /* ---------- Evidence & Justification panel ---------- */
    .evidence-panel {
        margin-top: 14px;
        background: #101b28;
        border: 1px solid #26384c;
        border-radius: 10px;
        overflow: hidden;
    }
    .evidence-title {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 13px 16px;
        color: #e7eef7;
        font-size: 17px;
        font-weight: 700;
        border-bottom: 1px solid #2b3e52;
    }
    .evidence-card {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 13px 14px;
        border-bottom: 1px solid #1d2b3b;
    }
    .evidence-card:last-child { border-bottom: none; }
    .evidence-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        flex: 0 0 36px;
        border-radius: 8px;
        background: #172b3e;
        color: #35baf5;
        font-size: 20px;
    }
    .evidence-copy { flex: 1; min-width: 0; }
    .evidence-heading {
        color: #e7eef7;
        font-size: 13px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .evidence-description {
        color: #aebed0;
        font-size: 12px;
        line-height: 1.5;
    }
    .evidence-status {
        flex: 0 0 auto;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 10px;
        font-weight: 700;
        color: #e7eef7;
        background: #26384c;
    }
    .evidence-status.warning { color: #ffca77; background: #392c19; }
    .evidence-status.critical { color: #ff7b85; background: #3b1c25; }
    .evidence-status.positive { color: #70e0b0; background: #16372e; }

    @media (max-width: 900px) {
        .indicator-legend { grid-template-columns: repeat(2, auto); }
    }
    @media (max-width: 600px) { .udp-row { grid-template-columns: 1fr; gap: 3px; } }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("## UDP Flood XAI")
st.caption("Incident evidence · UDP Traffic Details · Traffic Indicators")

# Find the CSV beside this script or in a project data folder.
script_dir = Path(__file__).resolve().parent
candidate_paths = [
    script_dir / "data" / "EdgeIIoT_train_80.csv",
    script_dir / "EdgeIIoT_train_80.csv",
    Path.cwd() / "data" / "EdgeIIoT_train_80.csv",
    Path.cwd() / "EdgeIIoT_train_80.csv",
]
dataset_path = next((path for path in candidate_paths if path.is_file()), None)

if dataset_path is not None:
    try:
        data = pd.read_csv(dataset_path, low_memory=False)
        st.caption(f"Dataset: `{dataset_path}`")
    except Exception as exc:
        st.error(f"Could not read the dataset: {exc}")
        st.stop()
else:
    st.info("Choose your EdgeIIoT CSV file. Missing fields will be shown as unavailable.")
    uploaded = st.file_uploader("Upload dataset CSV", type=["csv"])
    if uploaded is None:
        st.stop()
    try:
        data = pd.read_csv(uploaded, low_memory=False)
        st.caption(f"Dataset loaded: `{uploaded.name}`")
    except Exception as exc:
        st.error(f"Could not read the uploaded CSV: {exc}")
        st.stop()

if data.empty:
    st.error("The selected dataset contains no records.")
    st.stop()

selected_row, udp_count, found_udp = select_udp_record(data)
if found_udp:
    st.markdown(
        f'<div class="udp-note">Showing one of {udp_count:,} rows labelled as UDP Flood/DDoS UDP.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="udp-note">No UDP Flood label was detected automatically. '
        'Showing the first dataset row; verify the selected record before interpreting it as an attack.</div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Left panel: UDP Traffic Details
# ---------------------------------------------------------------------------
rows_html = []
for label, value, alert in build_details(selected_row):
    safe_label = html.escape(label)
    safe_value = html.escape(str(value))
    value_class = "udp-value"
    if value == UNAVAILABLE:
        value_class += " udp-muted"
    elif alert:
        value_class += " udp-alert"
    rows_html.append(
        f'<div class="udp-row"><div class="udp-label">{safe_label}</div>'
        f'<div class="{value_class}">{safe_value}</div></div>'
    )

panel_html = (
    '<section class="udp-panel">'
    '<div class="udp-panel-title"><span class="udp-icon">▤</span>UDP Traffic Details</div>'
    + "".join(rows_html)
    + "</section>"
)

# ---------------------------------------------------------------------------
# Evidence & Justification
# Uses available dataset values; does not invent missing evidence.
# ---------------------------------------------------------------------------
def evidence_item(icon, heading, description, status, status_class=""):
    return (
        '<div class="evidence-card">'
        f'<div class="evidence-icon">{icon}</div>'
        '<div class="evidence-copy">'
        f'<div class="evidence-heading">{html.escape(heading)}</div>'
        f'<div class="evidence-description">{html.escape(description)}</div>'
        '</div>'
        f'<span class="evidence-status {status_class}">'
        f'{html.escape(status)}</span>'
        '</div>'
    )


def numeric_feature(row, candidates):
    value = get_value(row, candidates)

    if value == UNAVAILABLE:
        return None

    try:
        number = float(str(value).replace(",", "").strip())
        if not pd.notna(number):
            return None
        return number
    except (ValueError, TypeError):
        return None


# Read the actual available measurements.
packet_rate_value = numeric_feature(
    selected_row,
    [
        "packets_per_second", "packet_rate",
        "packets/sec", "Packet Rate",
        "flow_packets_per_second"
    ]
)

traffic_rate_value = numeric_feature(
    selected_row,
    [
        "bytes_per_second", "byte_rate",
        "traffic_rate", "bytes/sec",
        "Traffic Rate", "flow_bytes_per_second"
    ]
)

inter_arrival_value = numeric_feature(
    selected_row,
    [
        "udp.time_delta", "udp_time_delta",
        "Average Inter-arrival Time",
        "avg_inter_arrival_time"
    ]
)

destination_port_value = numeric_feature(
    selected_row,
    [
        "udp.dstport", "udp.dst_port",
        "udp.destination_port",
        "Destination Port", "destination_port",
        "udp.port", "udp_port"
    ]
)

# A single row cannot prove repeated traffic to a destination.
if packet_rate_value is None:
    rate_evidence = evidence_item(
        "↑",
        "Packet rate unavailable",
        "The dataset row does not contain a recognized packet-rate feature. "
        "Calculate packets per second from timestamped traffic before "
        "assessing flood intensity.",
        "UNKNOWN",
        "warning"
    )
elif packet_rate_value > 1000:
    rate_evidence = evidence_item(
        "↑",
        "High packet rate",
        f"Measured packet rate: {packet_rate_value:,.2f} packets/sec. "
        "This may indicate flooding; compare against normal traffic "
        "and a validated detection threshold.",
        "REVIEW",
        "critical"
    )
else:
    rate_evidence = evidence_item(
        "↑",
        "Packet rate measurement",
        f"Measured packet rate: {packet_rate_value:,.2f} packets/sec. "
        "Use a validated baseline to determine whether this is abnormal.",
        "MEASURED"
    )

# Inter-arrival time is not necessarily an average unless derived as one.
if inter_arrival_value is None:
    timing_evidence = evidence_item(
        "◷",
        "Inter-arrival timing unavailable",
        "No recognized UDP timing field was found. Packet timestamps "
        "are needed to measure inter-arrival intervals.",
        "UNKNOWN",
        "warning"
    )
elif inter_arrival_value <= 0:
    timing_evidence = evidence_item(
        "◷",
        "Timing needs verification",
        f"The available time-delta value is {inter_arrival_value:g}. "
        "A zero or non-positive value alone does not establish a UDP flood.",
        "VERIFY",
        "warning"
    )
elif inter_arrival_value < 0.001:
    timing_evidence = evidence_item(
        "◷",
        "Very short time interval",
        f"Available time-delta value: {inter_arrival_value:g} seconds. "
        "Verify its units and compare packet timing with normal traffic.",
        "REVIEW",
        "warning"
    )
else:
    timing_evidence = evidence_item(
        "◷",
        "Inter-arrival timing",
        f"Available time-delta value: {inter_arrival_value:g} seconds. "
        "Interpret it alongside packet rate and the traffic baseline.",
        "MEASURED"
    )

# Port 502 is commonly used by Modbus TCP, but the port alone is not
# evidence of a UDP flood or proof that Modbus is being used.
if destination_port_value is None:
    port_evidence = evidence_item(
        "◎",
        "Destination port unavailable",
        "A destination UDP port could not be extracted from this row. "
        "The generic udp.port field may not distinguish source and destination.",
        "UNKNOWN",
        "warning"
    )
elif destination_port_value == 502:
    port_evidence = evidence_item(
        "◎",
        "Destination port 502",
        "The selected record references port 502. Confirm the protocol, "
        "direction and repeated packet counts; the port alone does not "
        "prove a flood or a Modbus attack.",
        "VERIFY",
        "warning"
    )
else:
    port_evidence = evidence_item(
        "◎",
        "Destination port observed",
        f"Available port value: {destination_port_value:g}. "
        "Investigate whether traffic to this port is unusually frequent.",
        "MEASURED"
    )

if traffic_rate_value is None:
    volume_evidence = evidence_item(
        "▥",
        "Traffic volume unavailable",
        "No recognized bytes-per-second feature was found. Derive traffic "
        "volume from packet sizes and timestamps or flow statistics.",
        "UNKNOWN",
        "warning"
    )
else:
    volume_evidence = evidence_item(
        "▥",
        "Traffic volume measurement",
        f"Available rate: {traffic_rate_value:,.2f} bytes/sec. "
        "Compare with the normal baseline to assess whether volume is elevated.",
        "MEASURED"
    )

evidence_html = (
    '<section class="evidence-panel">'
    '<div class="evidence-title">'
    '<span style="color:#35baf5">↗</span>'
    'Evidence &amp; Justification'
    '</div>'
    + rate_evidence
    + timing_evidence
    + port_evidence
    + volume_evidence
    + '</section>'
)

# ---------------------------------------------------------------------------
# Right panel: Traffic Indicators
# NOTE: HTML is built without indentation/blank lines, otherwise Streamlit's
# markdown parser treats it as a code block.
# ---------------------------------------------------------------------------
source_ip = html.escape(str(get_value(
    selected_row, ["ip.src_host", "ip.src", "Source IP", "source_ip"]
)))
destination_ip = html.escape(str(get_value(
    selected_row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"]
)))

bars_html = "".join('<span class="packet-bar"></span>' for _ in range(46))

legend_items = [
    ("#ff5364", "High packet rate"),
    ("#f6a23a", "Short inter-arrival time"),
    ("#25a7f0", "High traffic volume"),
    ("#a85cf5", "Repeated destination"),
]
legend_html = "".join(
    f'<div class="legend-item"><span class="legend-swatch" style="background:{color}"></span>{text}</div>'
    for color, text in legend_items
)

traffic_indicators_html = (
    '<section class="indicator-panel">'
    '<div class="indicator-title"><span style="color:#25b9f5">♧</span>Traffic Indicators</div>'
    '<div class="indicator-body">'
    '<div class="traffic-flow">'
    '<div class="flow-grid">'
    f'<div class="endpoint-block"><div class="endpoint-label">Source IP</div><div class="endpoint">{source_ip}</div></div>'
    f'<div class="packet-bars">{bars_html}</div>'
    '<div class="flow-arrows">→ →</div>'
    f'<div class="endpoint-block dest-block"><div class="endpoint-label">Destination IP</div><div class="endpoint target">{destination_ip}</div></div>'
    '</div>'
    '<div class="flow-caption-wrap"><div class="flow-caption">UDP Packets (High Frequency)</div></div>'
    '</div>'
    f'<div class="indicator-legend">{legend_html}</div>'
    '</div>'
    '</section>'
)

# ---------------------------------------------------------------------------
# Display UDP details + evidence in the left column,
# Traffic Indicators in the right column
# ---------------------------------------------------------------------------
left, right = st.columns([1.08, 1], gap="small")

with left:
    st.markdown(panel_html, unsafe_allow_html=True)
    st.markdown(evidence_html, unsafe_allow_html=True)

with right:
    st.markdown(traffic_indicators_html, unsafe_allow_html=True)
