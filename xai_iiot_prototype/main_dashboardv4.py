import streamlit as st
import pandas as pd
from datetime import date, time, datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import textwrap


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
# MERGED XAI / IDS DASHBOARD
# Sidebar: Detection Module
# Main: Incident Search & Investigation
# ============================================================

# ============================================================
# IDS DASHBOARD HEADER
# ============================================================

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
# DETECTION MODULE SIDEBAR
# ============================================================

with st.sidebar:

    # Back button
    if st.button("‹‹", key="back_btn", use_container_width=False):
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

    # Initialize record
    if "traffic_record" not in st.session_state:
        st.session_state["traffic_record"] = 0

    # Total records
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
        st.markdown(
            f"<div style='text-align:center; padding-top:8px;'>"
            f"<b>Record {st.session_state['traffic_record'] + 1:03d}</b>"
            f"</div>",
            unsafe_allow_html=True
        )

    with col3:
        if st.button(
            "+",
            key="next_record",
            use_container_width=True
        ):
            if st.session_state["traffic_record"] < total_records - 1:
                st.session_state["traffic_record"] += 1

    # Record counter
    st.markdown(
        f"<div style='text-align:center; color:#888; margin-top:5px;'>"
        f"{st.session_state['traffic_record'] + 1:,} / {total_records:,}"
        f"</div>",
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
        f"<div style='font-size:18px; font-weight:600;'>"
        f"{prediction}"
        f"</div>",
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
            f"<div style='font-size:18px; font-weight:600;'>"
            f"{confidence:.1f}%"
            f"</div>",
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

    # Temporary placeholder
    # We will replace this with your Random Forest prediction
    st.session_state["prediction"] = "—"
    st.session_state["confidence"] = None

    st.rerun()


if explain_clicked:

    if st.session_state.get("prediction") in [None, "—"]:

        st.warning(
            "Please analyze the traffic record before requesting an explanation."
        )

    else:

        st.session_state["analysis_status"] = "Explanation Pending"

        st.rerun()


if reset_clicked:

    st.session_state["traffic_record"] = 0
    st.session_state["analysis_status"] = "Ready"
    st.session_state["prediction"] = "—"
    st.session_state["confidence"] = None

    # Clear XAI results
    st.session_state.pop("shap_values", None)
    st.session_state.pop("lime_explanation", None)
    st.session_state.pop("current_record", None)

    st.rerun()


# ============================================================
# MAIN DASHBOARD
# ============================================================

# ============================================================
# INCIDENT SEARCH MODULE
# ============================================================

st.markdown("""
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
""", unsafe_allow_html=True)


# ============================================================
# INCIDENT DATA
# Load actual EdgeIIoT dataset
# ============================================================

# Your project structure:
# xai_iiot_prototype/
# ├── data/
# │   └── EdgeIIoT_train_80.csv
# └── main_dashboardv4.py

DATASET_PATH = Path(__file__).resolve().parent / "data" / "EdgeIIoT_train_80.csv"

try:
    incident_data = pd.read_csv(
        DATASET_PATH,
        low_memory=False
    )

    # --------------------------------------------------------
    # Generate Incident IDs
    # ALR-000001 → ALR-126240
    # --------------------------------------------------------
    if "Incident ID" not in incident_data.columns:
        incident_data.insert(
            0,
            "Incident ID",
            [
                f"ALR-{i:06d}"
                for i in range(1, len(incident_data) + 1)
            ]
        )

    # --------------------------------------------------------
    # Convert frame.time into proper datetime
    # --------------------------------------------------------
    if "frame.time" in incident_data.columns:

        incident_data["DateTime"] = pd.to_datetime(
            incident_data["frame.time"].astype(str).str.strip(),
            errors="coerce"
        )

    else:
        st.error(
            "The dataset does not contain the required "
            "'frame.time' column."
        )
        incident_data["DateTime"] = pd.NaT

    # --------------------------------------------------------
    # Create Date and Time columns from frame.time
    # --------------------------------------------------------
    incident_data["Date"] = incident_data["DateTime"].dt.date

    incident_data["Time"] = (
        incident_data["DateTime"]
        .dt.time
    )

    # --------------------------------------------------------
    # Create Source IP column
    # --------------------------------------------------------
    if "ip.src_host" in incident_data.columns:
        incident_data["Source IP"] = (
            incident_data["ip.src_host"]
            .astype(str)
        )
    else:
        incident_data["Source IP"] = "Unknown"

    # --------------------------------------------------------
    # Create Traffic Type
    # --------------------------------------------------------
    if "Attack_label" in incident_data.columns:

        incident_data["Type"] = incident_data["Attack_label"].apply(
            lambda x: "Normal" if str(x).strip() in ["0", "0.0"]
            else "Attack"
        )

    else:
        incident_data["Type"] = "Unknown"

    # --------------------------------------------------------
    # Create Severity
    # --------------------------------------------------------
    # Dashboard rule:
    # Normal traffic  -> Low
    # Attack traffic  -> High
    incident_data["Severity"] = incident_data["Type"].apply(
        lambda x: "Low" if x == "Normal" else "High"
    )

    # --------------------------------------------------------
    # Create Status
    # --------------------------------------------------------
    incident_data["Status"] = incident_data["Type"].apply(
        lambda x: "Normal" if x == "Normal" else "Open"
    )

    # --------------------------------------------------------
    # Remove rows where timestamp could not be parsed
    # --------------------------------------------------------
    incident_data = incident_data.dropna(
        subset=["DateTime"]
    ).reset_index(drop=True)

    st.success(
        f"Loaded {len(incident_data):,} incident records successfully."
    )

except FileNotFoundError:

    st.error(
        f"Dataset not found at:\n{DATASET_PATH}\n\n"
        "Make sure EdgeIIoT_train_80.csv is inside the data folder."
    )

    incident_data = pd.DataFrame()

except Exception as e:

    st.error(
        f"Error loading incident dataset:\n{e}"
    )

    incident_data = pd.DataFrame()




# ============================================================
# INCIDENT SEARCH UI
# ============================================================

st.markdown("""
<div class="incident-search-box">

<div class="incident-title">
🔎 INCIDENT SEARCH
</div>

<div class="incident-subtitle">
Search by incident ID or select a time range to view detected incidents
</div>

</div>
""", unsafe_allow_html=True)


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

# ------------------------------------------------------------
# Search an Incident ID and automatically load its timestamp
# into the Time Range fields.
# ------------------------------------------------------------
def search_incident_by_id():

    query = st.session_state.get("incident_id_search", "").strip()

    if not query:
        st.session_state["incident_id_error"] = "Please enter an Incident ID."
        st.session_state["incident_id_found"] = False
        return

    # Exact Incident ID match (case-insensitive)
    matches = incident_data[
        incident_data["Incident ID"].astype(str).str.strip().str.upper() == query.upper()
    ]

    if matches.empty:
        st.session_state["incident_id_error"] = f"Incident ID '{query}' was not found."
        st.session_state["incident_id_found"] = False
        return

    selected = matches.iloc[0]
    incident_datetime = pd.to_datetime(selected["DateTime"])

    # Automatically change the From/To date and time to the
    # date/time belonging to the searched Incident ID.
    st.session_state["from_date"] = incident_datetime.date()
    st.session_state["from_time"] = incident_datetime.time().replace(microsecond=0)
    st.session_state["to_date"] = incident_datetime.date()
    st.session_state["to_time"] = incident_datetime.time().replace(microsecond=0)

    # Show the searched incident immediately.
    st.session_state["incident_results"] = matches.copy()
    st.session_state["incident_search_performed"] = True
    st.session_state["incident_id_found"] = True
    st.session_state["incident_id_error"] = ""
    st.session_state["selected_incident_data"] = selected.to_dict()


with id_col2:

    id_search_clicked = st.button(
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


# From Date
with col1:

    from_date = st.date_input(
        "From Date",
        value=date(2026, 9, 21),
        key="from_date"
    )


# From Time
with col2:

    from_time = st.time_input(
        "From Time",
        value=time(8, 0),
        key="from_time"
    )


# To Date
with col3:

    to_date = st.date_input(
        "To Date",
        value=date(2026, 9, 21),
        key="to_date"
    )


# To Time
with col4:

    to_time = st.time_input(
        "To Time",
        value=time(12, 0),
        key="to_time"
    )


# ============================================================
# FILTERS
# ============================================================

filter_col1, filter_col2, filter_col3, button_col = st.columns(
    [1, 1, 1, 1.15]
)


# Traffic Type
with filter_col1:

    traffic_type = st.selectbox(
        "Traffic Type",
        [
            "All",
            "Normal",
            "Port Scan",
            "DoS",
            "Brute Force",
            "Botnet",
            "Malware",
            "Reconnaissance",
            "Injection"
        ],
        key="traffic_type_filter"
    )


# Severity
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


# Status
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

    st.markdown("<br>", unsafe_allow_html=True)

    search_clicked = st.button(
        "🔍  Search Incidents",
        type="primary",
        use_container_width=True,
        key="search_incidents"
    )


# ============================================================
# SEARCH LOGIC
# ============================================================

# ------------------------------------------------------------
# ID search feedback
# ------------------------------------------------------------
if st.session_state.get("incident_id_error"):
    st.error(f"⚠️ {st.session_state['incident_id_error']}")

elif st.session_state.get("incident_id_found"):
    found_data = st.session_state.get("incident_results", pd.DataFrame())
    if not found_data.empty:
        found_row = found_data.iloc[0]
        st.success(
            f"Incident {found_row['Incident ID']} found. "
            f"Time Range updated to {found_row['Date']} {found_row['Time']}."
        )


if search_clicked:

    # --------------------------------------------------------
    # Create selected datetime range
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
            "⚠️ From date/time cannot be later than To date/time."
        )

    else:

        filtered_data = incident_data.copy()


        # ----------------------------------------------------
        # Incident ID filter
        # ----------------------------------------------------

        if incident_id.strip():

            filtered_data = filtered_data[
                filtered_data["Incident ID"]
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
            (filtered_data["DateTime"] >= start_datetime)
            &
            (filtered_data["DateTime"] <= end_datetime)
        ]


        # ----------------------------------------------------
        # Traffic type filter
        # ----------------------------------------------------

        if traffic_type != "All":

            filtered_data = filtered_data[
                filtered_data["Type"] == traffic_type
            ]


        # ----------------------------------------------------
        # Severity filter
        # ----------------------------------------------------

        if severity != "All":

            filtered_data = filtered_data[
                filtered_data["Severity"] == severity
            ]


        # ----------------------------------------------------
        # Status filter
        # ----------------------------------------------------

        if status != "All":

            filtered_data = filtered_data[
                filtered_data["Status"] == status
            ]


        # ----------------------------------------------------
        # Save results
        # ----------------------------------------------------

        st.session_state["incident_results"] = filtered_data

        st.session_state["incident_search_performed"] = True


# ============================================================
# INCIDENT RESULTS
# ============================================================

if st.session_state.get(
    "incident_search_performed",
    False
):

    results = st.session_state.get(
        "incident_results",
        pd.DataFrame()
    )


    # ========================================================
    # RESULTS HEADER
    # ========================================================

    st.markdown(
        '<div class="search-divider"></div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-label">INCIDENTS FOUND</div>',
        unsafe_allow_html=True
    )


    st.caption(
        f"Showing incidents from "
        f"{from_date} {from_time.strftime('%H:%M')} "
        f"→ "
        f"{to_date} {to_time.strftime('%H:%M')}"
    )


    # ========================================================
    # RESULTS COUNT
    # ========================================================

    st.info(
        f"Found **{len(results)}** incident(s)"
    )


    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    if len(results) > 0:

        display_data = results[
            [
                "Incident ID",
                "Time",
                "Source IP",
                "Type",
                "Severity",
                "Status"
            ]
        ].copy()


        # Add row number
        display_data.insert(
            0,
            "#",
            range(
                1,
                len(display_data) + 1
            )
        )


        st.dataframe(
            display_data,
            use_container_width=True,
            hide_index=True,
            column_config={

                "Incident ID": st.column_config.TextColumn(
                    "Incident ID",
                    width="medium"
                ),

                "Time": st.column_config.TextColumn(
                    "Time",
                    width="small"
                ),

                "Source IP": st.column_config.TextColumn(
                    "Source IP",
                    width="medium"
                ),

                "Type": st.column_config.TextColumn(
                    "Type",
                    width="medium"
                ),

                "Severity": st.column_config.TextColumn(
                    "Severity",
                    width="small"
                ),

                "Status": st.column_config.TextColumn(
                    "Status",
                    width="medium"
                )
            }
        )


        # ====================================================
        # SELECT INCIDENT
        # ====================================================

        st.markdown("### Select Incident")

        selected_incident = st.selectbox(
            "Select an incident to investigate",
            results["Incident ID"].tolist(),
            key="selected_incident"
        )


        if st.button(
            "👁️  View Incident",
            type="primary",
            key="view_incident"
        ):

            selected_row = results[
                results["Incident ID"] == selected_incident
            ].iloc[0]


            # Save selected incident
            st.session_state["selected_incident_data"] = (
                selected_row.to_dict()
            )

            st.session_state["incident_selected"] = True

            st.success(
                f"Selected incident: {selected_incident}"
            )


    else:

        st.warning(
            "No incidents were found for the selected "
            "date/time range and filters."
        )