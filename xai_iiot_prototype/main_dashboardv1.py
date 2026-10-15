import streamlit as st
import pandas as pd
from datetime import date, time, datetime


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
# SAMPLE INCIDENT DATA
# Replace this later with your actual IDS database / CSV
# ============================================================

incident_data = pd.DataFrame([
    {
        "Incident ID": "INC-00125",
        "Date": "2026-09-21",
        "Time": "08:14:32",
        "Source IP": "10.0.0.25",
        "Type": "Port Scan",
        "Severity": "Medium",
        "Status": "Resolved"
    },
    {
        "Incident ID": "INC-00126",
        "Date": "2026-09-21",
        "Time": "08:37:18",
        "Source IP": "10.0.0.31",
        "Type": "DoS",
        "Severity": "High",
        "Status": "Investigating"
    },
    {
        "Incident ID": "INC-00127",
        "Date": "2026-09-21",
        "Time": "09:12:45",
        "Source IP": "10.0.0.18",
        "Type": "Normal",
        "Severity": "Low",
        "Status": "Normal"
    },
    {
        "Incident ID": "INC-00128",
        "Date": "2026-09-21",
        "Time": "10:05:21",
        "Source IP": "10.0.0.44",
        "Type": "Brute Force",
        "Severity": "High",
        "Status": "Open"
    },
    {
        "Incident ID": "INC-00129",
        "Date": "2026-09-21",
        "Time": "11:43:07",
        "Source IP": "10.0.0.12",
        "Type": "Normal",
        "Severity": "Low",
        "Status": "Normal"
    }
])


# Convert date/time into datetime
incident_data["DateTime"] = pd.to_datetime(
    incident_data["Date"] + " " + incident_data["Time"]
)


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

with id_col2:

    id_search_clicked = st.button(
        "🔍  Search",
        use_container_width=True,
        key="incident_id_button"
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

if search_clicked or id_search_clicked:

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