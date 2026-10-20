import streamlit as st


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