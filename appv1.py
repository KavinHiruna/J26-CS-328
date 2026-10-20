import joblib
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from model_pipeline import (
    CLASS_NAMES,
    FEATURES,
    MODEL_PATH,
    load_data,
    train_model,
)

from xai_engine import XAIEngine
from src.xai_sql import explain_sql_request


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="IIoT XAI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Explainable AI Security Dashboard")

st.caption(
    "Random Forest IDS + SHAP-based Explainable AI"
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("Detection Module")

detection_type = st.sidebar.selectbox(
    "Select Detection Type",
    [
        "IIoT Network IDS",
        "SQL Injection",
    ],
    index=1
)


# ============================================================
# SQL INJECTION DASHBOARD
# ============================================================

if detection_type == "SQL Injection":

    st.header("SQL Injection XAI Detector")

    st.caption(
        "Random Forest SQL Injection Detection + SHAP Explanation"
    )

    # --------------------------------------------------------
    # Load available dataset
    # --------------------------------------------------------

    dataset_path = "data/EdgeIIoT_train_80.csv"

    try:
        sql_df = pd.read_csv(dataset_path)

    except FileNotFoundError:

        st.error(
            f"Dataset not found: {dataset_path}"
        )

        st.stop()

    # --------------------------------------------------------
    # Select record
    # --------------------------------------------------------

    st.sidebar.subheader(
        "SQL Injection Controls"
    )

    record_index = st.sidebar.number_input(
        "Traffic Record",
        min_value=0,
        max_value=len(sql_df) - 1,
        value=0,
        step=1,
    )

    row = sql_df.iloc[
        int(record_index)
    ]

    # --------------------------------------------------------
    # Run SQL XAI
    # --------------------------------------------------------

    result = explain_sql_request(row)

    prediction = result["prediction"]

    normal_probability = result[
        "normal_probability"
    ]

    sql_probability = result[
        "sql_injection_probability"
    ]

    explanation_df = result[
        "explanation"
    ].copy()

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    if prediction == 1:

        prediction_label = "🔴 SQL INJECTION"
        confidence = sql_probability

    else:

        prediction_label = "🟢 NORMAL"
        confidence = normal_probability

    # --------------------------------------------------------
    # Main prediction cards
    # --------------------------------------------------------

    st.subheader(
        "Detection Result"
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Prediction",
        prediction_label
    )

    col2.metric(
        "Confidence",
        f"{confidence:.2%}"
    )

    col3.metric(
        "Record",
        int(record_index)
    )

    st.divider()

    # ========================================================
    # WHY DID THE MODEL DECIDE THIS?
    # ========================================================

    st.subheader(
        "Why Did the Model Decide This?"
    )

    # Take top 5 features
    top_features = (
        explanation_df
        .head(5)
        .copy()
    )

    # Display feature table

    display_df = top_features[
        [
            "feature",
            "value",
            "shap_value",
            "direction",
        ]
    ].copy()

    display_df.columns = [
        "Feature",
        "Value",
        "SHAP Contribution",
        "Effect",
    ]

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
    )

    # ========================================================
    # SHAP BAR CHART
    # ========================================================

    st.subheader(
        "SHAP Feature Contributions"
    )

    plot_df = top_features.sort_values(
        "shap_value"
    )

    fig, ax = plt.subplots(
        figsize=(10, 4.5)
    )

    ax.barh(
        plot_df["feature"],
        plot_df["shap_value"],
    )

    ax.axvline(
        0,
        linewidth=1
    )

    ax.set_xlabel(
        "SHAP Contribution"
    )

    ax.set_ylabel(
        "Feature"
    )

    ax.set_title(
        "Top Features Contributing to the Decision"
    )

    st.pyplot(
        fig,
        clear_figure=True
    )

    # ========================================================
    # HUMAN READABLE EXPLANATION
    # ========================================================

    st.subheader(
        "Human-readable Explanation"
    )

    positive = (
        explanation_df[
            explanation_df["shap_value"] > 0
        ]
        .head(5)
    )

    negative = (
        explanation_df[
            explanation_df["shap_value"] < 0
        ]
        .head(5)
    )

    if prediction == 1:

        st.markdown(
            f"""
### 🔴 SQL Injection Detected

The model classified this traffic as **SQL Injection**
with a probability of **{sql_probability:.2%}**.
"""
        )

        if len(positive) > 0:

            st.markdown(
                "**Features increasing the SQL Injection prediction:**"
            )

            for _, feature in positive.iterrows():

                st.write(
                    f"• `{feature['feature']}` "
                    f"— SHAP: "
                    f"`{feature['shap_value']:+.5f}`"
                )

        if len(negative) > 0:

            st.markdown(
                "**Features decreasing the SQL Injection prediction:**"
            )

            for _, feature in negative.iterrows():

                st.write(
                    f"• `{feature['feature']}` "
                    f"— SHAP: "
                    f"`{feature['shap_value']:+.5f}`"
                )

    else:

        st.markdown(
            f"""
### 🟢 Normal Traffic

The model classified this traffic as **Normal**
with a probability of **{normal_probability:.2%}**.
"""
        )

        if len(negative) > 0:

            st.markdown(
                "**The strongest factors decreasing the SQL Injection prediction were:**"
            )

            for _, feature in negative.iterrows():

                st.write(
                    f"• `{feature['feature']}` "
                    f"— SHAP: "
                    f"`{feature['shap_value']:+.5f}`"
                )

        if len(positive) > 0:

            st.markdown(
                "**Features that increased the SQL Injection prediction:**"
            )

            for _, feature in positive.iterrows():

                st.write(
                    f"• `{feature['feature']}` "
                    f"— SHAP: "
                    f"`{feature['shap_value']:+.5f}`"
                )

    # ========================================================
    # REQUEST INFORMATION
    # ========================================================

    st.divider()

    st.subheader(
        "Traffic Information"
    )

    request_col1, request_col2 = st.columns(2)

    with request_col1:

        st.write(
            "**Source IP**"
        )

        st.code(
            str(
                row.get(
                    "ip.src_host",
                    "N/A"
                )
            )
        )

        st.write(
            "**Destination IP**"
        )

        st.code(
            str(
                row.get(
                    "ip.dst_host",
                    "N/A"
                )
            )
        )

        st.write(
            "**HTTP Method**"
        )

        st.code(
            str(
                row.get(
                    "http.request.method",
                    "N/A"
                )
            )
        )

    with request_col2:

        st.write(
            "**Destination Port**"
        )

        st.code(
            str(
                row.get(
                    "tcp.dstport",
                    "N/A"
                )
            )
        )

        st.write(
            "**Source Port**"
        )

        st.code(
            str(
                row.get(
                    "tcp.srcport",
                    "N/A"
                )
            )
        )

        st.write(
            "**Request URI**"
        )

        st.code(
            str(
                row.get(
                    "http.request.full_uri",
                    "N/A"
                )
            )
        )


# ============================================================
# ORIGINAL IIoT IDS DASHBOARD
# ============================================================

else:

    st.header(
        "IIoT Network Intrusion Detection"
    )

    # --------------------------------------------------------
    # Load / train model
    # --------------------------------------------------------

    if not MODEL_PATH.exists():

        with st.spinner(
            "Training the prototype Random Forest IDS..."
        ):

            train_model()

    bundle = joblib.load(
        MODEL_PATH
    )

    model = bundle["model"]

    X_train = bundle["X_train"]

    df, X, y = load_data()

    engine = XAIEngine(
        model=model,
        X_train=X_train,
        feature_names=FEATURES,
        class_names=CLASS_NAMES,
    )

    # --------------------------------------------------------
    # Controls
    # --------------------------------------------------------

    st.sidebar.subheader(
        "IIoT IDS Controls"
    )

    row_index = st.sidebar.number_input(
        "Select traffic record",
        min_value=0,
        max_value=len(df) - 1,
        value=0,
        step=1,
    )

    top_n = st.sidebar.slider(
        "Number of explanation features",
        min_value=2,
        max_value=min(
            7,
            len(FEATURES)
        ),
        value=4,
    )

    row = X.iloc[
        int(row_index)
    ].values

    prediction, probabilities = engine.predict(
        row
    )

    label = CLASS_NAMES[
        prediction
    ]

    confidence = float(
        probabilities[prediction]
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Prediction",
        label
    )

    col2.metric(
        "Confidence",
        f"{confidence:.1%}"
    )

    col3.metric(
        "Record",
        int(row_index)
    )

    st.divider()

    # --------------------------------------------------------
    # Network Traffic
    # --------------------------------------------------------

    st.subheader(
        "1. Network Traffic Input"
    )

    st.dataframe(
        pd.DataFrame(
            [row],
            columns=FEATURES
        ),
        use_container_width=True,
    )

    # --------------------------------------------------------
    # SHAP
    # --------------------------------------------------------

    st.subheader(
        "2. SHAP Explanation"
    )

    shap_result = engine.shap_explanation(
        row
    )

    shap_df = pd.DataFrame(
        {
            "Feature": FEATURES,
            "Value": row,
            "SHAP contribution":
                shap_result["shap_values"],
        }
    ).sort_values(
        "SHAP contribution"
    )

    fig, ax = plt.subplots(
        figsize=(9, 4.5)
    )

    ax.barh(
        shap_df["Feature"],
        shap_df["SHAP contribution"]
    )

    ax.axvline(
        0,
        linewidth=1
    )

    ax.set_xlabel(
        "Contribution toward predicted class"
    )

    ax.set_title(
        f"SHAP Local Explanation — {label}"
    )

    st.pyplot(
        fig,
        clear_figure=True
    )

    # --------------------------------------------------------
    # LIME
    # --------------------------------------------------------

    st.subheader(
        "3. LIME Local Explanation"
    )

    lime_result = engine.lime_explanation(
        row,
        num_features=top_n
    )

    lime_df = pd.DataFrame(
        lime_result["features"],
        columns=[
            "Feature",
            "LIME contribution"
        ],
    )

    st.dataframe(
        lime_df,
        use_container_width=True
    )

    fig2, ax2 = plt.subplots(
        figsize=(9, 4.5)
    )

    lime_plot = lime_df.sort_values(
        "LIME contribution"
    )

    ax2.barh(
        lime_plot["Feature"],
        lime_plot["LIME contribution"]
    )

    ax2.axvline(
        0,
        linewidth=1
    )

    ax2.set_xlabel(
        "Local contribution"
    )

    ax2.set_title(
        f"LIME Explanation — {label}"
    )

    st.pyplot(
        fig2,
        clear_figure=True
    )

    # --------------------------------------------------------
    # Human readable
    # --------------------------------------------------------

    st.subheader(
        "4. Human-readable Explanation"
    )

    feature_labels = {
        "packet_size": "Packet size",
        "dst_port": "Destination port",
        "duration": "Connection duration",
        "tcp_syn": "TCP SYN flag",
        "packet_count": "Packet count",
        "bytes_in": "Incoming bytes",
        "bytes_out": "Outgoing bytes",
    }

    explanation = (
        engine.human_readable_explanation(
            row=row,
            shap_result=shap_result,
            feature_labels=feature_labels,
            top_n=top_n,
        )
    )

    st.info(
        explanation
    )

    # --------------------------------------------------------
    # Global importance
    # --------------------------------------------------------

    st.subheader(
        "5. Global Feature Importance"
    )

    importance_df = engine.feature_ranking(
        X_train
    )

    st.dataframe(
        importance_df,
        use_container_width=True
    )

    fig3, ax3 = plt.subplots(
        figsize=(9, 4.5)
    )

    plot_df = importance_df.sort_values(
        "importance"
    )

    ax3.barh(
        plot_df["feature"],
        plot_df["importance"]
    )

    ax3.set_xlabel(
        "Mean absolute SHAP value"
    )

    ax3.set_title(
        "Global SHAP Feature Importance"
    )

    st.pyplot(
        fig3,
        clear_figure=True
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "XAI Security Dashboard — "
    "Random Forest + SHAP"
)