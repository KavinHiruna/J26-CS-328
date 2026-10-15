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
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="IIoT XAI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ Explainable AI Security Dashboard")

st.caption(
    "ML-based Intrusion Detection with SHAP-based Explainable AI"
)


# ============================================================
# DETECTION MODULE
# ============================================================

st.sidebar.header("Detection Module")

detection_module = st.sidebar.selectbox(
    "Select detection type",
    [
        "IIoT Network IDS",
        "SQL Injection",
    ],
)


# ============================================================
# SQL INJECTION MODE
# ============================================================

if detection_module == "SQL Injection":

    st.header("💉 SQL Injection Detection")

    st.info(
        "Analyze HTTP traffic and explain why the SQL Injection "
        "model classified the request as malicious or normal."
    )

    # --------------------------------------------------------
    # Load SQL Injection dataset
    # --------------------------------------------------------

    SQL_DATASET = "data/SQL_injection_train_80.csv"

    try:

        sql_df = pd.read_csv(
            SQL_DATASET
        )

    except FileNotFoundError:

        st.error(
            "SQL Injection dataset not found: "
            f"{SQL_DATASET}"
        )

        st.stop()

    # --------------------------------------------------------
    # Select traffic record
    # --------------------------------------------------------

    st.sidebar.subheader(
        "SQL Injection Controls"
    )

    sql_row_index = st.sidebar.number_input(
        "Select SQL traffic record",
        min_value=0,
        max_value=len(sql_df) - 1,
        value=0,
        step=1,
    )

    sql_row = sql_df.iloc[
        int(sql_row_index)
    ]

    # --------------------------------------------------------
    # Run SQL Injection XAI
    # --------------------------------------------------------

    result = explain_sql_request(
        sql_row
    )

    prediction = result[
        "prediction"
    ]

    normal_probability = result[
        "normal_probability"
    ]

    sqli_probability = result[
        "sql_injection_probability"
    ]

    explanation_df = result[
        "explanation"
    ]

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    st.subheader(
        "1. Detection Result"
    )

    col1, col2, col3 = st.columns(3)

    if prediction == 1:

        prediction_label = "🔴 SQL INJECTION"

        confidence = sqli_probability

    else:

        prediction_label = "🟢 NORMAL"

        confidence = normal_probability

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
        int(sql_row_index)
    )

    # --------------------------------------------------------
    # Request Information
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "2. HTTP Request Information"
    )

    request_col1, request_col2 = st.columns(2)

    with request_col1:

        st.write(
            "**HTTP Method**"
        )

        st.code(
            str(
                sql_row.get(
                    "http.request.method",
                    "N/A"
                )
            )
        )

        st.write(
            "**Request URI**"
        )

        st.code(
            str(
                sql_row.get(
                    "http.request.full_uri",
                    "N/A"
                )
            )
        )

    with request_col2:

        st.write(
            "**Query Parameters**"
        )

        st.code(
            str(
                sql_row.get(
                    "http.request.uri.query",
                    "N/A"
                )
            )
        )

        st.write(
            "**Source IP**"
        )

        st.code(
            str(
                sql_row.get(
                    "ip.src_host",
                    "N/A"
                )
            )
        )

    # --------------------------------------------------------
    # SQL Features
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "3. Extracted SQL Features"
    )

    sql_features = explanation_df[
        [
            "feature",
            "value"
        ]
    ].copy()

    sql_features.columns = [
        "Feature",
        "Value"
    ]

    st.dataframe(
        sql_features,
        use_container_width=True,
        height=350,
    )

    # --------------------------------------------------------
    # SHAP Explanation
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "4. Why Did the Model Decide This?"
    )

    top_n = st.sidebar.slider(
        "Number of explanation features",
        min_value=3,
        max_value=15,
        value=5,
    )

    top_features = explanation_df.head(
        top_n
    ).copy()

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
    )

    # --------------------------------------------------------
    # SHAP BAR CHART
    # --------------------------------------------------------

    plot_df = top_features.sort_values(
        "shap_value"
    )

    fig, ax = plt.subplots(
        figsize=(9, 5)
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
        "SQL Injection SHAP Explanation"
    )

    st.pyplot(
        fig,
        clear_figure=True
    )

    # --------------------------------------------------------
    # HUMAN-READABLE EXPLANATION
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "5. Human-readable Explanation"
    )

    positive_features = (
        explanation_df[
            explanation_df["shap_value"] > 0
        ]
        .head(top_n)
    )

    negative_features = (
        explanation_df[
            explanation_df["shap_value"] < 0
        ]
        .head(top_n)
    )

    if prediction == 1:

        explanation_text = (
            f"The model classified this traffic as "
            f"**SQL Injection** with a confidence of "
            f"**{sqli_probability:.2%}**.\n\n"
        )

        if len(positive_features) > 0:

            explanation_text += (
                "**Features increasing the SQL Injection "
                "prediction:**\n\n"
            )

            for _, feature in positive_features.iterrows():

                explanation_text += (
                    f"- `{feature['feature']}` "
                    f"(SHAP: "
                    f"{feature['shap_value']:+.4f})\n"
                )

        if len(negative_features) > 0:

            explanation_text += (
                "\n**Features decreasing the SQL Injection "
                "prediction:**\n\n"
            )

            for _, feature in negative_features.iterrows():

                explanation_text += (
                    f"- `{feature['feature']}` "
                    f"(SHAP: "
                    f"{feature['shap_value']:+.4f})\n"
                )

    else:

        explanation_text = (
            f"The model classified this traffic as "
            f"**Normal** with a confidence of "
            f"**{normal_probability:.2%}**.\n\n"
        )

        if len(negative_features) > 0:

            explanation_text += (
                "**Features reducing the SQL Injection "
                "prediction:**\n\n"
            )

            for _, feature in negative_features.iterrows():

                explanation_text += (
                    f"- `{feature['feature']}` "
                    f"(SHAP: "
                    f"{feature['shap_value']:+.4f})\n"
                )

    st.info(
        explanation_text
    )

    # --------------------------------------------------------
    # SQL INJECTION PROBABILITY
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "6. Prediction Probabilities"
    )

    probability_df = pd.DataFrame(
        {
            "Class": [
                "Normal",
                "SQL Injection",
            ],
            "Probability": [
                normal_probability,
                sqli_probability,
            ],
        }
    )

    st.bar_chart(
        probability_df.set_index(
            "Class"
        )
    )

    st.caption(
        "SHAP explanations show which features contributed "
        "to the model's prediction. Positive SHAP values "
        "increase the SQL Injection prediction, while "
        "negative values decrease it."
    )


# ============================================================
# ORIGINAL IIoT IDS MODE
# ============================================================

else:

    st.header(
        "🌐 IIoT Network Intrusion Detection"
    )

    # Load / train model

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
    # Sidebar controls
    # --------------------------------------------------------

    st.sidebar.header(
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
    # Network traffic
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
    # Human-readable explanation
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
    # Global feature importance
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
    "Explainable AI Security Dashboard — "
    "Random Forest IDS + SHAP"
)