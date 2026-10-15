import joblib
import shap
import pandas as pd

from src.sql_feature_extractor import extract_sql_features


# ============================================================
# LOAD SQL INJECTION MODEL
# ============================================================

model = joblib.load(
    "models/sql_injection_rf.pkl"
)

feature_columns = joblib.load(
    "models/sql_feature_columns.pkl"
)

explainer = shap.TreeExplainer(model)


# ============================================================
# SQL INJECTION XAI
# ============================================================

def explain_sql_request(row):

    # Extract SQL / HTTP features
    features = extract_sql_features(row)

    # Create dataframe
    X = pd.DataFrame([features])

    # Ensure exact feature order
    X = X.reindex(
        columns=feature_columns,
        fill_value=0
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(X)[0]

    probability = model.predict_proba(X)[0]

    # --------------------------------------------------------
    # SHAP
    # --------------------------------------------------------

    shap_values = explainer.shap_values(X)

    if isinstance(shap_values, list):

        values = shap_values[1][0]

    else:

        values = shap_values[0]

        if len(values.shape) > 1:
            values = values[:, 1]

    # --------------------------------------------------------
    # Explanation dataframe
    # --------------------------------------------------------

    explanation = pd.DataFrame({
        "feature": feature_columns,
        "value": X.iloc[0].values,
        "shap_value": values,
    })

    explanation["impact"] = (
        explanation["shap_value"].abs()
    )

    explanation["direction"] = explanation[
        "shap_value"
    ].apply(
        lambda x:
            "INCREASES SQL Injection"
            if x > 0
            else "DECREASES SQL Injection"
    )

    explanation = explanation.sort_values(
        "impact",
        ascending=False
    ).reset_index(drop=True)

    return {
        "prediction": int(prediction),

        "normal_probability":
            float(probability[0]),

        "sql_injection_probability":
            float(probability[1]),

        "explanation":
            explanation
    }