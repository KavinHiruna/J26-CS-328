import pandas as pd
import joblib
import shap

from sql_feature_extractor import extract_sql_features


MODEL_PATH = "models/sql_injection_rf.pkl"
FEATURE_PATH = "models/sql_feature_columns.pkl"
DATASET_PATH = "data/EdgeIIoT_train_80.csv"


print("=" * 60)
print("XAI SQL INJECTION DETECTION")
print("=" * 60)


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading Random Forest model...")

model = joblib.load(MODEL_PATH)

feature_columns = joblib.load(FEATURE_PATH)

print("Model loaded successfully.")
print("Number of features:", len(feature_columns))


# ============================================================
# LOAD SAMPLE REQUEST
# ============================================================

dataset = pd.read_csv(DATASET_PATH)

print("\nDataset shape:", dataset.shape)


# Select one SQL injection example
row = dataset.iloc[0]


# ============================================================
# EXTRACT FEATURES
# ============================================================

print("\nExtracting SQL features...")

features = extract_sql_features(row)

X = pd.DataFrame([features])

# Make sure feature order is identical to training
X = X.reindex(
    columns=feature_columns,
    fill_value=0
)

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)


# ============================================================
# MODEL PREDICTION
# ============================================================

prediction = model.predict(X)[0]

probabilities = model.predict_proba(X)[0]

normal_probability = probabilities[0]

sqli_probability = probabilities[1]


print("\n" + "=" * 60)
print("MODEL PREDICTION")
print("=" * 60)

if prediction == 1:
    print("Prediction : SQL INJECTION")
else:
    print("Prediction : NORMAL")

print(f"Normal probability       : {normal_probability:.4f}")
print(f"SQL Injection probability: {sqli_probability:.4f}")


# ============================================================
# SHAP EXPLAINER
# ============================================================

print("\nCalculating SHAP explanation...")

explainer = shap.TreeExplainer(model)

shap_values = explainer.shap_values(X)


# ============================================================
# HANDLE SHAP OUTPUT
# ============================================================

if isinstance(shap_values, list):

    # Binary classification
    values = shap_values[1][0]

else:

    values = shap_values[0]

    if len(values.shape) > 1:
        values = values[:, 1]


# ============================================================
# CREATE EXPLANATION TABLE
# ============================================================

explanation = pd.DataFrame({
    "Feature": feature_columns,
    "Value": X.iloc[0].values,
    "SHAP": values
})


# Sort by absolute SHAP value
explanation["Abs_SHAP"] = explanation["SHAP"].abs()

explanation = explanation.sort_values(
    "Abs_SHAP",
    ascending=False
)


# ============================================================
# DISPLAY TOP FEATURES
# ============================================================

print("\n" + "=" * 60)
print("TOP FEATURES CONTRIBUTING TO DECISION")
print("=" * 60)

top_features = explanation.head(15)

for _, row in top_features.iterrows():

    direction = (
        "INCREASES SQLi"
        if row["SHAP"] > 0
        else "DECREASES SQLi"
    )

    print(
        f"{row['Feature']:30s} "
        f"Value={row['Value']:<10} "
        f"SHAP={row['SHAP']:+.5f} "
        f"{direction}"
    )


# ============================================================
# HUMAN-READABLE EXPLANATION
# ============================================================

print("\n" + "=" * 60)
print("HUMAN-READABLE EXPLANATION")
print("=" * 60)

# Top positive contributors
positive_features = explanation[
    explanation["SHAP"] > 0
].head(5)

# Top negative contributors
negative_features = explanation[
    explanation["SHAP"] < 0
].head(5)


if prediction == 1:

    print(
        f"\nThe request was classified as SQL Injection "
        f"with a model probability of "
        f"{sqli_probability:.2%}."
    )

    if len(positive_features) > 0:

        print(
            "\nThe following features increased the "
            "SQL Injection prediction:"
        )

        for _, feature in positive_features.iterrows():

            print(
                f"  • {feature['Feature']} "
                f"(SHAP: {feature['SHAP']:+.5f})"
            )

    if len(negative_features) > 0:

        print(
            "\nThe following features decreased the "
            "SQL Injection prediction:"
        )

        for _, feature in negative_features.iterrows():

            print(
                f"  • {feature['Feature']} "
                f"(SHAP: {feature['SHAP']:+.5f})"
            )

else:

    print(
        f"\nThe request was classified as Normal "
        f"with a model probability of "
        f"{normal_probability:.2%}."
    )

    if len(negative_features) > 0:

        print(
            "\nThe following features decreased the "
            "SQL Injection prediction:"
        )

        for _, feature in negative_features.iterrows():

            print(
                f"  • {feature['Feature']} "
                f"(SHAP: {feature['SHAP']:+.5f})"
            )

    if len(positive_features) > 0:

        print(
            "\nThe following features increased the "
            "SQL Injection prediction:"
        )

        for _, feature in positive_features.iterrows():

            print(
                f"  • {feature['Feature']} "
                f"(SHAP: {feature['SHAP']:+.5f})"
            )


print("\n" + "=" * 60)
print("Explanation completed.")
print("=" * 60)