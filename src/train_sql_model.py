import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

from sql_feature_extractor import extract_sql_features


# ============================================================
# DATASETS
# ============================================================

NORMAL_DATASET = r"data/EdgeIIoT_train_80.csv"
SQLI_DATASET = r"data/SQL_injection_train_80.csv"


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("LOADING DATASETS")
print("=" * 60)

print("\nLoading EdgeIIoT dataset...")
edge_df = pd.read_csv(NORMAL_DATASET)

print("EdgeIIoT shape:", edge_df.shape)

print("\nOriginal Attack_label distribution:")
print(edge_df["Attack_label"].value_counts())


print("\nLoading SQL Injection dataset...")
sqli_df = pd.read_csv(SQLI_DATASET)

print("SQL Injection dataset shape:", sqli_df.shape)


# ============================================================
# SELECT ONLY NORMAL TRAFFIC
# ============================================================

print("\n" + "=" * 60)
print("SELECTING NORMAL TRAFFIC")
print("=" * 60)

# Attack_label = 0 means normal traffic
normal_df = edge_df[edge_df["Attack_label"] == 0].copy()

print("Normal traffic rows:", len(normal_df))
print("SQL Injection rows:", len(sqli_df))


# ============================================================
# CREATE LABELS
# ============================================================

normal_df["SQLI_label"] = 0
sqli_df["SQLI_label"] = 1


# ============================================================
# BALANCE DATASET
# ============================================================

print("\n" + "=" * 60)
print("BALANCING DATASET")
print("=" * 60)

# Use the same number of samples from each class
sample_count = min(len(normal_df), len(sqli_df))

normal_df = normal_df.sample(
    n=sample_count,
    random_state=42
)

sqli_df = sqli_df.sample(
    n=sample_count,
    random_state=42
)

print("Normal samples:", len(normal_df))
print("SQL Injection samples:", len(sqli_df))


# ============================================================
# EXTRACT SQL FEATURES
# ============================================================

print("\n" + "=" * 60)
print("EXTRACTING SQL FEATURES")
print("=" * 60)

print("\nExtracting features from normal traffic...")

normal_features = pd.DataFrame(
    [
        extract_sql_features(row)
        for _, row in normal_df.iterrows()
    ]
)

print("Normal feature shape:", normal_features.shape)


print("\nExtracting features from SQL Injection traffic...")

sqli_features = pd.DataFrame(
    [
        extract_sql_features(row)
        for _, row in sqli_df.iterrows()
    ]
)

print("SQL Injection feature shape:", sqli_features.shape)


# ============================================================
# COMBINE DATA
# ============================================================

X = pd.concat(
    [normal_features, sqli_features],
    ignore_index=True
)

y = pd.concat(
    [
        normal_df["SQLI_label"],
        sqli_df["SQLI_label"]
    ],
    ignore_index=True
)


# ============================================================
# CLEAN FEATURES
# ============================================================

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)


print("\n" + "=" * 60)
print("FINAL DATASET")
print("=" * 60)

print("Feature shape:", X.shape)

print("\nClass distribution:")

print(
    y.value_counts()
    .rename(
        index={
            0: "Normal",
            1: "SQL Injection"
        }
    )
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", X_train.shape)
print("Testing samples:", X_test.shape)


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print("\n" + "=" * 60)
print("TRAINING RANDOM FOREST SQL INJECTION IDS")
print("=" * 60)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)


# ============================================================
# PREDICTION
# ============================================================

print("\nMaking predictions...")

y_pred = model.predict(X_test)


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)


print("\n" + "=" * 60)
print("SQL INJECTION MODEL RESULTS")
print("=" * 60)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Normal",
            "SQL Injection"
        ],
        zero_division=0
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 60)
print("TOP FEATURES")
print("=" * 60)

importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

print(
    importance.head(15).to_string(
        index=False
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

print("\n" + "=" * 60)
print("SAVING MODEL")
print("=" * 60)

joblib.dump(
    model,
    "models/sql_injection_rf.pkl"
)

joblib.dump(
    list(X.columns),
    "models/sql_feature_columns.pkl"
)

print("\nModel saved:")
print("models/sql_injection_rf.pkl")

print("\nFeature columns saved:")
print("models/sql_feature_columns.pkl")

print("\nTraining completed successfully!")