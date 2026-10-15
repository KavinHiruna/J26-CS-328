from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from xai_engine import XAIEngine

DATA_PATH = Path("data/demo_iiot.csv")
MODEL_PATH = Path("models/random_forest_ids.joblib")

FEATURES = [
    "packet_size",
    "dst_port",
    "duration",
    "tcp_syn",
    "packet_count",
    "bytes_in",
    "bytes_out",
]

CLASS_NAMES = ["Normal", "Attack"]


def load_data():
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES]
    y = df["label"]
    return df, X, y


def train_model():
    _, X, y = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "classification_report": classification_report(
            y_test, pred, target_names=CLASS_NAMES, output_dict=True
        ),
        "confusion_matrix": confusion_matrix(y_test, pred),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "features": FEATURES,
            "class_names": CLASS_NAMES,
            "X_train": X_train,
        },
        MODEL_PATH,
    )

    return model, X_train, X_test, y_train, y_test, metrics


def load_model():
    if not MODEL_PATH.exists():
        return train_model()

    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["X_train"], None, None, None, None


if __name__ == "__main__":
    model, X_train, X_test, y_train, y_test, metrics = train_model()
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print("Confusion matrix:")
    print(metrics["confusion_matrix"])

    engine = XAIEngine(
        model=model,
        X_train=X_train,
        feature_names=FEATURES,
        class_names=CLASS_NAMES,
    )

    sample = X_test.iloc[[0]]
    shap_result = engine.shap_explanation(sample.values[0])
    lime_result = engine.lime_explanation(sample.values[0])

    print("\nSHAP:")
    print(shap_result)

    print("\nLIME:")
    print(lime_result)
