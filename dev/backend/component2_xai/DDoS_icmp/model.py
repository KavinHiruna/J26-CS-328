"""
Model loading, adaptation and training for the DDoS ICMP Flood detector.

`ModelAdapter` hides the differences between what people upload:
  * a bundle saved by `train.py` (dict with model / feature_names / class_names / ...)
  * a bare scikit-learn style estimator or Pipeline (.joblib / .pkl)
  * an optional separate "feature encoder": either a feature transformer
    (StandardScaler, ColumnTransformer, ...) or a LabelEncoder for class names.
Explanations are always produced in the human-readable feature space; any
feature encoder is applied inside `predict_proba`.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .config import ATTACK_TYPE_ALIASES, DEFAULT_MODEL_PATH, MODEL_FEATURES
from .features import to_numeric


def _is_label_encoder(obj) -> bool:
    return hasattr(obj, "classes_") and hasattr(obj, "inverse_transform") and not hasattr(obj, "n_features_in_") \
        and not hasattr(obj, "transform_features")


def _final_estimator(model):
    return model.steps[-1][1] if hasattr(model, "steps") else model


@dataclass
class ModelAdapter:
    model: object
    feature_names: list
    feature_encoder: object | None = None
    label_encoder: object | None = None
    class_names: dict = field(default_factory=dict)   # raw class value -> display name
    meta: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ construction
    @classmethod
    def from_objects(cls, model_obj, encoder_obj=None) -> "ModelAdapter":
        meta, class_names, feature_names = {}, {}, None
        feature_encoder = label_encoder = None

        if isinstance(model_obj, dict):
            if "model" not in model_obj:
                raise ValueError("Bundle dict has no 'model' key.")
            meta = dict(model_obj.get("meta", {}))
            feature_names = model_obj.get("feature_names")
            class_names = dict(model_obj.get("class_names", {}))
            enc = model_obj.get("encoder") or model_obj.get("feature_encoder")
            if enc is not None:
                encoder_obj = encoder_obj or enc
            if model_obj.get("label_encoder") is not None:
                label_encoder = model_obj["label_encoder"]
            model_obj = model_obj["model"]

        if not (hasattr(model_obj, "predict_proba") or hasattr(model_obj, "decision_function") or hasattr(model_obj, "predict")):
            raise TypeError(f"Uploaded object of type {type(model_obj).__name__} is not a classifier.")

        if encoder_obj is not None:
            if isinstance(encoder_obj, dict):
                label_encoder = encoder_obj.get("label_encoder", label_encoder)
                encoder_obj = encoder_obj.get("feature_encoder") or encoder_obj.get("encoder")
            if encoder_obj is not None:
                if _is_label_encoder(encoder_obj):
                    label_encoder = encoder_obj
                elif hasattr(encoder_obj, "transform"):
                    feature_encoder = encoder_obj
                else:
                    raise TypeError(f"Encoder of type {type(encoder_obj).__name__} has no transform().")

        if feature_names is None:
            for src in (feature_encoder, model_obj, _final_estimator(model_obj),
                        model_obj.steps[0][1] if hasattr(model_obj, "steps") else None):
                names = getattr(src, "feature_names_in_", None) if src is not None else None
                if names is not None:
                    feature_names = [str(n) for n in names]
                    break
        if feature_names is None:
            n_in = getattr(feature_encoder, "n_features_in_", None) or getattr(model_obj, "n_features_in_", None)
            if n_in is not None and n_in != len(MODEL_FEATURES):
                raise ValueError(
                    f"The model expects {n_in} unnamed features but the ICMP feature set has {len(MODEL_FEATURES)}. "
                    "Re-train with named features (pandas DataFrame) or save a bundle with 'feature_names'."
                )
            feature_names = list(MODEL_FEATURES)

        adapter = cls(model=model_obj, feature_names=list(feature_names), feature_encoder=feature_encoder,
                      label_encoder=label_encoder, class_names=class_names, meta=meta)
        adapter._fill_class_names()
        return adapter

    @classmethod
    def from_bytes(cls, model_bytes: bytes, encoder_bytes: bytes | None = None) -> "ModelAdapter":
        model_obj = joblib.load(io.BytesIO(model_bytes))
        enc_obj = joblib.load(io.BytesIO(encoder_bytes)) if encoder_bytes else None
        return cls.from_objects(model_obj, enc_obj)

    @classmethod
    def from_path(cls, path: str | Path = DEFAULT_MODEL_PATH, encoder_path: str | Path | None = None) -> "ModelAdapter":
        model_obj = joblib.load(path)
        enc_obj = joblib.load(encoder_path) if encoder_path else None
        return cls.from_objects(model_obj, enc_obj)

    # ------------------------------------------------------------------ classes
    @property
    def classes(self) -> list:
        est = _final_estimator(self.model)
        cl = getattr(self.model, "classes_", None)
        if cl is None:
            cl = getattr(est, "classes_", None)
        return list(cl) if cl is not None else [0, 1]

    def _fill_class_names(self):
        for c in self.classes:
            if c in self.class_names:
                continue
            name = c
            if self.label_encoder is not None:
                try:
                    name = self.label_encoder.inverse_transform([c])[0]
                except Exception:
                    pass
            self.class_names[c] = str(name)

    def display_class(self, c) -> str:
        return self.class_names.get(c, str(c))

    def guess_attack_class(self):
        """Best default for 'which class means DDoS ICMP flood / attack'."""
        aliases = {a.lower() for a in ATTACK_TYPE_ALIASES}
        for c in self.classes:
            if self.display_class(c).lower() in aliases or "icmp" in self.display_class(c).lower():
                return c
        for c in self.classes:
            if str(c) in ("1", "1.0", "True", "attack", "Attack"):
                return c
        return self.classes[-1]

    def class_index(self, c) -> int:
        return self.classes.index(c)

    # ------------------------------------------------------------------ data
    def prepare(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Pick model columns from engineered features (+ raw columns if the model was trained on raw ones)."""
        X = pd.DataFrame(index=frame.index)
        missing = []
        for f in self.feature_names:
            if f in frame.columns:
                X[f] = to_numeric(frame[f])
            else:
                X[f] = 0.0
                missing.append(f)
        self.meta["missing_features"] = missing
        return X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(float)

    def _as_model_input(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(np.asarray(X, dtype=float).reshape(-1, len(self.feature_names)), columns=self.feature_names)
        if self.feature_encoder is not None:
            enc_in = X if hasattr(self.feature_encoder, "feature_names_in_") else X.values
            X = self.feature_encoder.transform(enc_in)
            if hasattr(X, "toarray"):
                X = X.toarray()
            names = getattr(self.model, "feature_names_in_", None)
            if names is not None and not isinstance(X, pd.DataFrame) and np.asarray(X).shape[1] == len(names):
                X = pd.DataFrame(np.asarray(X), columns=list(names))
            return X
        needs_names = getattr(self.model, "feature_names_in_", None) is not None
        return X if needs_names else X.values

    def predict_proba(self, X) -> np.ndarray:
        Xm = self._as_model_input(X)
        if hasattr(self.model, "predict_proba"):
            return np.asarray(self.model.predict_proba(Xm), dtype=float)
        if hasattr(self.model, "decision_function"):
            d = np.asarray(self.model.decision_function(Xm), dtype=float)
            if d.ndim == 1:
                p = 1 / (1 + np.exp(-d))
                return np.column_stack([1 - p, p])
            e = np.exp(d - d.max(axis=1, keepdims=True))
            return e / e.sum(axis=1, keepdims=True)
        pred = np.asarray(self.model.predict(Xm))
        return np.column_stack([(pred == c).astype(float) for c in self.classes])

    def attack_proba(self, X, attack_class) -> np.ndarray:
        return self.predict_proba(X)[:, self.class_index(attack_class)]

    @property
    def is_tree_model(self) -> bool:
        if self.feature_encoder is not None or hasattr(self.model, "steps"):
            return False
        est = self.model
        name = type(est).__name__.lower()
        return hasattr(est, "estimators_") or hasattr(est, "tree_") or any(
            k in name for k in ("xgb", "lgbm", "catboost", "gradientboosting", "histgradient"))

    def describe(self) -> dict:
        return {
            "model_type": type(self.model).__name__,
            "n_features": len(self.feature_names),
            "classes": [self.display_class(c) for c in self.classes],
            "feature_encoder": type(self.feature_encoder).__name__ if self.feature_encoder is not None else None,
            "label_encoder": type(self.label_encoder).__name__ if self.label_encoder is not None else None,
            **{k: v for k, v in self.meta.items() if k in ("trained_on", "metrics", "created", "model_name")},
        }


# ====================================================================== training
def train_model(features: pd.DataFrame, n_estimators: int = 200, random_state: int = 42,
                test_size: float = 0.25) -> tuple[dict, dict]:
    """
    Train a RandomForest on the engineered ICMP features.
    Split is grouped by traffic window so packets of one window never sit on both sides.
    Returns (bundle, metrics).
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                                 recall_score, roc_auc_score)
    from sklearn.model_selection import GroupShuffleSplit

    if "target" not in features.columns:
        raise ValueError("Training data has no labels (Attack_type / Attack_label).")
    y = features["target"].astype(int).values
    if len(np.unique(y)) < 2:
        raise ValueError("Training data needs both DDoS ICMP flood rows and normal/other rows.")
    X = features[list(MODEL_FEATURES)].astype(float)

    capture = features["capture"] if "capture" in features else pd.Series(0, index=features.index)
    groups = (capture.astype(str) + "|" + features["dst_ip"].astype(str) + "|"
              + features["window_id"].astype(str)).values
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    tr, te = next(splitter.split(X, y, groups))
    if len(np.unique(y[te])) < 2 or len(np.unique(y[tr])) < 2:   # fall back to a stratified split
        from sklearn.model_selection import train_test_split
        tr, te = train_test_split(np.arange(len(y)), test_size=test_size, stratify=y, random_state=random_state)

    clf = RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=2, class_weight="balanced",
                                 n_jobs=-1, random_state=random_state)
    clf.fit(X.iloc[tr], y[tr])
    proba = clf.predict_proba(X.iloc[te])[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "accuracy": float(accuracy_score(y[te], pred)),
        "precision": float(precision_score(y[te], pred, zero_division=0)),
        "recall": float(recall_score(y[te], pred, zero_division=0)),
        "f1": float(f1_score(y[te], pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y[te], proba)) if len(np.unique(y[te])) > 1 else float("nan"),
        "confusion_matrix": confusion_matrix(y[te], pred).tolist(),
        "n_train": int(len(tr)),
        "n_test": int(len(te)),
        "feature_importance": dict(sorted(zip(MODEL_FEATURES, map(float, clf.feature_importances_)),
                                          key=lambda kv: -kv[1])),
    }
    bundle = {
        "model": clf,
        "feature_names": list(MODEL_FEATURES),
        "class_names": {0: "Normal / other", 1: "DDoS ICMP Flood"},
        "meta": {
            "model_name": "RandomForest - DDoS ICMP Flood",
            "created": pd.Timestamp.now().isoformat(timespec="seconds"),
            "metrics": {k: v for k, v in metrics.items() if k not in ("feature_importance",)},
            "trained_on": int(len(features)),
        },
    }
    return bundle, metrics


def save_bundle(bundle: dict, path: str | Path = DEFAULT_MODEL_PATH) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return path
