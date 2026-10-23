"""
Detection model + explanations.

Prediction: Random Forest (scikit-learn) trained on the dataset's numeric features.
Uses the Component 1 V2 feature set (71 features) when config.USE_V2_FEATURES is True.
Explanation: per-record feature contributions using the tree-path decomposition
(Saabas method): for each tree, every split on the record's decision path moves
the predicted-class probability up or down; that change is credited to the split
feature, then averaged over trees. Contributions + base rate = predicted probability.
For non-tree models a perturbation fallback is used (replace each feature with its
median and measure the change in probability).
"""
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

from . import config

try:
    from backend.common.v2_features import V2FeatureEncoder
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from common.v2_features import V2FeatureEncoder


def feature_columns(df, label_col, id_col, extra_skip=()):
    skip = set(config.NON_FEATURE_COLUMNS) | {label_col, id_col, config.BINARY_LABEL_COLUMN} | set(extra_skip)
    feats = []
    for c in df.columns:
        n = "".join(ch for ch in c.lower() if ch.isalnum())
        if c in skip or c.startswith("_") or "incident" in n or n.startswith("unnamed") or n in ("id", "index"):
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            feats.append(c)
        else:
            conv = pd.to_numeric(df[c].head(5000), errors="coerce")
            if conv.notna().mean() > 0.95:
                feats.append(c)
    return feats


def _matrix(df, feats, medians=None):
    X = df[feats].apply(pd.to_numeric, errors="coerce")
    if medians is not None:
        X = X.fillna(medians)
    return X.fillna(0.0).astype(np.float32)


class Detector:
    def __init__(self, dataset):
        self.ds = dataset
        self.info = {}
        self._v2_encoder = None
        path = config.MODEL_PATH
        if path.exists():
            bundle = joblib.load(path)
            if isinstance(bundle, dict):
                self.model, self.features = bundle["model"], bundle["features"]
                self.medians = pd.Series(bundle.get("medians", {}))
                self.info = bundle.get("info", {})
                if "v2_encoder" in bundle:
                    self._v2_encoder = bundle["v2_encoder"]
            else:
                self.model = bundle
                self.features = list(getattr(bundle, "feature_names_in_", []))
                self.medians = pd.Series(dtype=float)
            if self._v2_encoder is None:
                missing = [f for f in self.features if f not in dataset.df.columns]
                if missing:
                    raise ValueError(f"Saved model expects columns missing from dataset: {missing[:10]}")
            print(f"[model] loaded {path} ({len(self.features)} features)", flush=True)
        else:
            self._train()
        if self._v2_encoder is None and self.medians.empty:
            self.medians = _matrix(dataset.df[self.features].head(50000), self.features).median()
        self.classes = [str(c) for c in self.model.classes_]

    def _train(self):
        ds = self.ds
        df = ds.df
        use_v2 = getattr(config, "USE_V2_FEATURES", False)
        n = min(config.TRAIN_SAMPLE_SIZE, len(df))
        y_all = df[ds.label_col]
        if n < len(df):
            frac = n / len(df)
            rng = np.random.default_rng(42)
            picked = []
            for _, ix in df.groupby(ds.label_col).indices.items():
                k = min(len(ix), max(50, int(len(ix) * frac)))
                picked.append(rng.choice(ix, size=k, replace=False))
            sample = df.iloc[np.sort(np.concatenate(picked))]
        else:
            sample = df

        if use_v2:
            print("[model] using Component 1 V2 feature set (71 features)", flush=True)
            enc = V2FeatureEncoder()
            enc.fit(sample)
            self._v2_encoder = enc
            self.features = enc.feature_names
            X = enc.transform(sample)
            self.medians = X.median()
        else:
            self.features = feature_columns(df, ds.label_col, ds.id_col, ds.exclude_cols)
            self.medians = _matrix(sample, self.features).median()
            X = _matrix(sample, self.features, self.medians)

        y = sample[ds.label_col].astype(str).to_numpy(dtype=object)
        strat = y if pd.Series(y).value_counts().min() >= 2 else None
        X = X.to_numpy(dtype=np.float32)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=strat)
        print(f"[model] training RandomForest on {len(Xtr):,} rows, {len(self.features)} features ...",
              flush=True)
        t0 = time.time()
        self.model = RandomForestClassifier(**config.RF_PARAMS).fit(Xtr, ytr)
        pred = self.model.predict(Xte)
        self.info = {
            "trained_rows": int(len(Xtr)),
            "holdout_accuracy": round(float(accuracy_score(yte, pred)), 4),
            "holdout_macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
            "train_seconds": round(time.time() - t0, 1),
        }
        print(f"[model] {self.info}", flush=True)
        config.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        bundle = {"model": self.model, "features": self.features,
                  "medians": self.medians.to_dict(), "info": self.info}
        if self._v2_encoder is not None:
            bundle["v2_encoder"] = self._v2_encoder
        joblib.dump(bundle, config.MODEL_PATH)

    # ------------------------------------------------------------------
    def _x(self, pos):
        """One record as a DataFrame if the model was fitted with column names, else NumPy."""
        if self._v2_encoder is not None:
            x = self._v2_encoder.transform(self.ds.df.iloc[[pos]])
        else:
            x = _matrix(self.ds.df.iloc[[pos]], self.features, self.medians)
        return x if hasattr(self.model, "feature_names_in_") else x.to_numpy(dtype=np.float32)

    def predict(self, pos):
        x = self._x(pos)
        proba = self.model.predict_proba(x)[0]
        order = np.argsort(proba)[::-1]
        k = int(order[0])
        actual = self.ds.df.iloc[pos][self.ds.label_col]
        return {
            "predicted": self.classes[k],
            "confidence": float(proba[k]),
            "is_attack": self.classes[k] != "Normal",
            "actual": actual,
            "correct": self.classes[k] == actual,
            "top": [{"label": self.classes[i], "p": float(proba[i])} for i in order[:5]],
        }

    def explain(self, pos, top_n=12):
        x = self._x(pos)
        proba = self.model.predict_proba(x)[0]
        k = int(np.argmax(proba))
        if hasattr(self.model, "estimators_") and hasattr(self.model.estimators_[0], "tree_"):
            base, contrib = self._tree_contrib(np.asarray(x, dtype=np.float32)[0], k)
            method = "Tree-path contributions (Saabas) over the Random Forest"
        else:
            base, contrib = self._perturb_contrib(x, k, proba[k])
            method = "Perturbation (feature set to dataset median)"
        raw = self.ds.df.iloc[pos]
        order = np.argsort(np.abs(contrib))[::-1][:top_n]
        items = [{
            "feature": self.features[i],
            "value": _fmt(raw[self.features[i]]),
            "contribution": float(contrib[i]),
        } for i in order if abs(contrib[i]) > 1e-6]
        label = self.classes[k]
        return {
            "predicted": label,
            "confidence": float(proba[k]),
            "base_value": float(base),
            "method": method,
            "contributions": items,
            "summary": _narrative(label, proba[k], base, items),
        }

    def _tree_contrib(self, xv, k):
        n_feat = len(self.features)
        contrib = np.zeros(n_feat)
        base = 0.0
        trees = self.model.estimators_
        for est in trees:
            t = est.tree_
            val = t.value[:, 0, :]
            val = val / val.sum(axis=1, keepdims=True)
            node = 0
            base += val[0, k]
            while t.children_left[node] != -1:
                f = t.feature[node]
                nxt = t.children_left[node] if xv[f] <= t.threshold[node] else t.children_right[node]
                contrib[f] += val[nxt, k] - val[node, k]
                node = nxt
        return base / len(trees), contrib / len(trees)

    def _perturb_contrib(self, x, k, p):
        X = pd.concat([pd.DataFrame(x, columns=self.features)] * len(self.features), ignore_index=True)
        for i, f in enumerate(self.features):
            X.iat[i, i] = self.medians.get(f, 0.0)
        if not hasattr(self.model, "feature_names_in_"):
            X = X.to_numpy(dtype=np.float32)
        pk = self.model.predict_proba(X)[:, k]
        return p - (p - pk).sum(), p - pk


def _fmt(v):
    try:
        f = float(v)
        return f"{f:g}"
    except (TypeError, ValueError):
        return str(v)[:40]


def _narrative(label, conf, base, items):
    pos = [c for c in items if c["contribution"] > 0][:3]
    neg = [c for c in items if c["contribution"] < 0][:2]
    name = label.replace("_", " ")
    what = "normal traffic" if label == "Normal" else f"{'an' if name[0].upper() in 'AEIOU' else 'a'} {name} attack"
    s = (f"The model classifies this record as {what} with {conf:.1%} confidence "
         f"(starting from a model baseline of {base:.1%} for this class). ")
    if pos:
        s += "The strongest evidence for this is " + ", ".join(
            f"{c['feature']} = {c['value']} (+{c['contribution']:.1%})" for c in pos) + ". "
    if neg:
        s += "Pulling the other way: " + ", ".join(
            f"{c['feature']} = {c['value']} ({c['contribution']:.1%})" for c in neg) + "."
    return s.strip()
