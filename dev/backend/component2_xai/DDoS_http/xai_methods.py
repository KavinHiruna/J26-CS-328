"""
Explanation methods shared by training (global) and the runtime service (local).

FIX M3: three fixed attribution methods for all packets:
  A. SHAP TreeExplainer   — model-internal (exact Shapley values)
  B. LIME                 — local surrogate (different explanation family)
  C. Occlusion            — perturbation-based (in consensus.py)
The surrogate decision tree is a separate global rule check, not an
attribution method counted toward XCS.

Tree-path (Saabas) contributions are kept as a private utility for the
surrogate's path decomposition but are NOT used as a patient-facing
explanation method.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.tree import DecisionTreeClassifier, export_text

try:                                    # optional heavy dependencies
    import shap  # type: ignore
except Exception:                       # pragma: no cover
    shap = None
try:
    from lime.lime_tabular import LimeTabularExplainer  # type: ignore
except Exception:                       # pragma: no cover
    LimeTabularExplainer = None

HAS_SHAP = shap is not None
HAS_LIME = LimeTabularExplainer is not None


# --------------------------------------------------------------------------- #
# SHAP
# --------------------------------------------------------------------------- #
def _positive_class_index(model) -> int:
    return int(np.where(model.classes_ == 1)[0][0])


def shap_values(model, X: pd.DataFrame, explainer=None):
    """Return (values[n, f], base_value) for the attack class using TreeSHAP."""
    if not HAS_SHAP:
        raise ImportError("shap is not installed")
    explainer = explainer or shap.TreeExplainer(model)
    vals = explainer.shap_values(X, check_additivity=False)
    k = _positive_class_index(model)
    if isinstance(vals, list):                      # shap < 0.45
        vals = vals[k]
    elif vals.ndim == 3:                            # shap >= 0.45 -> (n, f, classes)
        vals = vals[:, :, k]
    base = explainer.expected_value
    base = float(np.atleast_1d(base)[k] if np.ndim(base) else base)
    return np.asarray(vals), base


# --------------------------------------------------------------------------- #
# Tree-path (Saabas) contributions — exact decomposition of RF probability
# --------------------------------------------------------------------------- #
def _tree_delta_matrix(tree, n_features: int, k: int):
    t = tree.tree_
    value = t.value[:, 0, :]
    value = value / np.clip(value.sum(axis=1, keepdims=True), 1e-12, None)
    p = value[:, k]
    parent = np.full(t.node_count, -1)
    for node in range(t.node_count):
        for child in (t.children_left[node], t.children_right[node]):
            if child != -1:
                parent[child] = node
    rows, cols, data = [], [], []
    for node in range(1, t.node_count):
        par = parent[node]
        if par >= 0:
            rows.append(node)
            cols.append(t.feature[par])
            data.append(p[node] - p[par])
    delta = sparse.csr_matrix((data, (rows, cols)), shape=(t.node_count, n_features))
    return delta, p[0]


_DELTA_CACHE: dict[int, list] = {}


def _deltas_for(model, n_features: int):
    key = id(model)
    if key not in _DELTA_CACHE:
        k = _positive_class_index(model)
        _DELTA_CACHE[key] = [_tree_delta_matrix(est, n_features, k) for est in model.estimators_]
    return _DELTA_CACHE[key]


def tree_contributions(model, X: pd.DataFrame):
    """Return (contributions[n, f], bias) such that bias + sum(contrib) = P(attack)."""
    Xv = np.asarray(X, dtype=np.float32)
    n_features = Xv.shape[1]
    total = np.zeros(Xv.shape, dtype=float)
    bias = 0.0
    for est, (delta, root) in zip(model.estimators_, _deltas_for(model, n_features)):
        path = est.decision_path(Xv)
        total += np.asarray((path @ delta).todense())
        bias += root
    m = len(model.estimators_)
    return total / m, bias / m


def local_attributions(model, X: pd.DataFrame, shap_explainer=None, use_shap: bool = True):
    """Additive attribution for the attack class.

    FIX M3: SHAP is the only attribution method used for consensus so that
    every packet is scored the same way.  If ``shap`` is not installed the
    function raises immediately — install it with ``pip install shap``.
    """
    if not HAS_SHAP:
        raise ImportError(
            "SHAP is required for the XAI consensus pipeline (FIX M3). "
            "Install it with: pip install shap")
    vals, base = shap_values(model, X, shap_explainer)
    return vals, base, "SHAP (TreeExplainer)"


# --------------------------------------------------------------------------- #
# LIME
# --------------------------------------------------------------------------- #
def lime_explain(model, background: pd.DataFrame, row: pd.Series,
                 categorical_mask: list[bool], class_names: list[str],
                 num_features: int = 10, seed: int = 42):
    """Single LIME run with a fixed random seed (FIX M3)."""
    if not HAS_LIME:
        raise ImportError("lime is not installed")
    feature_names = list(background.columns)
    explainer = LimeTabularExplainer(
        training_data=background.to_numpy(dtype=float),
        feature_names=feature_names,
        class_names=class_names,
        categorical_features=[i for i, c in enumerate(categorical_mask) if c],
        mode="classification",
        discretize_continuous=True,
        random_state=seed,
    )

    def predict_fn(arr):
        return model.predict_proba(pd.DataFrame(arr, columns=feature_names))

    exp = explainer.explain_instance(row.to_numpy(dtype=float), predict_fn,
                                     num_features=num_features, labels=(1,))
    local_pred = float(np.ravel(exp.local_pred)[0]) if getattr(exp, "local_pred", None) is not None else None
    return ([{"rule": rule, "weight": float(w)} for rule, w in exp.as_list(label=1)],
            float(exp.intercept[1]), local_pred)


def lime_stability(model, background: pd.DataFrame, row: pd.Series,
                   categorical_mask: list[bool], class_names: list[str],
                   num_features: int = 10, repeats: int = 3,
                   base_seed: int = 42) -> dict:
    """Run LIME *repeats* times with different seeds; return mean weights and std.

    FIX M3: exposes LIME instability so the analyst can see it.
    """
    all_weights: dict[str, list[float]] = {}
    all_preds: list[float] = []
    for i in range(repeats):
        weights, _intercept, local_pred = lime_explain(
            model, background, row, categorical_mask, class_names,
            num_features=num_features, seed=base_seed + i)
        for w in weights:
            all_weights.setdefault(w["rule"], []).append(w["weight"])
        if local_pred is not None:
            all_preds.append(local_pred)
    summary = []
    for rule, vals in all_weights.items():
        summary.append({"rule": rule,
                        "weight_mean": float(np.mean(vals)),
                        "weight_std": float(np.std(vals)),
                        "runs": len(vals)})
    return {"weights": summary,
            "local_pred_mean": float(np.mean(all_preds)) if all_preds else None,
            "local_pred_std": float(np.std(all_preds)) if all_preds else None,
            "repeats": repeats}


# --------------------------------------------------------------------------- #
# Global surrogate
# --------------------------------------------------------------------------- #
def fit_surrogate(model, X: pd.DataFrame, max_depth: int, seed: int = 42):
    """Fit a shallow tree on the RF's own predictions; report fidelity."""
    y_rf = model.predict(X)
    sur = DecisionTreeClassifier(max_depth=max_depth, random_state=seed)
    sur.fit(X, y_rf)
    fidelity = float((sur.predict(X) == y_rf).mean())
    rules = export_text(sur, feature_names=list(X.columns), decimals=2)
    return sur, fidelity, rules


def describe_split(name: str, thr: float, left: bool, vocab: dict | None = None) -> str:
    """Readable split text; categorical codes are turned back into values."""
    if vocab and name in vocab:
        side = [tok for tok, code in vocab[name].items() if (code <= thr) == left]
        side = ["none" if tok == "0" else tok for tok in side]
        shown = ", ".join(side[:3]) + (" …" if len(side) > 3 else "")
        return f"{name} in {{{shown}}}"
    return f"{name} {'<=' if left else '>'} {thr:.2f}"


def surrogate_rule_list(sur: DecisionTreeClassifier, feature_names: list[str],
                        class_names: list[str], vocab: dict | None = None) -> list[dict]:
    """Flatten the surrogate into IF ... THEN ... rules with support/purity."""
    t = sur.tree_
    out: list[dict] = []

    def walk(node, conds):
        if t.children_left[node] == -1:
            v = t.value[node, 0, :]
            v = v / max(v.sum(), 1e-12)
            cls = int(np.argmax(v))
            out.append({
                "conditions": conds,
                "prediction": class_names[sur.classes_[cls]] if len(sur.classes_) > cls else str(cls),
                "confidence": float(v[cls]),
                "support": int(t.n_node_samples[node]),
            })
            return
        name, thr = feature_names[t.feature[node]], t.threshold[node]
        walk(t.children_left[node], conds + [describe_split(name, thr, True, vocab)])
        walk(t.children_right[node], conds + [describe_split(name, thr, False, vocab)])

    walk(0, [])
    return sorted(out, key=lambda r: -r["support"])
