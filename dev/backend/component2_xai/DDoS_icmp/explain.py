"""
Local explanations for one DDoS ICMP flood incident.

* SHAP: TreeExplainer for tree models, KernelExplainer otherwise.
  If the `shap` package is missing, a Monte-Carlo Shapley sampler is used.
* LIME: LimeTabularExplainer. If `lime` is missing, an equivalent
  kernel-weighted local linear surrogate is used.

All contributions are expressed toward the selected attack class
(positive = pushes toward "DDoS ICMP flood").
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .model import ModelAdapter


@dataclass
class Attribution:
    method: str
    values: dict                      # feature -> contribution toward attack class
    base_value: float | None = None   # expected attack probability / output
    conditions: dict = field(default_factory=dict)   # feature -> LIME rule text
    note: str = ""
    error: str | None = None

    def top(self, k: int) -> list[tuple[str, float]]:
        return sorted(self.values.items(), key=lambda kv: -abs(kv[1]))[:k]

    def as_frame(self, k: int | None = None) -> pd.DataFrame:
        items = self.top(k or len(self.values))
        return pd.DataFrame(items, columns=["feature", "contribution"])


def background_sample(X: pd.DataFrame, n: int, random_state: int = 42) -> pd.DataFrame:
    n = int(max(10, min(n, len(X))))
    return X.sample(n=n, random_state=random_state) if len(X) > n else X.copy()


# ------------------------------------------------------------------------- SHAP
def _pick_class(sv, idx: int, n_classes: int) -> np.ndarray:
    if isinstance(sv, list):
        return np.asarray(sv[idx])[0]
    sv = np.asarray(sv)
    if sv.ndim == 3:
        return sv[0, :, idx]
    row = sv[0] if sv.ndim == 2 else sv
    return -row if (n_classes == 2 and idx == 0) else row


def _pick_base(ev, idx: int, n_classes: int) -> float | None:
    if ev is None:
        return None
    ev = np.atleast_1d(np.asarray(ev, dtype=float))
    if ev.size > 1:
        return float(ev[idx])
    return float(-ev[0] if (n_classes == 2 and idx == 0) else ev[0])


def explain_shap(adapter: ModelAdapter, x: pd.DataFrame, background: pd.DataFrame, attack_class,
                 random_state: int = 42) -> Attribution:
    idx, n_cls = adapter.class_index(attack_class), len(adapter.classes)
    names = adapter.feature_names
    try:
        import shap  # noqa: F401
    except Exception:
        return _shapley_sampling(adapter, x, background, attack_class, random_state)

    import shap
    if adapter.is_tree_model:
        try:
            explainer = shap.TreeExplainer(adapter.model)
            sv = explainer.shap_values(adapter._as_model_input(x))
            vals = _pick_class(sv, idx, n_cls)
            return Attribution("SHAP (TreeExplainer)", dict(zip(names, map(float, vals))),
                               _pick_base(explainer.expected_value, idx, n_cls),
                               note="Exact tree SHAP values on the model's probability/margin output.")
        except Exception as exc:  # fall through to Kernel
            tree_err = str(exc)
        else:
            tree_err = None
    else:
        tree_err = None
    try:
        bg = background.values
        if len(bg) > 50:
            bg = shap.kmeans(bg, 25)
        f = lambda Z: adapter.predict_proba(pd.DataFrame(np.asarray(Z), columns=names))[:, idx]  # noqa: E731
        explainer = shap.KernelExplainer(f, bg)
        sv = explainer.shap_values(x.values, nsamples=min(600, 2 * len(names) + 400), silent=True)
        vals = np.asarray(sv).reshape(-1)[: len(names)]
        return Attribution("SHAP (KernelExplainer)", dict(zip(names, map(float, vals))),
                           float(np.atleast_1d(explainer.expected_value)[0]),
                           note="Model-agnostic Kernel SHAP on the attack probability."
                           + (f" TreeExplainer failed: {tree_err}" if tree_err else ""))
    except Exception as exc:
        att = _shapley_sampling(adapter, x, background, attack_class, random_state)
        att.note += f" (shap error: {exc})"
        return att


def _shapley_sampling(adapter: ModelAdapter, x: pd.DataFrame, background: pd.DataFrame, attack_class,
                      random_state: int = 42, n_perm: int = 64) -> Attribution:
    """Monte-Carlo permutation Shapley values (Strumbelj & Kononenko)."""
    rng = np.random.default_rng(random_state)
    idx = adapter.class_index(attack_class)
    names = adapter.feature_names
    F = len(names)
    xv = x.values.reshape(-1).astype(float)
    bg = background.values.astype(float)
    rows, perms = [], []
    for _ in range(n_perm):
        perm = rng.permutation(F)
        z = bg[rng.integers(len(bg))].copy()
        rows.append(z.copy())
        for j in perm:
            z[j] = xv[j]
            rows.append(z.copy())
        perms.append(perm)
    preds = adapter.predict_proba(pd.DataFrame(np.vstack(rows), columns=names))[:, idx]
    phi = np.zeros(F)
    step = F + 1
    for p, perm in enumerate(perms):
        chunk = preds[p * step:(p + 1) * step]
        phi[perm] += np.diff(chunk)
    phi /= n_perm
    base = float(adapter.predict_proba(background)[:, idx].mean())
    return Attribution("Shapley sampling", dict(zip(names, map(float, phi))), base,
                       note="`shap` package not installed - Monte-Carlo Shapley values (64 permutations).")


# ------------------------------------------------------------------------- LIME
def explain_lime(adapter: ModelAdapter, x: pd.DataFrame, background: pd.DataFrame, attack_class,
                 top_k: int = 10, num_samples: int = 2000, random_state: int = 42) -> Attribution:
    idx = adapter.class_index(attack_class)
    names = adapter.feature_names
    try:
        from lime.lime_tabular import LimeTabularExplainer
    except Exception:
        return _local_surrogate(adapter, x, background, attack_class, num_samples, random_state)

    predict = lambda Z: adapter.predict_proba(pd.DataFrame(np.asarray(Z), columns=names))  # noqa: E731
    class_names = [adapter.display_class(c) for c in adapter.classes]
    last_exc = None
    for discretize in (True, False):
        try:
            explainer = LimeTabularExplainer(background.values, feature_names=names, class_names=class_names,
                                             discretize_continuous=discretize, mode="classification",
                                             random_state=random_state)
            exp = explainer.explain_instance(x.values.reshape(-1), predict, num_features=len(names),
                                             labels=(idx,), num_samples=num_samples)
            pairs = exp.as_map()[idx]
            texts = exp.as_list(label=idx)
            values = {names[i]: float(w) for i, w in pairs}
            conds = {names[i]: t for (i, _), (t, _) in zip(pairs, texts)}
            for n in names:
                values.setdefault(n, 0.0)
            return Attribution("LIME", values, float(exp.intercept.get(idx, np.nan)) if hasattr(exp, "intercept") else None,
                               conds, note=f"LimeTabularExplainer, {num_samples} perturbations"
                               + ("" if discretize else ", continuous features (discretizer failed)"))
        except Exception as exc:
            last_exc = exc
    att = _local_surrogate(adapter, x, background, attack_class, num_samples, random_state)
    att.note += f" (lime error: {last_exc})"
    return att


def _local_surrogate(adapter: ModelAdapter, x: pd.DataFrame, background: pd.DataFrame, attack_class,
                     num_samples: int = 2000, random_state: int = 42) -> Attribution:
    """LIME-style surrogate: perturb around x, weight by an RBF kernel, fit weighted ridge on standardised data."""
    from sklearn.linear_model import Ridge

    rng = np.random.default_rng(random_state)
    idx = adapter.class_index(attack_class)
    names = adapter.feature_names
    xv = x.values.reshape(-1).astype(float)
    bg = background.values.astype(float)
    scale = bg.std(axis=0)
    scale[scale == 0] = 1.0
    Z = xv + rng.normal(size=(num_samples, len(names))) * scale
    # integer-like protocol features: sample them from the background instead of adding noise
    for j, n in enumerate(names):
        if n in ("ip_proto", "icmp_type", "icmp_code"):
            Z[:, j] = np.where(rng.random(num_samples) < 0.5, xv[j], bg[rng.integers(len(bg), size=num_samples), j])
    Z[0] = xv
    y = adapter.predict_proba(pd.DataFrame(Z, columns=names))[:, idx]
    Zs = (Z - xv) / scale
    d = np.sqrt((Zs ** 2).sum(axis=1))
    width = 0.75 * np.sqrt(len(names))
    w = np.sqrt(np.exp(-(d ** 2) / width ** 2))
    reg = Ridge(alpha=1.0).fit(Zs, y, sample_weight=w)
    contrib = reg.coef_  # effect of +1 std change; sign = direction toward attack
    conds = {n: f"{n} = {xv[j]:.4g}" for j, n in enumerate(names)}
    return Attribution("Local surrogate (LIME-style)", dict(zip(names, map(float, contrib))),
                       float(reg.intercept_), conds,
                       note="`lime` package not installed - kernel-weighted ridge surrogate around the incident.")


# ------------------------------------------------------------------------- occlusion
def occlusion(adapter: ModelAdapter, x: pd.DataFrame, reference: pd.Series, attack_class) -> dict:
    """Drop in attack probability when each feature is reset to a benign reference value."""
    idx = adapter.class_index(attack_class)
    base = adapter.predict_proba(x)[0, idx]
    rows = []
    for f in adapter.feature_names:
        z = x.copy()
        z[f] = reference.get(f, 0.0)
        rows.append(z)
    p = adapter.predict_proba(pd.concat(rows, ignore_index=True))[:, idx]
    return {f: float(base - pi) for f, pi in zip(adapter.feature_names, p)}
