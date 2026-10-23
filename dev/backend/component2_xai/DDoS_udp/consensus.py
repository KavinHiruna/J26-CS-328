"""
NOVELTY — Multi-method XAI Consensus (Component 2).

Single XAI methods can disagree about *why* a packet was flagged, and an analyst
has no way of knowing whether a given explanation can be trusted. This module
explains every packet with several independent methods and measures how much
they agree, producing a per-packet **XAI Consensus Score (XCS)** in [0, 1]:

    Methods
      A. SHAP TreeExplainer  (or exact tree-path contributions)  — model internals
      B. LIME                                                     — local linear surrogate
      C. Occlusion (baseline substitution)                        — model-agnostic perturbation
      D. Global surrogate tree path                               — interpretable rule model

    Agreement components
      rank      mean pairwise Spearman correlation of |attributions|
                over the union of each method's top features
      top-k     mean pairwise overlap coefficient of each method's top-k features
      direction share of (feature, method) pairs whose sign matches the
                majority sign, over the consensus top-k features
      verdict   share of rule/surrogate verdicts (surrogate, LIME local model)
                that agree with the Random Forest verdict

    XCS = Σ w_c · component_c        (weights in config.CONSENSUS_WEIGHTS)

    Trust level: High (XCS ≥ 0.75) · Medium (≥ 0.50) · Low (< 0.50 → analyst review)

The consensus ranking (mean of max-normalised |attribution| across methods,
signed by majority vote) is reported as the explanation the analyst should
rely on, together with how many methods support each feature.
"""
from __future__ import annotations

import re
from itertools import combinations

import numpy as np
import pandas as pd

from . import config
from .xai_methods import _positive_class_index, _tree_delta_matrix

METHOD_RF = "rf_attribution"
METHOD_LIME = "lime"
METHOD_OCC = "occlusion"
METHOD_SUR = "surrogate"


# --------------------------------------------------------------------------- #
# Extra attribution methods
# --------------------------------------------------------------------------- #
def occlusion_attributions(model, X: pd.DataFrame, baseline: np.ndarray) -> np.ndarray:
    """p(x) − p(x with feature j set to the typical-normal value), for every j."""
    Xv = X.to_numpy(dtype=float)
    n, f = Xv.shape
    k = _positive_class_index(model)
    p0 = model.predict_proba(X)[:, k]
    big = np.repeat(Xv, f, axis=0)                       # (n*f, f)
    j = np.tile(np.arange(f), n)
    big[np.arange(n * f), j] = baseline[j]
    pj = model.predict_proba(pd.DataFrame(big, columns=X.columns))[:, k].reshape(n, f)
    return p0[:, None] - pj


def surrogate_attributions(surrogate, X: pd.DataFrame):
    """Tree-path contributions of the global surrogate + its verdicts."""
    k = int(np.where(surrogate.classes_ == 1)[0][0]) if 1 in surrogate.classes_ else 0
    delta, _ = _tree_delta_matrix(surrogate, X.shape[1], k)
    vals = np.asarray((surrogate.decision_path(X) @ delta).todense())
    verdict = (surrogate.predict(X) == 1).astype(int)
    return vals, verdict


def lime_to_vector(weights: list[dict], feature_names: list[str]) -> np.ndarray:
    """Map LIME rule strings ("tcp.len > 0.00") back onto feature positions."""
    vec = np.zeros(len(feature_names))
    names = sorted(feature_names, key=len, reverse=True)       # tcp.flags.ack before tcp.flags
    for w in weights:
        for name in names:
            if re.search(rf"(^|\s){re.escape(name)}(\s|=|<|>|$)", w["rule"]):
                vec[feature_names.index(name)] += w["weight"]
                break
    return vec


# --------------------------------------------------------------------------- #
# Agreement metrics
# --------------------------------------------------------------------------- #
def _top(vec: np.ndarray, k: int) -> set[int]:
    order = np.argsort(-np.abs(vec))
    return {int(i) for i in order[:k] if abs(vec[i]) > 1e-12}


def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    if np.ptp(a) == 0 or np.ptp(b) == 0:
        return 0.0
    r = pd.Series(a).rank().corr(pd.Series(b).rank())
    return 0.0 if np.isnan(r) else float(r)


def consensus_for_packet(attrs: dict[str, np.ndarray], rf_verdict: int,
                         other_verdicts: dict[str, int], feature_names: list[str],
                         k: int = config.CONSENSUS_TOP_K) -> dict:
    methods = [m for m, v in attrs.items() if np.abs(v).sum() > 1e-12]
    tops = {m: _top(attrs[m], k) for m in methods}

    # rank agreement over the union of top-2k features
    rank_pairs, overlap_pairs, pair_detail = [], [], {}
    for a, b in combinations(methods, 2):
        union = sorted(_top(attrs[a], 2 * k) | _top(attrs[b], 2 * k))
        rho = _spearman(np.abs(attrs[a][union]), np.abs(attrs[b][union])) if len(union) > 2 else 0.0
        ov = len(tops[a] & tops[b]) / max(1, min(len(tops[a]), len(tops[b])))
        rank_pairs.append(max(rho, 0.0))
        overlap_pairs.append(ov)
        pair_detail[f"{a}|{b}"] = {"spearman": rho, "overlap": ov}
    rank = float(np.mean(rank_pairs)) if rank_pairs else 1.0
    topk = float(np.mean(overlap_pairs)) if overlap_pairs else 1.0

    # consensus ranking: mean of max-normalised attributions
    norm = {m: attrs[m] / (np.abs(attrs[m]).max() or 1.0) for m in methods}
    stack = np.vstack([norm[m] for m in methods]) if methods else np.zeros((1, len(feature_names)))
    importance = np.abs(stack).mean(axis=0)
    direction = np.sign(stack.sum(axis=0))
    order = np.argsort(-importance)
    cons_top = [int(i) for i in order[:k] if importance[i] > 0]

    agree_pairs, total_pairs, ranking = 0, 0, []
    for i in order[: max(k, 10)]:
        if importance[i] <= 0:
            continue
        signs = {m: np.sign(norm[m][i]) for m in methods if abs(norm[m][i]) > 1e-9}
        supporting = [m for m, s in signs.items() if s == direction[i] and s != 0]
        if i in cons_top:
            agree_pairs += len(supporting)
            total_pairs += len(signs)
        ranking.append({
            "feature": feature_names[i],
            "consensus_importance": float(importance[i]),
            "direction": "→ network flood" if direction[i] > 0 else ("→ Normal" if direction[i] < 0 else "neutral"),
            "methods_supporting": len(supporting),
            "methods_total": len(methods),
            **{f"{m}": float(norm[m][i]) for m in methods},
        })
    sign = agree_pairs / total_pairs if total_pairs else 1.0

    verdict = (float(np.mean([v == rf_verdict for v in other_verdicts.values()]))
               if other_verdicts else 1.0)

    comps = {"rank": rank, "topk": topk, "direction": sign, "verdict": verdict}
    w = config.CONSENSUS_WEIGHTS
    score = float(sum(w[c] * comps[c] for c in comps) / sum(w.values()))
    return {
        "score": score,
        "trust": trust_level(score),
        "components": comps,
        "methods": methods,
        "pairs": pair_detail,
        "verdicts": {"Random Forest": rf_verdict, **other_verdicts},
        "ranking": ranking,
    }


def trust_level(score: float) -> str:
    if score >= config.CONSENSUS_HIGH:
        return "High"
    if score >= config.CONSENSUS_MEDIUM:
        return "Medium"
    return "Low"


def recommendation(cons: dict, is_attack: bool) -> str:
    t = cons["trust"]
    if t == "High":
        return ("Explanations agree — the verdict and its reasons are reliable. "
                + ("Safe to act: rate-limit the flooded protocol at the target (SYN cookies for TCP SYN, ICMP/UDP rate limits) or filter upstream; sources are usually spoofed, so blocking them does not help." if is_attack else "No action needed."))
    if t == "Medium":
        return "Explanations partly agree — corroborate with traffic context (packet rate, distinct spoofed sources) before acting."
    return ("Explanations disagree — the model's reasoning is unstable for this packet. "
            "Escalate for analyst review before taking automated action.")
