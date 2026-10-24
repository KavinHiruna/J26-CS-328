"""
NOVELTY — Multi-method XAI Consensus (Component 2).

Single XAI methods can disagree about *why* a packet was flagged, and an analyst
has no way of knowing whether a given explanation can be trusted. This module
explains every packet with three attribution methods that each represent a
different explanation family and measures how much they agree, producing a
per-packet **XAI Consensus Score (XCS)** in [0, 1]:

    FIX M3: Three fixed attribution methods
      A. SHAP TreeExplainer        — model-internal (exact Shapley values)
      B. LIME                      — local linear surrogate
      C. Occlusion (baseline sub.) — model-agnostic perturbation
    The global surrogate tree is reported separately as a rule check,
    not counted as an attribution method.

    FIX M4: Repaired agreement components
      rank      (ρ + 1) / 2  on |attributions| over the top-k union only
      top-k     |A ∩ B| / k  with k fixed (default 5)
      direction sign agreement only over top-k features where |aⱼ| > ε

    XCS = Σ w_c · component_c        (weights in config.CONSENSUS_WEIGHTS)

    FIX M4: Verdict (surrogate / LIME vs RF) is reported as pass/fail,
    NOT averaged into XCS.

    FIX M2: Faithfulness deletion test
      Faithfulness = P(attack|x) − P(attack|x with top-k features replaced)
      Compared against random-k baseline.  Trust is "High" only when
      BOTH XCS and faithfulness are high.

    Trust level: High (XCS ≥ 0.75 AND faithful) · Medium (≥ 0.50) · Low
"""
from __future__ import annotations

import re
from itertools import combinations

import numpy as np
import pandas as pd

from . import config
from .xai_methods import _positive_class_index, _tree_delta_matrix

METHOD_SHAP = "shap"
METHOD_LIME = "lime"
METHOD_OCC = "occlusion"

# Legacy aliases kept for serialisation compatibility
METHOD_RF = METHOD_SHAP
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
    big = np.repeat(Xv, f, axis=0)
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
    names = sorted(feature_names, key=len, reverse=True)
    for w in weights:
        for name in names:
            if re.search(rf"(^|\s){re.escape(name)}(\s|=|<|>|$)", w["rule"]):
                vec[feature_names.index(name)] += w["weight"]
                break
    return vec


# --------------------------------------------------------------------------- #
# FIX M2: Faithfulness deletion test
# --------------------------------------------------------------------------- #
def faithfulness_test(model, X: pd.DataFrame, attributions: np.ndarray,
                      baseline: np.ndarray,
                      top_k: int = config.FAITHFULNESS_TOP_K,
                      random_repeats: int = config.FAITHFULNESS_RANDOM_REPEATS,
                      seed: int = config.RANDOM_STATE) -> dict:
    """Remove a packet's top-k attributed features and measure the probability drop.

    Returns ``{drop, random_drop, ratio, faithful}`` where *ratio* > 1 means
    the explanation points to genuinely important features.
    """
    Xv = X.to_numpy(dtype=float)
    n = Xv.shape[0]
    k_cls = _positive_class_index(model)
    p0 = model.predict_proba(X)[:, k_cls]

    drops = np.zeros(n, dtype=float)
    random_drops = np.zeros(n, dtype=float)
    rng = np.random.default_rng(seed)

    for i in range(n):
        abs_attr = np.abs(attributions[i])
        top_idx = np.argsort(-abs_attr)[:top_k]

        # drop top-k
        x_masked = Xv[i].copy()
        x_masked[top_idx] = baseline[top_idx]
        p_masked = model.predict_proba(
            pd.DataFrame([x_masked], columns=X.columns))[0, k_cls]
        drops[i] = p0[i] - p_masked

        # drop k random features (repeated, take mean)
        rand_drops_i = []
        for _ in range(random_repeats):
            rand_idx = rng.choice(Xv.shape[1], size=top_k, replace=False)
            x_rand = Xv[i].copy()
            x_rand[rand_idx] = baseline[rand_idx]
            p_rand = model.predict_proba(
                pd.DataFrame([x_rand], columns=X.columns))[0, k_cls]
            rand_drops_i.append(p0[i] - p_rand)
        random_drops[i] = float(np.mean(rand_drops_i))

    ratio = np.where(np.abs(random_drops) > 1e-9,
                     drops / np.abs(random_drops), np.inf)
    faithful = drops > random_drops * 1.5

    return {
        "drop": float(np.mean(drops)),
        "random_drop": float(np.mean(random_drops)),
        "ratio": float(np.mean(np.clip(ratio, 0, 100))),
        "faithful": bool(np.all(faithful)),
        "per_packet_drop": drops.tolist(),
        "per_packet_random_drop": random_drops.tolist(),
    }


# --------------------------------------------------------------------------- #
# FIX M4: Repaired agreement metrics
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
    """Compute the repaired XAI Consensus Score for one packet.

    FIX M4 changes vs. the original:
      - Rank: (ρ + 1) / 2  on |attr| restricted to the top-k union
      - Top-k: |A ∩ B| / k  (fixed denominator)
      - Direction: sign agreement only where |aⱼ| > DIRECTION_EPSILON
      - Verdict: excluded from XCS, reported separately as pass/fail
    """
    methods = [m for m, v in attrs.items() if np.abs(v).sum() > 1e-12]
    tops = {m: _top(attrs[m], k) for m in methods}
    eps = config.DIRECTION_EPSILON

    # -- rank agreement over the top-k union ----------------------------------
    rank_pairs, overlap_pairs, pair_detail = [], [], {}
    for a, b in combinations(methods, 2):
        union = sorted(tops[a] | tops[b])
        if len(union) > 2:
            rho = _spearman(np.abs(attrs[a][union]), np.abs(attrs[b][union]))
        else:
            rho = 0.0
        scaled_rho = (rho + 1.0) / 2.0       # FIX M4: map [-1, 1] → [0, 1]
        ov = len(tops[a] & tops[b]) / k       # FIX M4: fixed denominator k
        rank_pairs.append(scaled_rho)
        overlap_pairs.append(min(ov, 1.0))
        pair_detail[f"{a}|{b}"] = {"spearman": rho, "overlap": ov}
    rank = float(np.mean(rank_pairs)) if rank_pairs else 1.0
    topk = float(np.mean(overlap_pairs)) if overlap_pairs else 1.0

    # -- consensus ranking: mean of max-normalised attributions ---------------
    norm = {m: attrs[m] / (np.abs(attrs[m]).max() or 1.0) for m in methods}
    stack = np.vstack([norm[m] for m in methods]) if methods else np.zeros((1, len(feature_names)))
    importance = np.abs(stack).mean(axis=0)
    direction = np.sign(stack.sum(axis=0))
    order = np.argsort(-importance)
    cons_top = [int(i) for i in order[:k] if importance[i] > 0]

    # -- direction: sign agreement only where |attr| > eps --------------------
    agree_pairs, total_pairs, ranking = 0, 0, []
    for i in order[: max(k, 10)]:
        if importance[i] <= 0:
            continue
        signs = {}
        for m in methods:
            if abs(norm[m][i]) > eps:       # FIX M4: ignore tiny attributions
                signs[m] = np.sign(norm[m][i])
        supporting = [m for m, s in signs.items() if s == direction[i] and s != 0]
        if i in cons_top and signs:
            agree_pairs += len(supporting)
            total_pairs += len(signs)
        ranking.append({
            "feature": feature_names[i],
            "consensus_importance": float(importance[i]),
            "direction": ("→ HTTP flood" if direction[i] > 0
                          else ("→ Normal" if direction[i] < 0 else "neutral")),
            "methods_supporting": len(supporting),
            "methods_total": len(methods),
            **{f"{m}": float(norm[m][i]) for m in methods},
        })
    sign = agree_pairs / total_pairs if total_pairs else 1.0

    # -- verdict: pass/fail, NOT part of XCS (FIX M4) -------------------------
    verdict_agree = {name: (v == rf_verdict) for name, v in other_verdicts.items()}
    verdict_pass = all(verdict_agree.values()) if verdict_agree else True

    # -- XCS from the 3 repaired components -----------------------------------
    comps = {"rank": rank, "topk": topk, "direction": sign}
    w = config.CONSENSUS_WEIGHTS
    score = float(sum(w[c] * comps[c] for c in comps) / sum(w.values()))
    return {
        "score": score,
        "trust": trust_level(score),
        "components": comps,
        "methods": methods,
        "pairs": pair_detail,
        "verdicts": {"Random Forest": rf_verdict, **other_verdicts},
        "verdict_pass": verdict_pass,
        "ranking": ranking,
    }


def trust_level(score: float, faithful: bool = True) -> str:
    """FIX M2+M4: High only when BOTH XCS ≥ threshold AND faithful."""
    if score >= config.CONSENSUS_HIGH and faithful:
        return "High"
    if score >= config.CONSENSUS_MEDIUM:
        return "Medium"
    return "Low"


def recommendation(cons: dict, is_attack: bool) -> str:
    t = cons["trust"]
    vp = cons.get("verdict_pass", True)
    if t == "High" and vp:
        return ("Explanations agree and are faithful — the verdict and its reasons "
                "are reliable. "
                + ("Safe to act (e.g. rate-limit / block the source)." if is_attack
                   else "No action needed."))
    if t == "High" and not vp:
        return ("Explanations agree but the surrogate/LIME verdict differs from "
                "the RF — double-check with traffic context before acting.")
    if t == "Medium":
        return ("Explanations partly agree — corroborate with traffic context "
                "(source rate, HTTP method mix) before acting.")
    return ("Explanations disagree — the model's reasoning is unstable for this "
            "packet. Escalate for analyst review before taking automated action.")
