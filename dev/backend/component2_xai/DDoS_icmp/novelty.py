"""
Component 2 novelty layer for the DDoS ICMP Flood XAI dashboard.

1. Explanation Consensus Score   - how much SHAP and LIME agree for this incident
2. Knowledge-grounded alignment  - do the model's reasons match ICMP flood domain rules?
3. Counterfactual                - minimal changes that turn the incident benign
4. DDoS vs DoS attribution       - distributed or single-source flood?
5. Severity, mitigation and narrative for the analyst
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import (
    DISTRIBUTED_MAX_CONCENTRATION,
    DISTRIBUTED_MIN_SOURCES,
    DOMAIN_RULES,
    SEVERITY_BANDS,
    pretty,
)
from .explain import Attribution
from .model import ModelAdapter


# --------------------------------------------------------------------- 1. consensus
def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    if len(a) < 3:
        return float("nan")
    ra, rb = pd.Series(a).rank().values, pd.Series(b).rank().values
    if ra.std() == 0 or rb.std() == 0:
        return float("nan")
    return float(np.corrcoef(ra, rb)[0, 1])


def explanation_consensus(shap_att: Attribution | None, lime_att: Attribution | None, k: int = 10) -> dict:
    if shap_att is None or lime_att is None:
        return {"available": False, "score": None, "trust": "n/a",
                "reason": "Enable both SHAP and LIME to compute the consensus score."}
    k = max(1, min(k, len(shap_att.values)))
    top_s = [f for f, _ in shap_att.top(k)]
    top_l = [f for f, _ in lime_att.top(k)]
    s_set, l_set = set(top_s), set(top_l)
    inter, union = s_set & l_set, s_set | l_set
    jaccard = len(inter) / len(union) if union else 0.0

    def sgn(v, eps=1e-9):
        return 0 if abs(v) < eps else (1 if v > 0 else -1)

    signs = [sgn(shap_att.values[f]) == sgn(lime_att.values[f]) for f in inter]
    sign_agree = float(np.mean(signs)) if signs else 0.0
    feats = sorted(union)
    rho = _spearman(np.array([abs(shap_att.values.get(f, 0)) for f in feats]),
                    np.array([abs(lime_att.values.get(f, 0)) for f in feats]))
    rho01 = 0.5 if np.isnan(rho) else (rho + 1) / 2
    score = 0.5 * jaccard + 0.3 * sign_agree + 0.2 * rho01
    trust = "High" if score >= 0.7 else "Medium" if score >= 0.45 else "Low"
    table = pd.DataFrame({
        "feature": feats,
        "label": [pretty(f) for f in feats],
        "shap": [shap_att.values.get(f, 0.0) for f in feats],
        "lime": [lime_att.values.get(f, 0.0) for f in feats],
        "in_shap_top": [f in s_set for f in feats],
        "in_lime_top": [f in l_set for f in feats],
    })
    table["direction_agrees"] = np.sign(table["shap"]) == np.sign(table["lime"])
    return {
        "available": True, "score": float(score), "trust": trust, "k": k,
        "jaccard": float(jaccard), "sign_agreement": float(sign_agree),
        "rank_correlation": None if np.isnan(rho) else float(rho),
        "shared_features": sorted(inter, key=lambda f: -abs(shap_att.values[f])),
        "table": table,
    }


# --------------------------------------------------------------------- 2. grounding
def _rule_fires(value, op, ref) -> bool:
    if op == ">=":
        return value >= ref
    if op == "<=":
        return value <= ref
    if op == "==":
        return value == ref
    if op == "in":
        return value in ref
    raise ValueError(op)


def knowledge_alignment(row: pd.Series, attribution: Attribution | None, k: int = 10,
                        is_attack: bool = True) -> dict:
    """
    Attack decision : of the flood indicators that are present, how many does the model use as attack evidence?
    Benign decision : of the flood indicators that are absent, how many does the model use as benign evidence?
    """
    top = {f for f, _ in attribution.top(k)} if attribution else set()
    rows, fired_w, considered_w, aligned_w, total_w = [], 0.0, 0.0, 0.0, 0.0
    for r in DOMAIN_RULES:
        value = float(row.get(r.feature, np.nan))
        fired = bool(_rule_fires(value, r.op, r.value)) if not np.isnan(value) else False
        contrib = attribution.values.get(r.feature) if attribution else None
        supports = contrib is not None and contrib > 0
        if fired and supports:
            status = "Fired - model agrees"
        elif fired:
            status = "Fired - model ignores"
        elif supports and r.feature in top:
            status = "Not fired - model still relies on it"
        else:
            status = "Not fired - model agrees" if not is_attack and contrib is not None else "Not fired"
        total_w += r.weight
        fired_w += r.weight * fired
        if is_attack and fired:
            considered_w += r.weight
            aligned_w += r.weight * supports
        elif not is_attack and not fired:
            considered_w += r.weight
            aligned_w += r.weight * (contrib is not None and contrib <= 0)
        rows.append({"rule": r.rule_id, "indicator": r.text, "feature": r.feature, "label": pretty(r.feature),
                     "value": value, "fired": fired, "contribution": contrib, "in_top_k": r.feature in top,
                     "status": status})
    evidence = fired_w / total_w if total_w else 0.0
    alignment = aligned_w / considered_w if considered_w else 0.0
    if is_attack:
        verdict = ("Model reasons match ICMP flood indicators" if alignment >= 0.7 else
                   "Partly aligned - review the ignored indicators" if alignment >= 0.4 else
                   "Weak alignment - the model may be using spurious cues")
    else:
        verdict = ("Benign decision is backed by the absent flood indicators" if alignment >= 0.7 else
                   "Benign decision partly backed by domain indicators" if alignment >= 0.4 else
                   "Benign decision not explained by domain indicators - review")
    return {"evidence_score": float(evidence), "alignment_score": float(alignment), "verdict": verdict,
            "mode": "attack" if is_attack else "benign", "rules": pd.DataFrame(rows)}


# --------------------------------------------------------------------- 3. counterfactual
def benign_reference(adapter: ModelAdapter, X: pd.DataFrame, attack_class, threshold: float,
                     labels: pd.Series | None = None) -> pd.Series:
    p = adapter.attack_proba(X, attack_class)
    benign = X[p < threshold]
    if len(benign) < 5 and labels is not None:
        benign = X[labels.reindex(X.index).fillna(1).astype(int) == 0]
    if len(benign) < 5:
        benign = X
    return benign.median()


def counterfactual(adapter: ModelAdapter, x: pd.DataFrame, reference: pd.Series, attack_class,
                   threshold: float, attribution: Attribution | None = None, max_changes: int = 6) -> dict:
    idx = adapter.class_index(attack_class)
    p0 = float(adapter.predict_proba(x)[0, idx])
    if p0 < threshold:
        return {"needed": False, "start_prob": p0, "steps": [], "success": True,
                "message": "Incident is already below the decision threshold (classified benign)."}
    cand = [f for f in adapter.feature_names if float(x.iloc[0][f]) != float(reference.get(f, 0.0))]
    if attribution is not None:
        cand.sort(key=lambda f: -attribution.values.get(f, 0.0))
    current, steps, prob = x.copy(), [], p0
    for _ in range(max_changes):
        if not cand:
            break
        trials = []
        for f in cand:
            z = current.copy()
            z[f] = reference.get(f, 0.0)
            trials.append(z)
        probs = adapter.predict_proba(pd.concat(trials, ignore_index=True))[:, idx]
        j = int(np.argmin(probs))
        f = cand.pop(j)
        steps.append({"feature": f, "label": pretty(f), "from": float(current.iloc[0][f]),
                      "to": float(reference.get(f, 0.0)), "prob_after": float(probs[j])})
        current[f] = reference.get(f, 0.0)
        prob = float(probs[j])
        if prob < threshold:
            break
    success = prob < threshold
    msg = (f"Changing {len(steps)} feature(s) flips the decision to benign "
           f"({p0:.2f} -> {prob:.2f})." if success else
           f"No benign flip within {len(steps)} changes ({p0:.2f} -> {prob:.2f}) - the alert is robust.")
    return {"needed": True, "start_prob": p0, "end_prob": prob, "steps": steps, "success": success, "message": msg}


# --------------------------------------------------------------------- 4. DDoS vs DoS
def source_attribution(features: pd.DataFrame, row: pd.Series, top_n: int = 10) -> dict:
    win = features[(features["dst_ip"] == row["dst_ip"]) & (features["window_id"] == row["window_id"])]
    if "capture" in features.columns and "capture" in row:
        win = win[win["capture"] == row["capture"]]
    counts = win["src_ip"].value_counts()
    total = int(counts.sum())
    uniq = int(row.get("unique_src_count", len(counts)))
    conc = float(row.get("src_concentration", counts.iloc[0] / total if total else 1.0))
    distributed = uniq >= DISTRIBUTED_MIN_SOURCES and conc <= DISTRIBUTED_MAX_CONCENTRATION
    p = counts / total if total else counts
    entropy = float(-(p * np.log2(p)).sum()) if total else 0.0
    max_entropy = float(np.log2(len(counts))) if len(counts) > 1 else 1.0
    return {
        "type": "Distributed (DDoS)" if distributed else "Single / few sources (DoS)",
        "distributed": bool(distributed),
        "unique_sources": uniq,
        "concentration": conc,
        "entropy": entropy,
        "normalised_entropy": entropy / max_entropy if max_entropy else 0.0,
        "window_packets": total,
        "top_sources": pd.DataFrame({"src_ip": counts.index[:top_n], "packets": counts.values[:top_n],
                                     "share": (counts.values[:top_n] / total) if total else 0.0}),
    }


# --------------------------------------------------------------------- 5. severity / response
def severity(prob: float, pps: float) -> str:
    for p_min, pps_min, label in SEVERITY_BANDS:
        if prob >= p_min and pps >= pps_min:
            return label
    return "Low"


def mitigation(row: pd.Series, attrib: dict, is_attack: bool) -> list[str]:
    if not is_attack:
        return ["No action needed - keep monitoring the host's ICMP baseline."]
    dst = row.get("dst_ip", "the target")
    steps = [f"Rate-limit ICMP Echo Request toward {dst} at the edge gateway (e.g. <= 10 pkt/s per source)."]
    if attrib.get("distributed"):
        steps += [
            "Traffic is distributed: blocking single IPs will not help - apply aggregate ICMP rate limiting / "
            "upstream scrubbing and enable uRPF / ingress filtering against spoofed sources.",
            "Notify the upstream provider / IIoT gateway owner to drop ICMP floods closer to the source.",
        ]
    else:
        top = attrib.get("top_sources")
        src = top["src_ip"].iloc[0] if isinstance(top, pd.DataFrame) and len(top) else row.get("src_ip")
        steps.append(f"Traffic is concentrated: block or quarantine {src} (ACL / firewall rule) and check that device.")
    steps += [
        "Disable unnecessary ICMP echo responses on constrained IIoT devices; keep ICMP for the management VLAN only.",
        "Keep this incident report and PCAP window as evidence and tune the detector threshold if this was expected traffic.",
    ]
    return steps


def narrative(inc: dict) -> str:
    row = inc["row"]
    lines = [
        f"**{inc['verdict']}** - the model gives a {inc['probability']:.1%} probability of a DDoS ICMP flood "
        f"(threshold {inc['threshold']:.2f}), severity **{inc['severity']}**.",
        f"Target **{row['dst_ip']}** received **{row['pkts_per_sec']:,.0f} pkt/s** "
        f"(~{row['bytes_per_sec'] / 1024:,.1f} KiB/s) from **{int(row['unique_src_count'])} source(s)** in the window; "
        f"the busiest source carried {row['src_concentration']:.0%} of the packets "
        f"-> **{inc['attribution']['type']}**.",
    ]
    prim = inc.get("primary")
    if prim is not None:
        pos = [pretty(f) for f, v in prim.top(5) if v > 0][:3]
        neg = [pretty(f) for f, v in prim.top(10) if v < 0][:2]
        if pos:
            lines.append(f"Main reasons ({prim.method}): {', '.join(pos)} pushed the decision toward attack"
                         + (f"; {', '.join(neg)} pulled it toward benign." if neg else "."))
    ka = inc.get("alignment")
    if ka:
        lines.append(f"Knowledge-grounded alignment {ka['alignment_score']:.0%}: {ka['verdict'].lower()}.")
    cs = inc.get("consensus")
    if cs and cs.get("available"):
        lines.append(f"SHAP/LIME consensus {cs['score']:.0%} -> {cs['trust'].lower()} trust in this explanation.")
    cf = inc.get("counterfactual")
    if cf and cf.get("needed"):
        lines.append(cf["message"])
    return "\n\n".join(lines)
