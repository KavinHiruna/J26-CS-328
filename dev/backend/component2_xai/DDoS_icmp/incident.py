"""
Scoring, incident search and single-incident XAI report for DDoS ICMP Flood.
"""
from __future__ import annotations

import json
import re

import numpy as np
import pandas as pd

from .config import ATTACK_NAME, MODEL_FEATURES, ExplainSettings, pretty
from .explain import Attribution, background_sample, explain_lime, explain_shap
from .model import ModelAdapter
from .novelty import (benign_reference, counterfactual, explanation_consensus, knowledge_alignment,
                      mitigation, narrative, severity, source_attribution)


# ------------------------------------------------------------------ scoring
def score(features: pd.DataFrame, adapter: ModelAdapter, attack_class, threshold: float,
          batch: int = 50_000) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Returns (scored frame, model input matrix X). Same index on both."""
    X = adapter.prepare(features)
    probs = np.concatenate([adapter.attack_proba(X.iloc[i:i + batch], attack_class)
                            for i in range(0, len(X), batch)]) if len(X) else np.array([])
    scored = features.copy()
    scored["prob"] = probs
    scored["is_attack"] = scored["prob"] >= threshold
    scored["verdict"] = np.where(scored["is_attack"], ATTACK_NAME, "Benign")
    scored["severity"] = [severity(p, pps) if a else "None"
                          for p, pps, a in zip(scored["prob"], scored["pkts_per_sec"], scored["is_attack"])]
    return scored, X


# ------------------------------------------------------------------ search
_CMP_RE = re.compile(r"^(prob|pps|bps|srcs|conc|len|delta|row)\s*(>=|<=|>|<|=)\s*([0-9.eE+-]+)$", re.I)
_CMP_COL = {"prob": "prob", "pps": "pkts_per_sec", "bps": "bytes_per_sec", "srcs": "unique_src_count",
            "conc": "src_concentration", "len": "frame_len", "delta": "frame_time_delta", "row": "row_id"}
SEARCH_HELP = (
    "Free text matches IP / label / verdict / severity / row id. Filters: `src:IP` `dst:IP` `ip:IP` `row:123` "
    "`type:DDoS_ICMP` `pred:attack|benign` `sev:critical` and comparisons `prob>0.9` `pps>=500` `srcs>=3` "
    "`conc<=0.5` `bps>10000`. All terms are combined with AND."
)


def search_incidents(scored: pd.DataFrame, query: str) -> pd.DataFrame:
    if not query or not query.strip():
        return scored
    mask = pd.Series(True, index=scored.index)
    text_cols = [c for c in ("src_ip", "dst_ip", "attack_type", "verdict", "severity") if c in scored.columns]
    for tok in query.strip().split():
        m = _CMP_RE.match(tok)
        if m:
            col = _CMP_COL[m.group(1).lower()]
            op, val = m.group(2), float(m.group(3))
            s = scored[col].astype(float)
            mask &= {">": s > val, "<": s < val, ">=": s >= val, "<=": s <= val, "=": s == val}[op]
            continue
        if ":" in tok:
            key, val = tok.split(":", 1)
            key, v = key.lower(), val.lower()
            if key == "src":
                mask &= scored["src_ip"].str.lower().str.contains(v, regex=False)
            elif key == "dst":
                mask &= scored["dst_ip"].str.lower().str.contains(v, regex=False)
            elif key == "ip":
                mask &= scored["src_ip"].str.lower().str.contains(v, regex=False) | \
                        scored["dst_ip"].str.lower().str.contains(v, regex=False)
            elif key in ("row", "id"):
                mask &= scored["row_id"].astype(str) == v
            elif key == "type" and "attack_type" in scored:
                mask &= scored["attack_type"].astype(str).str.lower().str.contains(v, regex=False)
            elif key == "pred":
                mask &= scored["is_attack"] if v.startswith(("att", "ddos", "icmp", "1", "mal")) else ~scored["is_attack"]
            elif key in ("sev", "severity"):
                mask &= scored["severity"].str.lower() == v
            else:
                mask &= False
            continue
        v = tok.lower()
        hit = scored["row_id"].astype(str) == v
        for c in text_cols:
            hit |= scored[c].astype(str).str.lower().str.contains(v, regex=False)
        mask &= hit
    return scored[mask]


def incident_options(scored: pd.DataFrame, limit: int = 500) -> pd.DataFrame:
    """Rank candidates: attacks first (by probability, then packet rate), one per target window."""
    if scored.empty:
        return scored
    ranked = scored.sort_values(["is_attack", "prob", "pkts_per_sec"], ascending=[False, False, False])
    keys = ["dst_ip", "window_id"] + (["capture"] if "capture" in ranked else [])
    return ranked.drop_duplicates(keys).head(limit)


# ------------------------------------------------------------------ timeline
def timeline(scored: pd.DataFrame, row: pd.Series, span: int = 30) -> pd.DataFrame:
    sub = scored[scored["dst_ip"] == row["dst_ip"]]
    if "capture" in scored.columns:
        sub = sub[sub["capture"] == row["capture"]]
    w = int(row["window_id"])
    sub = sub[(sub["window_id"] >= w - span) & (sub["window_id"] <= w + span)]
    g = sub.groupby("window_id").agg(
        pkts_per_sec=("pkts_per_sec", "max"), bytes_per_sec=("bytes_per_sec", "max"),
        unique_src_count=("unique_src_count", "max"), attack_prob=("prob", "mean"),
        icmp_share=("ip_proto", lambda s: float((s == 1).mean())),
    ).reset_index()
    g["seconds_from_incident"] = g["window_id"] - w
    return g


# ------------------------------------------------------------------ the incident
def benign_reference_from_scores(scored: pd.DataFrame, X: pd.DataFrame, threshold: float) -> pd.Series:
    """Median feature values of traffic the model considers benign (falls back to labelled normal rows)."""
    benign = X[scored["prob"] < threshold]
    if len(benign) < 5 and "target" in scored:
        benign = X[scored["target"] == 0]
    return (benign if len(benign) >= 5 else X).median()


def build_incident(scored: pd.DataFrame, X: pd.DataFrame, adapter: ModelAdapter, row_id: int, attack_class,
                   settings: ExplainSettings, background: pd.DataFrame | None = None,
                   reference: pd.Series | None = None) -> dict:
    pos = scored.index[scored["row_id"] == row_id]
    if len(pos) == 0:
        raise KeyError(f"row_id {row_id} not found")
    i = pos[0]
    row = scored.loc[i]
    x = X.loc[[i]]
    if background is None:
        background = background_sample(X, settings.background_rows, settings.random_state)
    if reference is None:
        reference = benign_reference_from_scores(scored, X, settings.threshold)

    prob = float(row["prob"])
    is_attack = prob >= settings.threshold
    shap_att = lime_att = None
    errors = []
    if settings.compute_shap:
        try:
            shap_att = explain_shap(adapter, x, background, attack_class, settings.random_state)
        except Exception as exc:
            errors.append(f"SHAP failed: {exc}")
    if settings.compute_lime:
        try:
            lime_att = explain_lime(adapter, x, background, attack_class, settings.top_k,
                                    settings.lime_samples, settings.random_state)
        except Exception as exc:
            errors.append(f"LIME failed: {exc}")
    primary: Attribution | None = shap_att or lime_att

    attrib = source_attribution(scored, row)
    inc = {
        "row_id": int(row_id),
        "row": row,
        "x": x,
        "probability": prob,
        "threshold": settings.threshold,
        "is_attack": bool(is_attack),
        "verdict": f"{ATTACK_NAME} detected" if is_attack else "Benign traffic",
        "severity": severity(prob, float(row["pkts_per_sec"])) if is_attack else "None",
        "attack_class": adapter.display_class(attack_class),
        "true_label": row.get("attack_type") if "attack_type" in row else None,
        "shap": shap_att,
        "lime": lime_att,
        "primary": primary,
        "consensus": explanation_consensus(shap_att, lime_att, settings.top_k),
        "alignment": knowledge_alignment(row, primary, settings.top_k, is_attack) if primary else None,
        "counterfactual": counterfactual(adapter, x, reference, attack_class, settings.threshold, primary),
        "attribution": attrib,
        "mitigation": mitigation(row, attrib, is_attack),
        "reference": reference,
        "errors": errors,
        "timeline": timeline(scored, row),
    }
    inc["narrative"] = narrative(inc)
    return inc


# ------------------------------------------------------------------ export
def _jsonable(v):
    if isinstance(v, (np.floating, np.integer)):
        return v.item()
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, pd.DataFrame):
        return v.to_dict(orient="records")
    if isinstance(v, pd.Series):
        return {k: _jsonable(x) for k, x in v.to_dict().items()}
    if isinstance(v, Attribution):
        return {"method": v.method, "base_value": v.base_value, "values": v.values,
                "conditions": v.conditions, "note": v.note}
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, float) and np.isnan(v):
        return None
    return v


def incident_to_json(inc: dict) -> str:
    keep = {k: v for k, v in inc.items() if k not in ("x", "reference", "primary")}
    keep["features"] = {f: float(inc["row"][f]) for f in MODEL_FEATURES if f in inc["row"]}
    keep["row"] = {k: inc["row"][k] for k in ("row_id", "src_ip", "dst_ip", "timestamp", "window_id")}
    return json.dumps(_jsonable(keep), indent=2, default=str)


def incident_to_markdown(inc: dict) -> str:
    r = inc["row"]
    md = [f"# {ATTACK_NAME} - incident #{inc['row_id']}", "",
          f"- Verdict: **{inc['verdict']}** (p = {inc['probability']:.3f}, threshold {inc['threshold']:.2f})",
          f"- Severity: **{inc['severity']}**",
          f"- Source -> Target: `{r['src_ip']}` -> `{r['dst_ip']}`",
          f"- Attribution: {inc['attribution']['type']} ({inc['attribution']['unique_sources']} sources, "
          f"top share {inc['attribution']['concentration']:.0%})", "", "## Narrative", "", inc["narrative"], "",
          "## Feature values", "", "| Parameter | Value |", "|---|---|"]
    md += [f"| {pretty(f)} | {float(r[f]):.4g} |" for f in MODEL_FEATURES]
    if inc["primary"] is not None:
        md += ["", f"## Top reasons ({inc['primary'].method})", "", "| Parameter | Contribution |", "|---|---|"]
        md += [f"| {pretty(f)} | {v:+.4f} |" for f, v in inc["primary"].top(10)]
    cs = inc["consensus"]
    if cs.get("available"):
        md += ["", "## Explanation consensus", "",
               f"Score {cs['score']:.2f} ({cs['trust']} trust) - top-{cs['k']} overlap {cs['jaccard']:.0%}, "
               f"direction agreement {cs['sign_agreement']:.0%}."]
    if inc["alignment"]:
        md += ["", "## Knowledge-grounded alignment", "",
               f"Alignment {inc['alignment']['alignment_score']:.0%}, evidence {inc['alignment']['evidence_score']:.0%}."]
        for _, rr in inc["alignment"]["rules"].iterrows():
            md.append(f"- {rr['rule']} {rr['indicator']}: {rr['status']}")
    md += ["", "## Recommended response", ""] + [f"1. {s}" for s in inc["mitigation"]]
    return "\n".join(md)
