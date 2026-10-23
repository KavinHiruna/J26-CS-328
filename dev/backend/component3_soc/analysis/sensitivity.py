"""
sensitivity.py - EVIDENCE that the result does not hinge on one choice. Change one thing, measure what moves.

For every test the script reports, against the chosen setting:
  * rank agreement (Spearman) of the new scores with the chosen scores
  * how many of the top 1,000 alerts stay in the top 1,000
  * the share of alerts whose priority level changes (levels = FIRST CVSS bands on score / 10)
Run (from the dev folder):  python -m backend.component3_soc.analysis.sensitivity
"""
import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from .. import pipeline, scoring
from ..config import LEVEL_CUTOFFS, OUTPUT_DIR, REPORT_DIR, WEIGHTS

KEYS = ["severity", "confidence", "asset", "frequency"]


def levels(score, cutoffs=(90, 70, 40)):
    return np.select([score >= cutoffs[0], score >= cutoffs[1], score >= cutoffs[2]], [3, 2, 1], 0)


def score_with(f, weights):
    """f: DataFrame of the four factors already on 0..1. Vectorised version of scoring.risk_score."""
    return 100 * sum(weights[k] * f[k] for k in KEYS)


def main():
    _, queue = pipeline.run(save=False)
    f = pd.DataFrame({"severity": (queue.attack_severity - 1) / 4, "confidence": queue.detection_confidence,
                      "asset": (queue.asset_criticality - 1) / 4, "frequency": (queue.attack_frequency - 1) / 4})
    base = score_with(f, WEIGHTS)
    assert np.allclose(base, queue.risk_score, atol=0.0051), "vectorised score differs from the pipeline"
    base_level, base_top = levels(base), set(base.nlargest(1000).index)
    rows = []

    def record(name, score, new_levels=None):
        lv = levels(score) if new_levels is None else new_levels
        rows.append({"change": name, "spearman_with_chosen": round(spearmanr(score, base)[0], 3),
                     "top1000_kept_%": round(100 * len(set(score.nlargest(1000).index) & base_top) / 1000, 1),
                     "levels_changed_%": round(100 * float((lv != base_level).mean()), 1)})

    for k in KEYS:                                              # 1. each weight +-20%, the others rescaled to sum to 1
        for factor in (0.8, 1.2):
            w = dict(WEIGHTS)
            w[k] *= factor
            total = sum(w.values())
            record(f"weight of {k} x{factor}", score_with(f, {n: v / total for n, v in w.items()}))
    record("equal weights (25% each)", score_with(f, {k: 0.25 for k in KEYS}))
    w = dict(WEIGHTS); w["frequency"] = 0.0
    total = sum(w.values())
    record("frequency factor removed", score_with(f, {n: v / total for n, v in w.items()}))
    older = f.copy()                                            # 2. earlier assumed asset values: control 5, the others 3
    older["asset"] = (queue.asset_criticality.where(queue.asset_criticality >= 5, 3.0) - 1) / 4
    record("asset values 5/3/3 (earlier assumption) instead of survey 5/4/4", score_with(older, WEIGHTS))
    ranked = f.copy()                                           # 3. a different scaling: percentile rank instead of (x-1)/4
    for k in ("severity", "asset", "frequency"):
        ranked[k] = f[k].rank(pct=True)
    record("percentile-rank scaling instead of (x-1)/4", score_with(ranked, WEIGHTS))
    for name, cut in [("level cut-offs 80/60/40 (no source)", (80, 60, 40)), ("level cut-offs 85/65/40", (85, 65, 40)),
                      ("level cut-offs 95/75/45", (95, 75, 45))]:   # 4. other level boundaries (the order does not change)
        record(name, base, levels(base, cut))
    table = pd.DataFrame(rows)
    text = ("SENSITIVITY: change one choice, compare with the chosen setting\n" + table.to_string(index=False)
            + "\n\nReading: a high Spearman and a high top-1000 share mean the queue order barely moves; "
              "'levels_changed' is the share of alerts that get another label.\n"
              "Level cut-offs never change the order, only the labels.\n"
            "Percentile-rank scaling keeps the order (Spearman about 0.95) but gives a different score range, so its "
            "'levels_changed' mostly reflects the changed scale, not a changed ranking.\n"
            "Equal weights keep the broad order (Spearman about 0.85) but change which alerts are at the very top: "
            "the weights matter most there.")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "sensitivity.txt").write_text(text, encoding="utf-8")
    table.to_csv(OUTPUT_DIR / "sensitivity.csv", index=False)
    print(text)
    return {"ok": True, "table": table}


if __name__ == "__main__":
    main()
