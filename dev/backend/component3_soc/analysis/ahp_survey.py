"""
ahp_survey.py - EVIDENCE for the factor weights: turn the AHP survey (survey 1) into group weights.

Method (Saaty, 1980; group AHP by aggregating individual judgements, Forman and Peniwati, 1998):
  1. Each respondent's 6 answers become a 4 x 4 pairwise matrix (Severity, Confidence, Asset criticality, Frequency).
     Answer scale: equal = 1, somewhat = 3, much = 5 (and the reciprocals 1/3 and 1/5).
  2. Each respondent's own weights = principal eigenvector; consistency ratio CR = CI / RI with RI = 0.90 for 4 factors.
  3. Group matrix = element-wise GEOMETRIC MEAN of the respondents' matrices.
  4. Group weights = principal eigenvector of the group matrix.  Then compare with config.WEIGHTS.

Run (from the dev folder):  python -m backend.component3_soc.analysis.ahp_survey
Writes docs/results/ahp_survey.txt and outputs/survey_*.csv
"""
import numpy as np
import pandas as pd

from ..config import OUTPUT_DIR, REPORT_DIR, SURVEY1_FILE, WEIGHTS

FACTORS = ["Severity", "Confidence", "Asset criticality", "Frequency"]
KEYS = ["severity", "confidence", "asset", "frequency"]                  # same order, names used in config.WEIGHTS
PAIRS = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]                 # the order of questions 3 to 8 in the form
RI4 = 0.90                                                               # Saaty's random index for a 4 x 4 matrix


def answer_to_value(text, first, second):
    """a_ij for `first` versus `second`, read from the answer text."""
    t = str(text).strip().lower()
    if t.startswith("both"):
        return 1.0
    strength = 5.0 if "much" in t else 3.0 if "somewhat" in t else None
    if strength is None:
        raise ValueError(f"Cannot read answer: {text!r}")
    return strength if t.startswith(first.lower()) else 1 / strength


def weights_and_cr(matrix):
    values, vectors = np.linalg.eig(matrix)
    k = np.argmax(values.real)
    w = np.abs(vectors[:, k].real)
    w = w / w.sum()
    return w, ((values[k].real - 4) / 3) / RI4


def matrix_from_answers(answers):
    m = np.ones((4, 4))
    for (i, j), answer in zip(PAIRS, answers):
        m[i, j] = answer_to_value(answer, FACTORS[i], FACTORS[j])
        m[j, i] = 1 / m[i, j]
    return m


def analyse(df):
    question_columns = [c for c in df.columns if c.strip()[:2] in ("3.", "4.", "5.", "6.", "7.", "8.")]
    assert len(question_columns) == 6, f"expected 6 pairwise questions, found {len(question_columns)}"
    matrices = [matrix_from_answers([row[c] for c in question_columns]) for _, row in df.iterrows()]
    per_person = []
    for i, m in enumerate(matrices):
        w, cr = weights_and_cr(m)
        per_person.append({"respondent": i + 1, "background": df.iloc[i, 1], "experience": df.iloc[i, 2],
                           **{f"w_{k}": round(x, 4) for k, x in zip(KEYS, w)}, "CR": round(cr, 3)})
    group = np.exp(np.mean([np.log(m) for m in matrices], axis=0))        # geometric mean
    w_group, cr_group = weights_and_cr(group)
    return pd.DataFrame(per_person), group, w_group, cr_group


def main():
    df = pd.read_csv(SURVEY1_FILE)
    per_person, group, w_group, cr_group = analyse(df)
    lines = [f"AHP SURVEY: {len(df)} respondents",
             "Backgrounds: " + ", ".join(f"{n} {b}" for b, n in df.iloc[:, 1].value_counts().items()),
             "Experience:  " + ", ".join(f"{n} {b}" for b, n in df.iloc[:, 2].value_counts().items()),
             "", "GROUP MATRIX (geometric mean)",
             pd.DataFrame(group, index=FACTORS, columns=FACTORS).round(3).to_string(),
             "", f"GROUP CONSISTENCY RATIO = {cr_group:.3f}   (acceptable if <= 0.10)",
             f"Respondents individually consistent (CR <= 0.10): {(per_person['CR'] <= 0.10).sum()} of {len(per_person)}",
             "", "GROUP WEIGHTS: survey result against the numbers in config.py"]
    for key, name, w in zip(KEYS, FACTORS, w_group):
        status = "OK" if abs(w - WEIGHTS[key]) <= 0.001 else "DIFFERENT"
        lines.append(f"  {name:<18} survey {w:.4f}   config {WEIGHTS[key]:.4f}   {status}")
    lines += ["", "AGREEMENT BETWEEN RESPONDENTS (min / median / max weight of each factor)",
              per_person[[f"w_{k}" for k in KEYS]].agg(["min", "median", "max"]).round(3).to_string()]
    text = "\n".join(lines)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "ahp_survey.txt").write_text(text, encoding="utf-8")
    per_person.to_csv(OUTPUT_DIR / "survey_per_respondent.csv", index=False)
    print(text)
    return {"ok": all(abs(w - WEIGHTS[k]) <= 0.001 for k, w in zip(KEYS, w_group)) and cr_group <= 0.10}


if __name__ == "__main__":
    main()
