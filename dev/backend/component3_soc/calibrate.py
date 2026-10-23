"""
calibrate.py - make the detector's confidence mean what it says.

PROBLEM (measured): Component 1's XGBoost says about 0.99 but is right only 91% of the time (error ECE 0.094),
and the error depends on the class (when it predicts DDoS_HTTP it is right only 51% of the time).

METHOD: one isotonic regression per PREDICTED class maps "raw confidence" -> "chance the prediction is correct"
(Niculescu-Mizil and Caruana, 2005; Guo et al., 2017). With 5-fold cross-fitting every alert is calibrated by a model
that never saw its own label.

LIMIT (say it): the labels come from the test split, because that is where Component 1's predictions exist.
A deployed system should calibrate on held-out validation predictions from Component 1.
"""
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.model_selection import StratifiedKFold

from .config import (ALERTS_FILE, CALIBRATION_FOLDS, CALIBRATION_MIN_CLASS_ROWS, CALIBRATION_REPORT,
                     CALIBRATION_SEED, REPORT_DIR)


def ece(confidence, correct, bins=10):
    """Expected calibration error: average gap between stated confidence and real accuracy, per confidence bin."""
    box = np.minimum((confidence * bins).astype(int), bins - 1)
    return float(sum((box == i).mean() * abs(confidence[box == i].mean() - correct[box == i].mean())
                     for i in range(bins) if (box == i).any()))


def _isotonic(confidence, correct):
    return IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(confidence, correct)


def calibrate(alerts):
    """Return the calibrated confidence (0-1) for every row of `alerts`.
    Needs the columns confidence_raw, predicted_type and true_type."""
    raw = alerts["confidence_raw"].to_numpy(float)
    predicted = alerts["predicted_type"].to_numpy()
    correct = (predicted == alerts["true_type"].to_numpy()).astype(float)
    result = np.zeros(len(alerts))
    folds = StratifiedKFold(CALIBRATION_FOLDS, shuffle=True, random_state=CALIBRATION_SEED)
    for train, test in folds.split(raw, predicted):
        for cls in np.unique(predicted[test]):
            train_c = train[predicted[train] == cls]
            test_c = test[predicted[test] == cls]
            if len(train_c) >= CALIBRATION_MIN_CLASS_ROWS:
                result[test_c] = _isotonic(raw[train_c], correct[train_c]).predict(raw[test_c])
            elif len(train_c):
                result[test_c] = correct[train_c].mean()
            else:
                result[test_c] = raw[test_c]
    return np.round(result, 4)


def main():
    alerts = pd.read_csv(ALERTS_FILE)
    calibrated = calibrate(alerts)
    correct = (alerts["predicted_type"] == alerts["true_type"]).to_numpy(float)
    raw = alerts["confidence_raw"].to_numpy(float)
    text = (f"Overall accuracy of the detector: {correct.mean():.4f}\n"
            f"Raw confidence:        ECE {ece(raw, correct):.4f}  mean {raw.mean():.4f}\n"
            f"Calibrated confidence: ECE {ece(calibrated, correct):.4f}  mean {calibrated.mean():.4f}\n"
            "Good calibration = mean confidence close to accuracy and a small ECE.")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    CALIBRATION_REPORT.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
