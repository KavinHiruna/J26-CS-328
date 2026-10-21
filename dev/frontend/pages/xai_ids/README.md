# XAI-IDS — Explainable AI for Intrusion Detection

A Python (Flask) dashboard for the Edge-IIoT dataset: search incidents by ID or
time range, step through traffic records, classify them with a Random Forest,
and explain each prediction feature by feature.

## Run

```bash
cd xai_ids
python -m venv .venv
.venv\Scripts\activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

The dataset path is already set in `config.py`:

```
D:\4Y1S\research\J26-CS-328\dev\data\raw\EdgeIIoT_train_80_with_incident_id.csv
```

To use a different file without editing code: `set XAI_IDS_DATASET=C:\path\file.csv`
(PowerShell: `$env:XAI_IDS_DATASET="C:\path\file.csv"`). To add more files to the
sidebar's Dataset dropdown, add entries to `DATASETS` in `config.py`.

**First start** loads the CSV and trains a Random Forest on a stratified sample
(150k rows by default), then saves it to `models/rf_edgeiiot.joblib`. Later starts
load the saved model. Delete that file to retrain. To use your own trained
scikit-learn model, save it at that path either as a bare estimator fitted on a
DataFrame (so it has `feature_names_in_`) or as a dict
`{"model": est, "features": [...], "medians": {...}}`.

## How the dashboard maps to the dataset

| UI field | Source |
|---|---|
| Incident ID | the `incident_id` column (auto-detected; generated if missing) |
| Type | `Attack_type` |
| Source IP | `ip.src_host` |
| Time | `frame.time` if it contains full dates, otherwise synthetic (see below) |
| Severity | mapped from attack type in `SEVERITY_MAP` (`config.py`) |
| Status | **simulated** — the dataset has no workflow status. Normal rows are "Normal"; attacks get a stable Open / Investigating / Resolved from a hash of the ID. Changes made in the incident window are saved to `status_overrides.json`. |

**Timestamps.** Edge-IIoT's `frame.time` often holds only a year and a clock time
(e.g. `2021 11:44:10.08`) with no month or day. When fewer than 90% of rows have a
real date, the app assigns sequential timestamps in file order starting
`SYNTHETIC_START` (default 2026-09-21 08:00:00), one per `SYNTHETIC_INTERVAL_SEC`.
A banner on the page says when this happens. If your 80% split was shuffled, those
times only reflect row order, not capture order.

## Explainability

**Analyze Traffic** classifies the selected record. **Explain Prediction** (and every
**View** window) shows per-feature contributions computed by tree-path decomposition
(the Saabas method): every split a record passes through in each tree raises or lowers
the predicted-class probability, and that change is credited to the split feature.
Baseline + all contributions equals the predicted probability exactly, so the bars
add up. For non-tree models a perturbation fallback is used. If you later install
`shap`, `Detector.explain` in `model.py` is the single place to swap it in.

Note: this file is the **training** split, so predictions on its own rows are
optimistic. Point a second `DATASETS` entry at your 20% test split to evaluate fairly.

## Files

```
app.py            Flask routes / JSON API
config.py         dataset path, column names, severity map, model settings
data_loader.py    CSV loading, timestamps, incident search, status store
model.py          Random Forest training/loading, prediction, explanations
templates/        page layout
static/           CSS + JavaScript
tools/make_sample_data.py   small synthetic Edge-IIoT-style CSV for testing
```
