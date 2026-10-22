"""
Component 2 - SQLi XAI: file locations + loading (BACKEND)

FILE LOCATION : dev/backend/component2_xai/sqli_xai_config.py

All folder and file paths for the SQL injection XAI dashboard are defined here.
To move a file, change it here only - the frontend page and the evaluation
script both read their paths from this file.

  dev/
  ├── data/                                   <- DATA_DIR    (dataset CSV)
  ├── backend/component2_xai/                 <- BACKEND_DIR (engine, styles, config, evaluation)
  │   └── model/                              <- MODEL_DIR   (trained model + feature list)
  └── frontend/pages/com2_attack/             <- page only
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------- folders
BACKEND_DIR = Path(__file__).resolve().parent              # dev/backend/component2_xai
PROJECT_ROOT = BACKEND_DIR.parents[1]                       # dev
DATA_DIR = PROJECT_ROOT / "data"                            # dev/data
MODEL_DIR = BACKEND_DIR / "model"                           # dev/backend/component2_xai/model
OUTPUT_DIR = PROJECT_ROOT / "outputs" / "component2_xai_eval"  # evaluation results

# ---------------------------------------------------------------- file names
DATASET_FILE = "EdgeIIoT_train_80_with_incident_id.csv"
MODEL_FILE = "sql_injection_rf.pkl"
FEATURES_FILE = "sql_feature_columns.pkl"

# ---------------------------------------------------------------- full paths (first existing one is used)
DATASET_PATHS = [
    DATA_DIR / DATASET_FILE,
    DATA_DIR / "raw" / DATASET_FILE,          # fallback if you keep a raw/ sub-folder
]
MODEL_PATHS = [MODEL_DIR / MODEL_FILE]
FEATURE_PATHS = [MODEL_DIR / FEATURES_FILE]


def first_existing(paths):
    """Return the first path in the list that exists on disk, else None."""
    return next((Path(p) for p in paths if Path(p).is_file()), None)


def load_artifact(source):
    """
    Load a model / feature-list file saved with joblib or pickle.
    `source` can be a path or an uploaded file object. Only load files you trust.
    """
    if source is None:
        return None
    try:
        import joblib
        if hasattr(source, "seek"):
            source.seek(0)
        return joblib.load(source)
    except Exception:
        import pickle
        if hasattr(source, "seek"):
            source.seek(0)
            return pickle.load(source)
        with open(source, "rb") as fh:
            return pickle.load(fh)
