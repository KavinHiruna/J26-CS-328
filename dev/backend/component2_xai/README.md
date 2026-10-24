# Component 2 – SQL Injection XAI (backend + frontend)

## Folder layout
```
dev\
├── .streamlit\
│   └── config.toml                     ← blue & white theme for Streamlit widgets
├── data\
│   └── EdgeIIoT_train_80_with_incident_id.csv      ← DATASET
├── backend\component2_xai\             ← BACKEND
│   ├── sqli_xai_config.py              ← all file paths + model loading
│   ├── sqli_xai_engine.py              ← XAI logic (PSS, SHAP, LIME, trust, counterfactual, techniques)
│   ├── sqli_xai_styles.py              ← colours, fonts, CSS
│   ├── evaluate_sqli_xai.py            ← batch evaluation for the thesis
│   ├── README.md
│   └── model\
│       ├── sql_injection_rf.pkl        ← MODEL
│       └── sql_feature_columns.pkl     ← FEATURE LIST
├── frontend\pages\com2_attack\         ← FRONTEND
│   └── sqli_xai_novelty_page.py        ← Streamlit page (layout only)
└── outputs\component2_xai_eval\        ← created by the evaluation script
```

To move any file, change only `sqli_xai_config.py`.

## Install (once)
```powershell
cd D:\4Y1S\research\J26-CS-328\dev
python -m pip install pandas numpy scikit-learn joblib streamlit shap lime
```

## Run the dashboard
```powershell
cd D:\4Y1S\research\J26-CS-328\dev
python -m streamlit run frontend\pages\com2_attack\sqli_xai_novelty_page.py
```

## Run the evaluation
```powershell
cd D:\4Y1S\research\J26-CS-328\dev
python backend\component2_xai\evaluate_sqli_xai.py --n 300 --candidates
```
Results are saved to `dev\outputs\component2_xai_eval\` (`summary.json`, `per_incident_metrics.csv`).

## Novelty (implemented in sqli_xai_engine.py)
1. **Payload-Span Shapley** – exact Shapley values over evidence groups in the real HTTP payload.
2. **Character-level heat map** of the request.
3. **Explanation Trust Score** – rules / PSS / SHAP / LIME agreement + deletion fidelity vs random baseline.
4. **Minimal sanitisation counterfactual.**
5. **SQLi technique profiling** – CWE-89 / CAPEC / ATT&CK T1190 mapping, narrative and priority.

**Important:** the feature builder must match how the model was trained. If it doesn't, pass your own `feature_builder=` to `SQLiXAIEngine`.

## Fixes for the known PSS problems (v2)
Search `FIX P<n>` in `sqli_xai_engine.py`.

| Problem | Fix |
|---|---|
| P1 parameter `=` counted as evidence | `name=` signs go to a fixed "structure" group, never a player; only comparison `=` (1=1) is evidence |
| P2 removal creates unusual requests | PSS re-run with a second removal method (delete vs blank) + out-of-range check; both shown in the trust table |
| P3 results depend on grouping | Groups fixed to `TAXONOMY` (OWASP/CAPEC); evaluation compares with a coarse grouping |
| P4 overlapping groups | Each character belongs to one group (`FAMILY_PRIORITY`) |
| P5 only the payload part explained | Two-player Shapley split: baseline + SQL payload + network/size |
| P6 cost | At most 11 groups (2,048 model calls); `n_players` reported |
| P7 novelty claim | Same deletion test for the groups PSS, SHAP and LIME pick, so they can be compared |

Feature definitions are unchanged, so the model still receives inputs built like its training data.
