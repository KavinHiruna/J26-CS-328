# Component 2 – Evidence-Grounded Hybrid XAI for SQL Injection

## Files
| File | Purpose |
|---|---|
| `sqli_xai_engine.py` | Core engine (no UI). Feature builder, Payload-Span Shapley, trust score, counterfactual, technique profile, narrative. |
| `sqli_xai_novelty_page.py` | Streamlit dashboard page that uses the engine. |
| `evaluate_sqli_xai.py` | Batch evaluation → `per_incident_metrics.csv` + `summary.json` for the report. |

Put all three in `dev/frontend/pages/com2_attack/`.

## Install
```powershell
python -m pip install pandas numpy scikit-learn streamlit shap lime
```
SHAP and LIME are optional. Without them the novelty parts (PSS, trust, counterfactual, techniques) still run; trust then uses fewer checks.
The model and feature-column artifacts are loaded with `joblib`; only use trusted artifact files.

## Run the dashboard (from the `dev` folder)
```powershell
python -m streamlit run frontend\pages\com2_attack\sqli_xai_novelty_page.py
```
It looks for:
- `data/raw/EdgeIIoT_train_80_with_incident_id.csv`
- `backend/component2_xai/model/sql_injection_rf.pkl`
- `backend/component2_xai/model/sql_feature_columns.pkl`

You can also upload them in the sidebar.

## Run the evaluation (from the `dev` folder)
```powershell
python frontend\pages\com2_attack\evaluate_sqli_xai.py --data data\raw\EdgeIIoT_train_80_with_incident_id.csv --model backend\component2_xai\model\sql_injection_rf.pkl --features backend\component2_xai\model\sql_feature_columns.pkl --n 300 --candidates --out outputs\component2_xai_eval
```

## What is novel
1. **Payload-Span Shapley (PSS).** Exact Shapley values over groups of real payload evidence: quotes, comments, UNION, time-delay calls and so on. Each group is removed by actually sanitising those characters, re-extracting features and re-scoring the model for every combination. The values sum exactly to P(attack) − P(attack with all payload evidence removed).
2. **Span-grounded heat-map.** Attributions are drawn on the exact characters of the request.
3. **Explanation Trust Score.** It combines:
   - rules ↔ PSS agreement
   - PSS ↔ SHAP agreement
   - PSS ↔ LIME agreement
   - deletion fidelity compared with a random-deletion baseline of the same size
4. **Exact minimal sanitisation counterfactual.** The smallest set of evidence groups whose removal flips the decision. If no set exists, the model is relying on network or size features instead.
5. **Technique profiling.** Detects UNION, boolean-blind, time-blind, error-based, stacked queries, enumeration, comment truncation and obfuscation. Each is mapped to CWE-89 / CAPEC-66 / CAPEC-7 / ATT&CK T1190, with an analyst narrative and a priority.

## Important limitations
- **The feature builder must match the training preprocessing.** `default_feature_builder` follows the 54-feature schema, but if Student 1 / the model author computed features differently, predictions will differ. In that case, pass your own `feature_builder=` to `SQLiXAIEngine`.
- **Evidence groups can overlap.** For example, `select` belongs to both "keywords" and "UNION…SELECT". Shapley handles the interaction, but the split between those two groups is shared.
- **Deletion fidelity uses the same removal operator as PSS.** Always read it against the random baseline.
- **Thresholds are design choices** (trust levels 0.7 / 0.4, technique severities). Justify or tune them in the report.
