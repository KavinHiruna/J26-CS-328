# IIoT XAI Prototype

This is the first working prototype for the XAI component.

## Target architecture

IIoT traffic
→ preprocessing
→ Random Forest IDS
→ prediction + probability
→ SHAP
→ LIME
→ explanation engine
→ human-readable explanation
→ dashboard

## Important project boundary

Your research document defines the XAI component as responsible for:
- SHAP integration
- LIME integration
- feature importance ranking
- prediction explanations
- XAI visualizations
- explanation dashboard

The final version should consume Student 1's trained IDS model and the same feature-preprocessing pipeline used by that model.

## Current prototype

Because Student 1's final model is not yet connected, this repository contains:
1. A small synthetic IIoT-style demo dataset.
2. A Random Forest IDS trained on the demo data.
3. SHAP local and global explanations.
4. LIME local explanations.
5. Human-readable explanation generation.
6. A Streamlit dashboard.

The synthetic dataset is only for testing the XAI component. It must not be presented as the final research dataset.

## Run

Create a virtual environment, install dependencies, then run:

```bash
pip install -r requirements.txt
python model_pipeline.py
streamlit run app.py
```

Open the Streamlit URL shown in the terminal.

## Connecting Student 1's IDS

The final integration should replace the demo model with Student 1's exported Random Forest/XGBoost/etc. and preserve:
- exact feature names
- exact feature order
- same preprocessing/encoding
- same class labels

Recommended hand-off:

Student 1 → `model.joblib` + preprocessing object + feature list + class labels

Your XAI layer → prediction, probability, SHAP, LIME, explanation text, visualizations

## Suggested final folders

```text
xai_iiot/
├── app.py
├── xai_engine.py
├── model_pipeline.py
├── requirements.txt
├── data/
│   └── demo_iiot.csv
├── models/
│   └── random_forest_ids.joblib
└── README.md
```
