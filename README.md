<<<<<<< HEAD
# J26-CS-328
Explainable AI-Driven IDS and SOC Automation for Industrial IoT Security
=======
# J26-CS-328 - Explainable AI-Driven IDS and SOC Automation for Industrial IoT

One repository, one frontend, four backend components.

| Component | Owner | Backend folder | Frontend page |
|---|---|---|---|
| 1. Detection (IDS) | member 1 | `backend/component1_detection/` | `frontend/pages/1_Detection.py` |
| 2. Explainable AI | member 2 | `backend/component2_xai/` | `frontend/pages/2_Explainability.py` |
| 3. SOC alert prioritisation and response | Hiruna B.H.K | `backend/component3_soc/` | `frontend/pages/3_SOC_Prioritisation.py` |
| 4. Forensics | member 4 | `backend/component4_forensics/` | `frontend/pages/4_Forensics.py` |

## Run
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run frontend/app.py
```

## Rules (short version, details in CONTRIBUTING.md)
1. Work only inside your own `backend/componentN_*/` folder and your own page in `frontend/pages/`.
2. Components talk to each other only through the JSON messages in `docs/interfaces.md`.
3. Never push to `main`. Work on your branch, open a pull request into `develop`.
4. Never commit datasets or trained models larger than 50 MB (see `.gitignore`).
>>>>>>> 521446f (Initial commit)
