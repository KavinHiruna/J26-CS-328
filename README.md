# J26-CS-328 — Explainable AI-Driven IDS and SOC Automation for Industrial IoT

One repository, one frontend, four backend components.

## Component Ownership

| Component | Owner | Backend folder | Frontend page |
|---|---|---|---|
| Component 1. Detection (IDS) | Member 1 | `backend/component1_detection/` | `frontend/pages/1_Detection.py` |
| Component 2. Explainable AI (XAI) | Member 2 | `backend/component2_xai/` | `frontend/pages/2_Explainability.py` |
| Component 3. SOC alert prioritisation and response | Hiruna B.H.K | `backend/component3_soc/` | `frontend/pages/3_SOC_Prioritisation.py` |
| Component 4. Forensics | Member 4 | `backend/component4_forensics/` | `frontend/pages/4_Forensics.py` |

## Architecture

```text
Industrial IoT / Power Plant Data
              |
              v
    Component 1: Detection (IDS)
              |
      Detection + Probability
              |
              v
    Component 2: Explainable AI
              |
    Human-readable explanation
              |
              v
    Component 3: SOC Prioritisation
              |
     Prioritised alerts / response
              |
              v
       Component 4: Forensics
```

The Streamlit frontend provides a unified interface for the four backend components. Components exchange information using the JSON message interfaces documented in `docs/interfaces.md`.

## Project Structure

```text
J26-CS-328/
├── backend/
│   ├── component1_detection/
│   ├── component2_xai/
│   ├── component3_soc/
│   └── component4_forensics/
├── frontend/
│   ├── app.py
│   └── pages/
│       ├── 1_Detection.py
│       ├── 2_Explainability.py
│       ├── 3_SOC_Prioritisation.py
│       └── 4_Forensics.py
├── docs/
│   └── interfaces.md
├── tests/
├── .gitignore
├── CONTRIBUTING.md
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10 or a compatible version supported by the dependencies.
- Git.
- Visual Studio Code or another Python IDE.

## Run the Project

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run frontend/app.py
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run frontend/app.py
```

Open the local URL printed in the terminal by Streamlit.

## Component Responsibilities

### Component 1 — Detection (IDS)

Detect potentially malicious or abnormal activity in Industrial IoT network or process data. The component should provide its detection result and relevant confidence/probability information through the agreed interface.

### Component 2 — Explainable AI (XAI)

Explain IDS predictions using explainability techniques such as SHAP or LIME. The goal is to provide transparent, feature-level and human-readable justifications for intrusion detection decisions in Industrial IoT environments.

### Component 3 — SOC Alert Prioritisation and Response

Prioritise alerts to help analysts decide which incidents should be handled first, and support the agreed response workflow.

### Component 4 — Forensics

Support the investigation of security incidents using available event and evidence data, following the agreed interface and project scope.

## Component Communication

- Follow the JSON message formats documented in `docs/interfaces.md`.
- Do not make undocumented assumptions about another component's inputs or outputs.
- Coordinate interface changes with the other component owners before merging them.

## Git and Branching Rules

1. Work on your own branch.
2. Do not push directly to `main`.
3. Open a pull request into `develop`.
4. Keep commits focused and use clear commit messages.
5. Pull or fetch the latest changes before starting work and before opening a pull request.

## Development Rules

1. Work only inside your assigned `backend/componentN_*/` folder and your own page in `frontend/pages/`.
2. Coordinate changes to shared files with the group before editing them.
3. Keep component logic in the backend and use the frontend page to display and collect user input.
4. Keep configuration and dependencies documented.
5. Add or update tests when changing component behaviour.
6. Do not commit API keys, passwords, tokens, or other secrets.

## Data and Model Files

- Do not commit datasets or trained models larger than **50 MB**.
- Keep local datasets, model artefacts, virtual environments, caches, and secrets out of Git using `.gitignore`.
- Document where data comes from and any steps needed to prepare it.
- Only use datasets in accordance with their licence and permitted use.

## Testing Checklist

Before opening a pull request:

- [ ] Activate the project virtual environment.
- [ ] Install or update required dependencies.
- [ ] Run the Streamlit application.
- [ ] Test the changed component and its frontend page.
- [ ] Check that the component follows `docs/interfaces.md`.
- [ ] Confirm that no secrets, large datasets, or unintended files are included.
- [ ] Review the changes before submitting the pull request.

## Contribution Workflow

1. Create or switch to your working branch.
2. Make changes within your assigned component and page.
3. Run the relevant tests and check the application.
4. Commit and push your branch.
5. Open a pull request targeting `develop`.
6. Address review comments and wait for approval before merging.

## Documentation

| File | Purpose |
|---|---|
| `README.md` | Project overview and setup instructions |
| `CONTRIBUTING.md` | Detailed contribution and collaboration rules |
| `docs/interfaces.md` | JSON contracts between components |
| `.gitignore` | Files and artefacts excluded from Git |

---

**Project ID:** J26-CS-328  
**Project:** Explainable AI-Driven IDS and SOC Automation for Industrial IoT
