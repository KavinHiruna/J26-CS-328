# XAI-IDS backend

JSON API for the XAI-IDS dashboard: loads the Edge-IIoT CSV, trains or loads the
Random Forest, and returns incidents, predictions and explanations.

```
dev/
├── backend/
│   ├── common/xai_ids/      <- this package
│   │   ├── server.py        start the API
│   │   ├── api.py           routes (Flask blueprint, /api/...)
│   │   ├── config.py        dataset path, ports, columns, severity, model settings
│   │   ├── data_loader.py   CSV loading, timestamps, incident search, status store
│   │   ├── detector.py      Random Forest training/loading, prediction, explanations
│   │   └── tools/make_sample_data.py
│   └── model/               trained model (rf_edgeiiot.joblib)
├── data/raw/                EdgeIIoT_train_80_with_incident_id.csv
└── frontend/pages/xai_ids/  dashboard page
```

## Run

From the **dev** folder (not from inside this folder):

```powershell
cd D:\4Y1S\research\J26-CS-328\dev
pip install -r backend\common\xai_ids\requirements.txt
python -m backend.common.xai_ids.server
```

Ready when it prints `XAI-IDS backend API running at http://127.0.0.1:5001/api`.
First start trains the model and saves it to `backend\model\rf_edgeiiot.joblib`;
later starts load it. Delete that file to retrain.

## Settings (config.py or environment variables)

| Setting | Default | Env var |
|---|---|---|
| Dataset | `dev\data\raw\EdgeIIoT_train_80_with_incident_id.csv` | `XAI_IDS_DATASET` |
| Model folder | `dev\backend\model` | `XAI_IDS_MODEL_DIR` |
| Port | 5001 | `XAI_IDS_BACKEND_PORT` |
| Allowed browser origins | `*` | `XAI_IDS_CORS_ORIGINS` |

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | is the server up |
| GET | `/api/datasets` | dataset names |
| GET | `/api/meta?dataset=` | classes, counts, time span, model info |
| GET | `/api/incidents?from_date&from_time&to_date&to_time&type&severity&status&page` | time-range search |
| GET | `/api/incidents?incident_id=` | search by ID (exact or partial) |
| GET | `/api/record?type=&n=` | n-th record of a traffic type |
| GET | `/api/analyze?row=` or `?incident_id=` | prediction |
| GET | `/api/explain?row=` or `?incident_id=` | prediction + feature contributions |
| GET | `/api/incident/<id>` | all raw fields |
| POST | `/api/incident/<id>/status` `{"status": "Resolved"}` | change status |

To serve these routes from a bigger backend app instead of this server:
`from backend.common.xai_ids.api import bp; app.register_blueprint(bp)`.
