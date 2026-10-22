# XAI-IDS frontend

The dashboard page only. All data comes from the backend API in
`backend/common/xai_ids`, so **start the backend first**.

```
xai_ids/
├── app.py               serves the page
├── settings.py          backend URL and port
├── xai_ids_templates/index.html
└── xai_ids_static/      style.css, app.js
```

## Run

Two terminals:

```powershell
# Terminal 1 - backend
cd D:\4Y1S\research\J26-CS-328\dev
python -m backend.common.xai_ids.server

# Terminal 2 - frontend
cd D:\4Y1S\research\J26-CS-328\dev\frontend\pages\xai_ids
python app.py
```

Open http://127.0.0.1:5000. If the backend isn't running yet, the page says so
and keeps retrying every 5 seconds.

If the backend runs on another port or machine, set `BACKEND_URL` in
`settings.py` (or the `XAI_IDS_BACKEND_URL` environment variable).
