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

## Links to the Component-2 attack XAI pages

Incidents the backend tags as SQL injection or DDoS HTTP Flood link to their XAI
page (incident ID, the row button, the incident popup, the top bar and the sidebar).
Each page opens with `?incident=<ID>` selected and has a "← Back to XAI IDS" button.

| Page | Default URL | Override (`settings.py` or env var) | Start it (from `dev/`) |
|---|---|---|---|
| Web Injection XAI | http://localhost:8501 | `SQLI_XAI_URL` | `python -m streamlit run frontend/pages/com2_attack/web_injection.py --server.port 8501` |
| DDoS HTTP Flood XAI | http://localhost:8510 | `DDOS_XAI_URL` | `python -m streamlit run frontend/pages/com2_attack/ddos_http.py --server.port 8510` |

The XAI pages link back to `XAI_IDS_URL` (default http://127.0.0.1:5000).
