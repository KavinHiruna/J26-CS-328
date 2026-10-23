# Com4_src (Component 4 frontend)

Static pages produced by the Component 4 backend (`dev/backend/component4_forensics`).
Open `index.html` in a browser. Each scenario folder has `forensic_report.html`
(single file, charts embedded), `dashboard.html` and the chart PNGs.

To refresh after changing the backend: run `python main.py all` in the backend `src` folder,
then copy `output/<scenario>/*.html` and `*.png` into the matching folder here.
The page-building code (`report_html.py`, `visualize.py`, `theme.py`) stays in the backend
because the pipeline calls it when it writes the report.
