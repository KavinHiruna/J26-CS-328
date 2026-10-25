"""
XAI-IDS frontend - serves the dashboard page. All data comes from the backend
API (backend/common/xai_ids), which must be running.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from flask import Flask, render_template

import settings

app = Flask(
    __name__,
    template_folder="xai_ids_templates",
    static_folder="xai_ids_static",
    static_url_path="/static",
)


@app.route("/")
def index():
    return render_template("index.html", api_base=settings.BACKEND_URL,
                           sqli_xai_url=settings.SQLI_XAI_URL, ddos_xai_url=settings.DDOS_XAI_URL,
                           icmp_xai_url=settings.ICMP_XAI_URL)


if __name__ == "__main__":
    print(f"\n  XAI-IDS dashboard at http://{settings.HOST}:{settings.PORT}"
          f"\n  using backend API at {settings.BACKEND_URL}/api\n", flush=True)
    app.run(host=settings.HOST, port=settings.PORT, debug=False)
