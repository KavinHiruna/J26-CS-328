"""
Start the XAI-IDS backend API.

From the dev folder, either:
    python -m backend.common.xai_ids.server
    python backend\\common\\xai_ids\\server.py
"""
import sys
from pathlib import Path

if __package__ in (None, ""):
    # Run as a script: make "backend.common.xai_ids" importable from the dev folder.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.common.xai_ids import config  # noqa: E402
from backend.common.xai_ids.api import create_app, get_detector  # noqa: E402


def main():
    print(f"[backend] dataset : {config.DATASETS[next(iter(config.DATASETS))]}", flush=True)
    print(f"[backend] model   : {config.MODEL_PATH}", flush=True)
    try:
        get_detector()  # load data + model before serving
    except FileNotFoundError as e:
        print(f"\nERROR: {e}\n", file=sys.stderr)
        sys.exit(1)
    app = create_app()
    print(f"\n  XAI-IDS backend API running at http://{config.HOST}:{config.PORT}/api\n", flush=True)
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
