from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from flask import Flask, Response, jsonify, request

from demo.request_logger import DemoRequestLogger
_DEFAULT_LOG = _REPO_ROOT / "data" / "live_web.log"
_LOG_PATH = Path(os.environ.get("THREATLENS_DEMO_LOG", str(_DEFAULT_LOG)))

_logger = DemoRequestLogger(_LOG_PATH)

app = Flask(__name__)


@app.after_request
def _log_request(response: Response) -> Response:
    _logger.log_request(
        method=request.method,
        path=request.path or "/",
        status_code=response.status_code,
        remote_addr=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "-"),
    )
    return response


@app.route("/")
def home() -> str:
    return "<h1>ThreatLens Demo</h1><p>Home</p>"


@app.route("/about")
def about() -> str:
    return "<h1>About</h1><p>Demo page</p>"


@app.route("/api/health")
def health() -> tuple[Response, int]:
    return jsonify({"status": "ok"}), 200


@app.route("/api/echo", methods=["POST"])
def echo() -> tuple[Response, int]:
    return jsonify({"received": True}), 200


def main() -> None:
    host = os.environ.get("THREATLENS_DEMO_HOST", "127.0.0.1")
    port = int(os.environ.get("THREATLENS_DEMO_PORT", "5000"))
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
