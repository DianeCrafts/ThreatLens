from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Final

import requests
import yaml

_DEFAULT_UA: Final[str] = "ThreatLens-AttackTraffic/1.0"
_DEFAULT_BASE: Final[str] = "http://127.0.0.1:5000"


def _load_thresholds() -> tuple[int, int]:
    """Return (suspicious_threshold, spike_threshold) from config/settings.yaml."""
    root = Path(__file__).resolve().parent.parent
    cfg_path = root / "config" / "settings.yaml"
    try:
        raw: dict[str, Any] = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        web = raw.get("detection", {}).get("web", {})
        suspicious = int(web["suspicious_ip"]["request_threshold"])
        spike = int(web["traffic_spike"]["min_requests_in_window"])
        return suspicious, spike
    except (OSError, KeyError, TypeError, ValueError):
        return 25, 80


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Send bursty traffic to the demo server to exceed Phase 2 web detection thresholds "
            "(suspicious per-source volume and global traffic spike)."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=_DEFAULT_BASE,
        help="Demo server base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--spike-requests",
        type=int,
        default=0,
        help=(
            "Number of rapid GET requests for a global traffic spike (0 = auto from settings.yaml + 5)."
        ),
    )
    parser.add_argument(
        "--suspicious-requests",
        type=int,
        default=0,
        help=(
            "Number of rapid GET requests for same-source burst (0 = auto from settings.yaml + 5)."
        ),
    )
    parser.add_argument(
        "--path",
        default="/api/health",
        help="Path to request (default: %(default)s)",
    )
    args = parser.parse_args()

    suspicious_cfg, spike_cfg = _load_thresholds()
    spike_n = args.spike_requests if args.spike_requests > 0 else spike_cfg + 5
    suspicious_n = (
        args.suspicious_requests if args.suspicious_requests > 0 else suspicious_cfg + 5
    )

    base = args.base_url.rstrip("/")
    path = args.path if args.path.startswith("/") else f"/{args.path}"
    url = f"{base}{path}"
    session = requests.Session()
    headers = {"User-Agent": _DEFAULT_UA}

    print(
        f"Sending {suspicious_n} rapid requests (per-source suspicious threshold is {suspicious_cfg})..."
    )
    for _ in range(suspicious_n):
        session.get(url, headers=headers, timeout=15)

    time.sleep(0.5)

    print(
        f"Sending {spike_n} rapid requests (traffic spike threshold is {spike_cfg})..."
    )
    for _ in range(spike_n):
        session.get(url, headers=headers, timeout=15)

    total = suspicious_n + spike_n
    print(
        f"Done. Sent {total} HTTP GETs to {url}. "
        "Run the ThreatLens web pipeline against data/live_web.log to evaluate alerts."
    )


if __name__ == "__main__":
    main()
