from __future__ import annotations

import argparse
import time
from typing import Final

import requests

_DEFAULT_UA: Final[str] = "ThreatLens-TestTraffic/1.0"
_DEFAULT_BASE: Final[str] = "http://127.0.0.1:5000"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send low-volume normal traffic to the ThreatLens demo Flask app.",
    )
    parser.add_argument(
        "--base-url",
        default=_DEFAULT_BASE,
        help="Demo server base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=5,
        help="How many times to visit each route (default: %(default)s)",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=0.08,
        help="Pause between requests for a calm baseline (default: %(default)s)",
    )
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    session = requests.Session()
    headers = {"User-Agent": _DEFAULT_UA}
    routes = ("/", "/about", "/api/health")

    for round_index in range(args.rounds):
        for path in routes:
            url = f"{base}{path}"
            response = session.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            time.sleep(max(0.0, args.delay_seconds))

    print(
        f"Completed {args.rounds} round(s) over {len(routes)} routes "
        f"({args.rounds * len(routes)} GET requests)."
    )


if __name__ == "__main__":
    main()
