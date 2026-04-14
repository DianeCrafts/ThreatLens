from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from app.alerts.manager import AlertManager
from app.config import AppSettings
from app.detection.port_scan import PortScanDetector
from app.detection.repeated_connections import RepeatedConnectionsDetector
from app.models.alert import Alert
from app.network.connection_parser import parse_connection_record
from app.network.network_models import NetworkObservation
from app.network.packet_parser import parse_packet_record
from app.network.packet_replay import iter_replay_records
from app.storage.json_writer import JsonWriter


def _parse_record(record: dict[str, Any]) -> NetworkObservation | None:
    parsed = parse_packet_record(record)
    if parsed is not None:
        return parsed
    return parse_connection_record(record)


def _collect_replay_observations(settings: AppSettings) -> tuple[list[NetworkObservation], int]:
    observations: list[NetworkObservation] = []
    malformed = 0
    for record in iter_replay_records(settings.paths.network_packets_replay):
        parsed = _parse_record(record)
        if parsed is not None:
            observations.append(parsed)
        else:
            malformed += 1
    observations.sort(key=lambda obs: obs.timestamp)
    return observations, malformed


def _run_detection(
    settings: AppSettings, observations: list[NetworkObservation]
) -> list[Alert]:
    port_scan = PortScanDetector(settings.detection.network.port_scan)
    repeated = RepeatedConnectionsDetector(settings.detection.network.repeated_connections)
    alerts: list[Alert] = []
    alerts.extend(port_scan.detect(observations))
    alerts.extend(repeated.detect(observations))
    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts


def run_replay(settings: AppSettings) -> None:
    observations, _malformed = _collect_replay_observations(settings)
    alerts = _run_detection(settings, observations)
    manager = AlertManager()
    manager.publish(alerts)
    writer = JsonWriter()
    writer.write_model_sequence(settings.paths.network_events_output, observations)
    writer.write_model_sequence(settings.paths.network_alerts_output, manager.alerts)


def run_live(settings: AppSettings, *, iface: str | None, count: int, duration: int) -> None:
    from app.network.sniffer import live_capture

    timeout = float(duration) if count == 0 else None
    observations = live_capture(iface=iface, count=count, timeout=timeout)
    observations.sort(key=lambda obs: obs.timestamp)
    alerts = _run_detection(settings, observations)
    manager = AlertManager()
    manager.publish(alerts)
    writer = JsonWriter()
    writer.write_model_sequence(settings.paths.network_events_output, observations)
    writer.write_model_sequence(settings.paths.network_alerts_output, manager.alerts)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ThreatLens network monitoring (replay or live).")
    parser.add_argument(
        "--mode",
        choices=("replay", "live"),
        required=True,
        help="replay reads JSON metadata; live uses Scapy (Windows: Npcap + admin).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to settings.yaml (default: <repo>/config/settings.yaml).",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface name for live mode (optional).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Live mode: stop after N packets (0 = use duration instead).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Live mode: capture seconds when --count is 0 (default: 30).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    project_root = Path(__file__).resolve().parent.parent.parent
    config_path = args.config or (project_root / "config" / "settings.yaml")
    settings = AppSettings.from_yaml(config_path)

    if args.mode == "replay":
        run_replay(settings)
        return

    try:
        run_live(
            settings,
            iface=args.iface,
            count=max(0, args.count),
            duration=max(1, args.duration),
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
