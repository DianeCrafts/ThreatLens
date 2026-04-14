# ThreatLens Network Monitoring (Phase 3)

Phase 3 adds **replay mode** (read metadata from `data/sample_packets.json`) and **optional live capture** on Windows using **Scapy**. Observations are normalized, analyzed for port scans and repeated connection bursts, written to JSON, and printed to the terminal.

## Requirements

- Windows 10 or later
- Python 3.12.10
- PowerShell

## Install

From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-network.txt
```

## Replay mode (recommended for demos)

Replay does **not** require Npcap or administrator privileges. It reads only structured metadata from JSON (no raw packet payloads).

```powershell
python -m app.network.network_runner --mode replay
```

Outputs:

- `outputs\network_events.json`
- `outputs\network_alerts.json`

Thresholds and paths are configured in `config\settings.yaml` under `paths` and `detection.network`.

## Live mode (Windows notes)

Live capture uses **Scapy**, which on Windows depends on **Npcap** (or WinPcap, deprecated) for packet capture.

1. Install **Npcap** from [https://npcap.com/](https://npcap.com/) (use the installer option compatible with your environment; many setups use “WinPcap API-compatible mode”).
2. Run PowerShell **as Administrator** so the capture driver can be accessed.
3. Optionally install **Wireshark** to verify interfaces; Scapy’s `show_interfaces()` can help pick a name.

Then:

```powershell
python -m app.network.network_runner --mode live --duration 30
```

Options:

- `--duration N` — capture for *N* seconds when `--count` is `0` (default: 30).
- `--count N` — stop after *N* packets (if set, duration is not used as a stop condition).
- `--iface "Ethernet"` — bind to a specific interface name (exact spelling depends on your PC).

If Scapy cannot open the adapter, you will see an error message; use **replay mode** for reliable CI and demos.

## Security and privacy

- Replay JSON is **metadata only** (IPs, ports, protocol, timestamps).
- Live mode builds the same **metadata-only** `NetworkObservation` records; **payloads are not stored** in ThreatLens outputs.

## Tests

```powershell
pytest tests\test_packet_parser.py tests\test_port_scan.py tests\test_repeated_connections.py
```

Or run the full suite:

```powershell
pytest
```
