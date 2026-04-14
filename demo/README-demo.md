# ThreatLens local demo (Phase 4)

This demo runs a small **Flask** site on your machine, logs every HTTP request to `data\live_web.log` in the **same pipe-delimited format** that Phase 2’s `WebLogParser` expects, and includes scripts to generate **normal** and **attack** traffic for end-to-end testing.

## Prerequisites

- Windows 10 or later  
- Python 3.12.10  
- PowerShell  
- Repository root: the folder that contains `demo`, `app`, `config`, and `data`

## Install demo dependencies

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-demo.txt
```

## 1. Start the demo website

From the repository root, either:

```powershell
python demo\demo_server.py
```

or:

```powershell
python -m demo.demo_server
```

The entry script adds the repository root to `sys.path` so `import demo` works when you run the file directly. The server listens on `http://127.0.0.1:5000` by default. Leave this window open.

Optional environment variables:

- `THREATLENS_DEMO_HOST` — bind address (default `127.0.0.1`)  
- `THREATLENS_DEMO_PORT` — port (default `5000`)  
- `THREATLENS_DEMO_LOG` — log file path (default `data\live_web.log`)

## 2. Generate normal traffic (second PowerShell window)

Activate the same venv, then:

```powershell
python -m demo.generate_test_traffic
```

This performs a small number of GETs to `/`, `/about`, and `/api/health` with a short delay between requests so the log looks like calm baseline traffic.

## 3. Generate suspicious / spike traffic

With the demo server still running:

```powershell
python -m demo.generate_attack_traffic
```

This sends two rapid bursts. Request counts are chosen from `config\settings.yaml` so they exceed:

- **Suspicious web activity** — more requests than `detection.web.suspicious_ip.request_threshold` from one source IP within the configured time window (localhost appears as `127.0.0.1`).  
- **Traffic spike** — more total requests than `detection.web.traffic_spike.min_requests_in_window` inside the spike window.

## 4. Run ThreatLens on the live log

Point the web pipeline at the demo log, then run the Phase 2 web runner.

1. Edit `config\settings.yaml` and set:

   ```yaml
   web_log_file: data/live_web.log
   ```

   (You can switch this back to `data/sample_web.log` when finished.)

2. Run:

   ```powershell
   python -m app.web.web_runner
   ```

3. Inspect outputs:

   - `outputs\web_events.json`  
   - `outputs\web_alerts.json`  

Alerts should include **suspicious_web_activity** and **traffic_spike** entries when thresholds were exceeded.

## Automated test for logging

```powershell
pytest tests\test_demo_logging.py
```

## Log line format

Each line appended by the demo server looks like:

```text
2026-04-13T12:00:00Z | 127.0.0.1 | GET | /api/health | 200 | User-Agent-String
```

This matches `app.web.web_log_parser.WebLogParser` (IPv4 source, ISO8601 `Z` timestamp, `/path`, integer status).
