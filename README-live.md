# ThreatLens Demo Environment (Phase 4)

Phase 4 provides a complete **end-to-end demonstration setup** for ThreatLens on Windows.

It allows you to:
- run a local website
- generate normal and suspicious traffic
- log requests to a file
- run ThreatLens detection pipelines
- visualize results in the dashboard

This phase connects all previous phases into a **real, testable scenario**.

---

## Prerequisites

- Windows 10 or later
- Python 3.12.10
- PowerShell
- Virtual environment activated

---

## Install dependencies

From the repository root:

```powershell
pip install Flask
```


## Demo components
- demo/demo_server.py — local Flask website
- demo/request_logger.py — writes structured logs
- demo/generate_test_traffic.py — normal traffic generator
- demo/generate_attack_traffic.py — suspicious traffic generator
- data/live_web.log — generated request logs

Step-by-step demo flow
1. Start the local website
```powershell
python demo\demo_server.py
```
What happens:

Flask server starts (usually on http://127.0.0.1:5000
)
Incoming requests are logged to data/live_web.log

2. Generate normal traffic
```powershell
python demo\generate_test_traffic.py
```
What happens:

Sends regular requests to the website
Log file is populated with normal activity
No alerts should be triggered
3. Generate suspicious traffic
```
python demo\generate_attack_traffic.py
```
What happens:

Sends repeated / burst traffic
Designed to exceed detection thresholds
Creates suspicious patterns in live_web.log
4. Run ThreatLens detection

Run all pipelines:
```powershell
python -m app.main
python -m app.web.web_runner --log-file data/live_web.log
python -m app.network.network_runner --mode replay
```
What happens:

- Phase 1 → processes authentication logs
- Phase 2 → processes website logs
- Phase 3 → processes network replay data

Outputs written to:

- outputs/events.json
- outputs/alerts.json
- outputs/web_events.json
- outputs/web_alerts.json
- outputs/network_events.json
- outputs/network_alerts.json
5. Launch the dashboard
```powershell
streamlit run dashboard\app.py
```
Expected results in dashboard

After running the full pipeline, you should see:

### Normal traffic
- appears in logs
- does NOT trigger alerts
### Suspicious traffic
- triggers web alerts
- increases alert count
- appears in "Recent Alerts"
### Dashboard visuals
- total alerts
- alert trends over time
- top suspicious IPs
- repeated request patterns
- suspicious website activity
What this phase demonstrates

Phase 4 proves that ThreatLens can:

- observe real application activity
- log that activity
- detect suspicious patterns
- generate alerts
- display results visually

This is a complete end-to-end security monitoring demo.
