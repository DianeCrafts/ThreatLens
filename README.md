
# ThreatLens

ThreatLens is a modular **intrusion detection and monitoring system** built in Python.

It detects suspicious activity from:
- authentication logs
- website/server logs
- network connection metadata

and presents results through structured outputs and a visual dashboard.

---

## Features

- Log-based intrusion detection (brute-force login detection)
- Website traffic analysis (request spikes, repeated hits)
- Network monitoring (port scans, connection bursts)
- JSON-based structured outputs
- Interactive dashboard using Streamlit
- Modular, extensible architecture

---

## Project Structure

```
ThreatLens/
├── app/ # Core detection logic
├── dashboard/ # Streamlit dashboard
├── demo/ # Local demo environment (Phase 4)
├── config/ # YAML configuration
├── data/ # Input logs and sample data
├── outputs/ # Generated results
├── tests/ # Unit tests

```



---

## Tech Stack

- Python 3.12.10
- pandas
- Streamlit
- Plotly
- Scapy
- PyYAML
- pytest

---

## Setup (Windows)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dashboard.txt
pip install -r requirements-network.txt
pip install Flask
```
## Run ThreatLens (Core Pipelines)

```powershell
python -m app.main
python -m app.web.web_runner --log-file data/live_web.log
python -m app.network.network_runner --mode replay
```


## Run Dashboard
```powershell
streamlit run dashboard\app.py
```

Dashboard will open at:

http://localhost:8501


## Demo

Start local website:
```powershell
python demo\demo_server.py
```
## Generate traffic:
```powershell
python demo\generate_test_traffic.py
python demo\generate_attack_traffic.py
```
## Run detection:
```powershell
python -m app.web.web_runner --log-file data/live_web.log
```
Then launch dashboard.

## Outputs

ThreatLens generates structured outputs in outputs/:

### Authentication:
- events.json
- alerts.json
### Website:
- web_events.json
- web_alerts.json
### Network:
- network_events.json
- network_alerts.json
## Detection Capabilities
### Authentication
- failed login tracking
- brute-force detection
### Website
- request spikes
- repeated requests from same IP
- suspicious traffic patterns
### Network
- port scan detection
- repeated connection attempts
- burst traffic detection
## Design Principles
- modular architecture
- typed Python models
- config-driven thresholds
- JSON outputs for interoperability
- Windows-first compatibility
## Tests
```powershell
pytest
```
## Future Enhancements
- anomaly detection (machine learning)
- real-time streaming pipeline
- alert integrations (email, webhook)
- multi-host monitoring



