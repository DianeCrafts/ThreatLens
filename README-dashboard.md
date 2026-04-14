# ThreatLens Dashboard (Phase 2)

This document explains how to install dashboard dependencies, regenerate JSON outputs, and launch the Streamlit UI on Windows with Python 3.12.10.

## Prerequisites

- Windows 10 or later
- Python 3.12.10
- PowerShell

## Install dependencies

From the ThreatLens repository root (the directory that contains `app`, `dashboard`, `config`, and `data`):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dashboard.txt
```

The file `requirements-dashboard.txt` includes the base `requirements.txt` packages plus `streamlit`, `pandas`, and `plotly`.

## Generate JSON outputs

The dashboard reads files under `outputs\`. Generate them with the Phase 1 and Phase 2 pipelines:

```powershell
python -m app.main
python -m app.web.web_runner
```

This writes:

- `outputs\events.json` and `outputs\alerts.json` from authentication logs
- `outputs\web_events.json` and `outputs\web_alerts.json` from website access logs

Paths and detection thresholds are defined in `config\settings.yaml`.

## Launch the Streamlit dashboard

Run Streamlit from the repository root so relative paths resolve correctly:

```powershell
streamlit run dashboard\app.py
```

Streamlit opens a browser tab automatically. If it does not, follow the URL printed in the terminal (typically `http://localhost:8501`).

## Run automated tests (including dashboard loader tests)

```powershell
pytest
```

## Troubleshooting

- If Streamlit reports `No module named 'dashboard'`, ensure you launch the app with `streamlit run dashboard\app.py` from the repository root. The entry script adds the repo root to `sys.path` so the `dashboard` package resolves correctly.
- If imports fail during tests, ensure you are in the repository root and that `pytest.ini` contains `pythonpath = .`.
- If the dashboard shows empty tables, confirm the JSON files exist and are valid arrays. The loader treats missing files, empty files, and invalid JSON as empty datasets without crashing.
- If `streamlit` is not found, confirm the virtual environment is activated and `pip install -r requirements-dashboard.txt` completed successfully.
