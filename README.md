# ThreatLens (Phase 1)

ThreatLens is a small Python toolkit that reads local authentication-style logs, normalizes them into structured events, applies a brute-force detection rule, prints alerts to the console, and writes JSON artifacts for later analysis.

## Requirements

- Windows 10 or later
- [Python 3.12.10](https://www.python.org/downloads/release/python-31210/) (64-bit recommended)
- PowerShell

## Setup (Windows PowerShell)

From the repository root (the folder that contains `app`, `config`, and `data`):

```powershell
py -3.12 --version
```

If `py` is not available, use the Python launcher path shown by the installer, or `python --version` after adding Python to `PATH`.

Create and activate a virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If script execution is restricted, run once (as Administrator if required):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the detector

Ensure your shell is still in the repository root with the virtual environment activated, then:

```powershell
python -m app.main
```

Outputs are written relative to the repository root:

- `outputs/events.json` — normalized events
- `outputs/alerts.json` — generated alerts
- `outputs/summary.json` — run metadata and counters

Log path and detection thresholds are configured in `config/settings.yaml`.

## Run tests

```powershell
pytest
```

## Log format

`data/sample_auth.log` demonstrates the supported pipe-delimited format:

```text
ISO8601_timestamp | source_ip | service | username | STATUS | message
```

`STATUS` must be `FAIL` or `SUCCESS`. Lines beginning with `#` and blank lines are ignored. Malformed lines are skipped without stopping the run.

## License

Provide your own license as needed for your environment.
