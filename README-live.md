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