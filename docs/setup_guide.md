# HuggingMask Setup Guide

## 1) Installation Check Commands
Run these after installing Git, Python 3.12, and Docker Desktop:

```bash
git --version
python --version
docker --version
docker compose version
```

Team rule: each member shares screenshots of all 4 outputs in Discord/Notion.

Use Python `3.12` for both local virtual environments and Docker. `modelscan` does not support Python 3.13, so Python 3.13 images can fail during dependency installation.

## 2) Create and Activate Virtual Environment
Create:

```bash
python -m venv .venv
```

Activate:

Windows (PowerShell):
```powershell
.venv\Scripts\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Upgrade pip:
```bash
python -m pip install --upgrade pip
```

## 3) Install Packages
```bash
pip install -r requirements.txt
```

## 4) Run with Docker
```bash
docker compose up --build
```

The first image build can take several minutes because `torch`, `modelscan`, and `yara-python` are installed. `.dockerignore` excludes Git metadata, local virtual environments, caches, generated files, and large model artifacts from the build context.

## 5) Health Check
After startup, open:
- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`

Expected:
- `/health` returns `200` with `{"status":"ok"}`
- `/docs` loads Swagger UI

## 6) Common Errors and Fixes
1. Error: `open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.`
   Fix: start Docker Desktop, wait until engine is fully running, then retry `docker compose up --build`.

2. Error: `ModuleNotFoundError` or package import errors while testing.
   Fix: activate `.venv`, run `pip install -r requirements.txt` again, then rerun `python -m pytest -q`.

3. Error: `Bind for 0.0.0.0:8000 failed: port is already allocated`.
   Fix: stop the process/container using port `8000` or change mapping in `compose.yaml`.

   Windows check:
   ```powershell
   Get-NetTCPConnection -LocalPort 8000
   ```

4. Error: `No matching distribution found for modelscan`.
   Fix: recreate the environment with Python 3.12 and use the project Dockerfile based on `python:3.12-slim`.

## 7) Current Presentation Baseline
- Date checked: 2026-06-08
- Local pytest: `700 passed, 1 skipped`
- Docker image build: passed
- Container checks: `/health` 200, `/docs` 200
