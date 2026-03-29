# HuggingMask Setup Guide

## 1) Installation Check Commands
Run these after installing Git, Python 3.13, and Docker Desktop:

```bash
git --version
python --version
docker --version
docker compose version
```

Team rule: each member shares screenshots of all 4 outputs in Discord/Notion.

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
   Fix: activate `.venv`, run `pip install -r requirements.txt` again, then rerun `pytest -q`.

3. Error: `Bind for 0.0.0.0:8000 failed: port is already allocated`.
   Fix: stop the process/container using port `8000` or change mapping in `compose.yaml`.
