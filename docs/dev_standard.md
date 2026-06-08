# HuggingMask Development Standard

## 1) Repository Standard
- Repository name: `HuggingMask`
- Branch rules: `main`, `dev`, `feature/*`
- Module structure: `proxy`, `analyzer`, `whitelist`, `sandbox`
- Shared service port: `8000`
- Python version (single team standard): `3.12`
- Package install method: `venv + pip`
- Run baseline: `docker compose up --build`
- Minimum success criteria:
  - `GET /health` returns `200`
  - `python -m pytest -q` full regression suite passes

Python 3.12 is required because `modelscan` does not support Python 3.13. The Dockerfile uses `python:3.12-slim` for the same reason.

## 2) Team Local Environment Prerequisites
Install:
- Git
- Python 3.12
- Docker Desktop (with Compose)

Each member must submit screenshots of these checks:
- `git --version`
- `python --version`
- `docker --version`
- `docker compose version`

## 3) Python Virtual Environment Policy
Create:
- `python -m venv .venv`

Activate:
- Windows: `.venv\Scripts\activate`
- macOS/Linux: `source .venv/bin/activate`

Upgrade pip:
- `python -m pip install --upgrade pip`

All Python package installs must be done only inside `.venv`.

## 4) Local Run and Validation
Install packages:
- `pip install -r requirements.txt`

Run app:
- `docker compose up --build`

Validation endpoints:
- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/dashboard`

Run test:
- `python -m pytest -q`

Presentation baseline checked on 2026-06-08:
- pytest: `700 passed, 1 skipped`
- Docker image build: passed
- container `/health` and `/docs`: passed
