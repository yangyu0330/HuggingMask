# HuggingMask

Bootstrap repository for the HuggingMask capstone team.

## Quick Start
1. Create and activate virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Run with Docker: `docker compose up --build`
4. Validate:
   - `http://127.0.0.1:8000/health`
   - `http://127.0.0.1:8000/docs`
5. Run test: `pytest -q`

## Branch Policy
- Work on `feature/*`
- Open PR to `dev`
- Do not push directly to `main`
