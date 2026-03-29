# HuggingMask

AI privacy/security capstone project baseline with a FastAPI proxy bootstrap.

## Folder Structure
```text
HuggingMask/
├─ .github/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  └─ CODEOWNERS
├─ proxy/
│  └─ app/
├─ analyzer/
├─ whitelist/
├─ sandbox/
├─ tests/
├─ docs/
├─ evidence/
│  ├─ week01 ~ week10
│  ├─ meetings/
│  ├─ tests/
│  ├─ demo/
│  ├─ perf/
│  └─ budget/
├─ requirements.txt
├─ Dockerfile
├─ compose.yaml
└─ .gitignore
```

## Run Command
```bash
docker compose up --build
```

## Branch Rules
- Base branches: `main`, `dev`
- Work branch: `feature/*`
- PR flow: `feature/*` -> `dev`
- `main` direct push/merge is not allowed

## Test Command
```bash
pytest -q
```

## Module Responsibility
- `proxy`: Request/response gateway, FastAPI entrypoint
- `analyzer`: Prompt/content analysis logic
- `whitelist`: Allowed model/policy management
- `sandbox`: Isolated execution and safety controls

Note: Assign owner names per module in `CODEOWNERS` or team docs when finalizing staffing.
