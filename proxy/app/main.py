from fastapi import FastAPI

from analyzer.schemas import ValidationJobRequest
from analyzer.service import validate_job

app = FastAPI(title="HuggingMask Proxy Bootstrap")


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "HuggingMask bootstrap running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/v1/validation/jobs")
def validation_jobs(payload: ValidationJobRequest):
    return validate_job(payload)