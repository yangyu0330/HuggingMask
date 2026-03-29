from fastapi import FastAPI

app = FastAPI(title="HuggingMask Proxy Bootstrap")


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "HuggingMask bootstrap running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
