"""HuggingMask 프록시 부트스트랩.

현재는 다음만 활성화되어 있다:
  - 헬스 체크 (/, /health)
  - 화이트리스트 엔진 (/internal/v1/whitelist/*, /pending/*, /review, /feedback, /audit/*)

analyzer/sandbox 라우터는 각 모듈 구현 완료 후 추가 예정.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from whitelist.bootstrap import init_whitelist
from whitelist.router import router as whitelist_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_whitelist()
    yield


app = FastAPI(title="HuggingMask Proxy Bootstrap", lifespan=lifespan)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "HuggingMask bootstrap running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(whitelist_router)
