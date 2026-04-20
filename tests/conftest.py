"""
공통 테스트 fixture.

- db_session: 매 테스트마다 깨끗한 인메모리 SQLite 세션
- model_ref:  테스트용 ModelRef 더미
- check_request_factory: WhitelistCheckRequest 빌더
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from whitelist.database import Base
from whitelist import tables  # noqa: F401 — 테이블 등록 트리거
from whitelist.models import (
    EndpointMode, ModelRef, WhitelistCheckRequest,
)


@pytest.fixture
def db_session():
    """매 테스트마다 새 인메모리 SQLite 세션"""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def model_ref() -> ModelRef:
    return ModelRef(
        repo_id="org/demo-model",
        revision="main",
        source_host="huggingface.co",
        source_url="https://huggingface.co/org/demo-model",
        requested_by="developer-a",
        requested_at="2026-04-20T09:00:00Z",
        endpoint_mode=EndpointMode.HF_ENDPOINT_PROXY,
    )


@pytest.fixture
def check_request_factory(model_ref):
    def _make(apis: list[str]) -> WhitelistCheckRequest:
        return WhitelistCheckRequest(
            schema_version="1.0",
            request_id=str(uuid.uuid4()),
            job_id=str(uuid.uuid4()),
            model=model_ref,
            apis=apis,
        )
    return _make
