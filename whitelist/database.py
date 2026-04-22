"""SQLAlchemy 엔진 / 세션 관리.

기본은 SQLite 파일 (whitelist.db). HUGGINGMASK_DB_URL 환경변수로
PostgreSQL 등으로 교체 가능.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DEFAULT_DB_URL = "sqlite:///./whitelist.db"
DATABASE_URL = os.environ.get("HUGGINGMASK_DB_URL", DEFAULT_DB_URL)


class Base(DeclarativeBase):
    pass


_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Session:
    """FastAPI Depends용 세션 제너레이터"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """테이블 생성 — 앱 시작 시 호출"""
    # tables 모듈을 import 해야 metadata에 등록됨
    from whitelist import tables  # noqa: F401
    Base.metadata.create_all(bind=engine)
