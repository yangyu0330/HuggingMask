"""프록시 다운로드 게이트(whitelist.acquisition) 회귀.

받기 전 검사 → 판정(ACQUIRED/QUARANTINED/PENDING) → 저장소 기록. 네트워크
없는 내장 데모(demo:b2-sandbox)로 게이트 흐름과 저장을 검증한다.
"""
from whitelist.acquisition import gate_model, list_acquired


def test_gate_demo_records_decision(db_session):
    out = gate_model("demo:b2-sandbox", db=db_session)
    assert out["ok"] is True
    # B-2 데모는 REVIEW_REQUIRED → 사람 검토 보류(PENDING), 미배포
    assert out["decision"] == "REVIEW_REQUIRED", out["decision"]
    assert out["status"] == "PENDING"
    assert out["allowed"] is False

    items = list_acquired(db_session)
    rec = next((i for i in items if i["repo_id"] == "demo:b2-sandbox"), None)
    assert rec is not None
    assert rec["status"] == "PENDING"


def test_gate_empty_repo_fails(db_session):
    out = gate_model("   ", db=db_session)
    assert out["ok"] is False
    assert out["error_code"] == "EMPTY_REPO_ID"


def test_gate_upserts_same_repo(db_session):
    gate_model("demo:b2-sandbox", db=db_session)
    gate_model("demo:b2-sandbox", db=db_session)
    items = [i for i in list_acquired(db_session) if i["repo_id"] == "demo:b2-sandbox"]
    assert len(items) == 1  # 같은 repo 는 갱신(중복 행 X)
