"""
감사 로그 해시 체인 테스트 — 9.2절 무결성 보장

검증 포인트:
- 첫 항목의 prev_hash는 GENESIS
- 각 항목의 prev_hash = 직전 항목의 entry_hash
- entry_hash 재계산이 저장값과 일치
- detail 사후 변조 시 verify가 실패
- prev_hash 변조 시 verify가 실패
"""

from datetime import datetime, timezone

from whitelist.audit import (
    GENESIS_HASH, append_audit, compute_entry_hash, verify_audit_chain,
)
from whitelist.tables import AuditLog


def _add(db, action: str, api_path: str, actor: str = "system", detail: str = ""):
    log = append_audit(db, action, api_path, actor, detail)
    db.commit()
    return log


class TestChainFormation:

    def test_first_entry_links_to_genesis(self, db_session):
        _add(db_session, "test_action", "torch.X")
        log = db_session.query(AuditLog).first()
        assert log.prev_hash == GENESIS_HASH
        assert len(log.entry_hash) == 64

    def test_chain_links(self, db_session):
        _add(db_session, "a1", "api.A")
        _add(db_session, "a2", "api.B")
        _add(db_session, "a3", "api.C")
        logs = list(db_session.query(AuditLog).order_by(AuditLog.id))
        assert logs[0].prev_hash == GENESIS_HASH
        assert logs[1].prev_hash == logs[0].entry_hash
        assert logs[2].prev_hash == logs[1].entry_hash


class TestVerification:

    def test_intact_chain_passes(self, db_session):
        for i in range(5):
            _add(db_session, "act", f"api.X{i}")
        ok, errors = verify_audit_chain(db_session)
        assert ok
        assert errors == []

    def test_detail_tampering_detected(self, db_session):
        _add(db_session, "act", "torch.X", detail="원본")
        log = db_session.query(AuditLog).first()
        log.detail = "변조"
        db_session.commit()
        ok, errors = verify_audit_chain(db_session)
        assert not ok
        assert any("변조 의심" in e for e in errors)

    def test_prev_hash_tampering_detected(self, db_session):
        for i in range(3):
            _add(db_session, "act", f"api.X{i}")
        logs = list(db_session.query(AuditLog).order_by(AuditLog.id))
        logs[1].prev_hash = "0" * 64
        db_session.commit()
        ok, errors = verify_audit_chain(db_session)
        assert not ok


class TestHashFunction:

    def test_deterministic(self):
        ts = datetime(2026, 4, 20, tzinfo=timezone.utc)
        h1 = compute_entry_hash("p", "a", "x", "u", ts, "d")
        h2 = compute_entry_hash("p", "a", "x", "u", ts, "d")
        assert h1 == h2

    def test_input_change_changes_hash(self):
        ts = datetime(2026, 4, 20, tzinfo=timezone.utc)
        h1 = compute_entry_hash("p", "approve", "x", "u", ts, "d")
        h2 = compute_entry_hash("p", "reject", "x", "u", ts, "d")
        assert h1 != h2

    def test_tzinfo_normalization(self):
        """SQLite roundtrip 시 tzinfo가 사라져도 같은 해시여야 함"""
        ts_aware = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)
        ts_naive = datetime(2026, 4, 20, 12, 0, 0)
        h1 = compute_entry_hash("p", "a", "x", "u", ts_aware, "d")
        h2 = compute_entry_hash("p", "a", "x", "u", ts_naive, "d")
        assert h1 == h2
