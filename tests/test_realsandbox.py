"""실제 B-2 샌드박스 배선(whitelist.realsandbox) opt-in 게이트 회귀.

기본(토글 off)은 아무것도 안 하고, 토글 on이라도 Docker/runsc 미가용/실패면
graceful degrade(None) 하는 것을 검증한다. 실제 runsc e2e는 WSL2 환경 전용.
"""
from whitelist.realsandbox import build_real_b2_context, real_sandbox_enabled


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HUGGINGMASK_ENABLE_REAL_SANDBOX", raising=False)
    assert real_sandbox_enabled() is False
    assert build_real_b2_context(snapshot_root=None, evidence_dir="x") is None


def test_toggle_recognizes_truthy_values(monkeypatch):
    for v in ("1", "true", "YES", "on"):
        monkeypatch.setenv("HUGGINGMASK_ENABLE_REAL_SANDBOX", v)
        assert real_sandbox_enabled() is True
    for v in ("0", "", "false", "no"):
        monkeypatch.setenv("HUGGINGMASK_ENABLE_REAL_SANDBOX", v)
        assert real_sandbox_enabled() is False


def test_enabled_without_docker_degrades_gracefully(monkeypatch, tmp_path):
    # 토글 on이지만 Docker/runsc/이미지 미비 → 예외 대신 None(기존 경로 유지)
    monkeypatch.setenv("HUGGINGMASK_ENABLE_REAL_SANDBOX", "1")
    # 구성 자체는 Docker 데몬 접근 없이도 객체 생성까지는 될 수 있으나,
    # 어떤 경우든 예외를 던지지 않아야 한다(None 또는 dict).
    out = build_real_b2_context(snapshot_root=str(tmp_path), evidence_dir=str(tmp_path / "ev"))
    assert out is None or isinstance(out, dict)
