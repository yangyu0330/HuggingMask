"""
제한 런타임 (CODE_RESTRICTED_RUNTIME) 단위 테스트.

Phase 1 (현재): skeleton 인터페이스 검증
  - RestrictedRuntimeResult 양유상 스키마 키 호환
  - restricted_exec skeleton이 SKIPPED 반환 (false positive 0 보장)
  - runtime_check_loader 어댑터 — callable/mapping source_loader

Phase 2~3 (후속): 실제 격리 메커니즘
"""

from __future__ import annotations

import pytest

from analyzer.validators.code_restricted_runtime import (
    IMPORT_ALLOWLIST, IMPORT_DENYLIST, RESTRICTED_BUILTINS,
    RestrictedRuntimeResult, RuntimeStatus,
    restricted_exec, runtime_check_loader,
)


# ─────────────────────────────────────────────
# 양유상 스키마 호환성
# ─────────────────────────────────────────────

class TestYangyuSchemaCompat:
    """``code_validator._normalize_runtime_check``가 기대하는 키 셋을
    ``RestrictedRuntimeResult.to_dict()``가 모두 포함하는지.
    """

    REQUIRED_KEYS = {
        "runtime_mode", "status", "builtins_removed",
        "import_allowlist_applied", "dummy_forward_executed",
        "sandbox_runtime", "syscall_anomaly_detected", "logs_ref",
    }

    def test_default_result_has_all_required_keys(self):
        result = RestrictedRuntimeResult()
        d = result.to_dict()
        missing = self.REQUIRED_KEYS - d.keys()
        assert missing == set(), f"누락된 키: {missing}"

    def test_runtime_mode_default(self):
        result = RestrictedRuntimeResult()
        assert result.runtime_mode == "RESTRICTED_RUNTIME"

    def test_status_default_is_skipped(self):
        """기본값 SKIPPED — 양유상 _runtime_gate_passed()는 PASS만 통과.
        skeleton은 false positive 0 (안전한 fallback).
        """
        result = RestrictedRuntimeResult()
        assert result.status == RuntimeStatus.SKIPPED

    def test_sandbox_fields_are_none(self):
        """sandbox_runtime / syscall_anomaly_detected는 검증3(gVisor) 영역.
        제한 런타임에서는 항상 None.
        """
        result = RestrictedRuntimeResult()
        assert result.sandbox_runtime is None
        assert result.syscall_anomaly_detected is None

    def test_yangyu_runtime_gate_pass_only_on_pass_status(self):
        """양유상 _runtime_gate_passed() 동작 검증 — 우리 status 값을
        그대로 사용한다.
        """
        from analyzer.validators.code_validator import _runtime_gate_passed

        # PASS만 True
        assert _runtime_gate_passed({"status": "PASS"}) is True

        # 그 외는 모두 False (안전)
        for status in (
            RuntimeStatus.FAIL, RuntimeStatus.TIMEOUT,
            RuntimeStatus.MEMORY_LIMIT, RuntimeStatus.ERROR,
            RuntimeStatus.SKIPPED,
        ):
            assert _runtime_gate_passed({"status": status}) is False


# ─────────────────────────────────────────────
# 정책 상수
# ─────────────────────────────────────────────

class TestPolicyConstants:

    def test_restricted_builtins_contains_dangerous(self):
        """eval/exec/__import__ 같은 핵심 위험 builtins 포함."""
        for name in ("eval", "exec", "compile", "__import__", "open"):
            assert name in RESTRICTED_BUILTINS

    def test_import_allowlist_has_safe_modules(self):
        """모델링 코드가 흔히 쓰는 안전한 모듈."""
        for mod in ("torch", "torch.nn", "numpy", "transformers"):
            assert mod in IMPORT_ALLOWLIST

    def test_import_denylist_has_dangerous(self):
        """우리 PERMANENTLY_BLOCKED와 정합."""
        for mod in ("subprocess", "socket", "pickle", "ctypes", "os"):
            assert mod in IMPORT_DENYLIST

    def test_allowlist_denylist_disjoint(self):
        """같은 모듈이 양쪽에 동시에 있으면 안 됨."""
        overlap = IMPORT_ALLOWLIST & IMPORT_DENYLIST
        assert overlap == set(), f"중복: {overlap}"


# ─────────────────────────────────────────────
# skeleton 동작 (Phase 1 — 실제 실행 없이 SKIPPED 반환)
# ─────────────────────────────────────────────

class TestSkeletonBehavior:

    def test_safe_code_returns_skipped_for_now(self):
        """Phase 1 skeleton — 실제 실행 안 함, SKIPPED 반환.
        false positive 0 (양유상 gate 통과 못 함 → 안전).
        Phase 2~3에서 실제 PASS 판정 추가 예정.
        """
        result = restricted_exec("x = 1 + 1\n")
        assert result.status == RuntimeStatus.SKIPPED

    def test_exec_does_not_actually_execute_yet(self):
        """skeleton은 격리 없이 실행하지 않음 — 부수효과 없어야 함."""
        # 만약 진짜 실행됐다면 ImportError 나올 텐데, skeleton은 안 실행
        result = restricted_exec("import nonexistent_module_xyz\n")
        assert result.status == RuntimeStatus.SKIPPED
        # exception 정보 없음 (실행 안 했으므로)
        assert result.exception_class is None

    def test_result_to_dict_round_trip(self):
        result = restricted_exec("pass")
        d = result.to_dict()
        assert d["runtime_mode"] == "RESTRICTED_RUNTIME"
        assert "status" in d


# ─────────────────────────────────────────────
# runtime_check_loader 어댑터 (양유상 orchestrator에 주입할 함수)
# ─────────────────────────────────────────────

class TestRuntimeCheckLoader:

    def test_callable_source_loader(self):
        sources = {"modeling.py": "x = 1\n"}
        result = runtime_check_loader(
            "modeling.py", source_loader=sources.get,
        )
        assert result is not None
        assert result["runtime_mode"] == "RESTRICTED_RUNTIME"

    def test_mapping_source_loader(self):
        sources = {"modeling.py": "x = 1\n"}
        result = runtime_check_loader(
            "modeling.py", source_loader=sources,
        )
        assert result is not None
        assert "status" in result

    def test_missing_repo_path_returns_none(self):
        sources = {"other.py": "x = 1\n"}
        result = runtime_check_loader(
            "modeling.py", source_loader=sources,
        )
        assert result is None

    def test_bytes_source_decoded(self):
        sources = {"modeling.py": "x = 1\n".encode("utf-8")}
        result = runtime_check_loader(
            "modeling.py", source_loader=sources,
        )
        assert result is not None
        assert result["runtime_mode"] == "RESTRICTED_RUNTIME"
