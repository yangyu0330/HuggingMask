"""
제한 런타임 (CODE_RESTRICTED_RUNTIME) 단위 테스트.

기본 계약:
  - RestrictedRuntimeResult 양유상 스키마 키 호환
  - restricted_exec가 builtins/import/audit/time/memory 제한 적용
  - runtime_check_loader 어댑터 — callable/mapping source_loader
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
        """eval/exec/compile/open 같은 핵심 위험 builtins 포함.

        ``__import__``은 RESTRICTED에 없다 — 정상 ``import`` 문 동작에 필요.
        IMPORT_DENYLIST는 sys.meta_path import hook이 별도로 차단.
        """
        for name in ("eval", "exec", "compile", "open"):
            assert name in RESTRICTED_BUILTINS

    def test_import_dunder_intentionally_kept(self):
        """``__import__``은 builtins overlay에 유지 (import 문 동작에 필요)."""
        assert "__import__" not in RESTRICTED_BUILTINS

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
    """Phase 1 skeleton 회귀 — to_dict 라운드트립."""

    def test_result_to_dict_round_trip(self):
        result = restricted_exec("pass")
        d = result.to_dict()
        assert d["runtime_mode"] == "RESTRICTED_RUNTIME"
        assert "status" in d


# ─────────────────────────────────────────────
# Phase 2 — 실제 격리 실행 (multiprocessing)
# subprocess spawn 비용으로 각 테스트 ~수백 ms 소요. 핵심 시나리오만.
# ─────────────────────────────────────────────

class TestPhase2Isolation:

    def test_safe_arithmetic_passes(self):
        """안전 코드 → status=PASS, exception 없음."""
        result = restricted_exec("x = 1 + 2 * 3\n", timeout_seconds=10.0)
        assert result.status == RuntimeStatus.PASS, (
            f"기대 PASS, 실제 {result.status}. tb={result.traceback}"
        )
        assert result.exception_class is None
        assert result.exec_time_ms > 0

    def test_dangerous_import_blocked(self):
        """IMPORT_DENYLIST 모듈 import → ImportError → FAIL."""
        result = restricted_exec(
            "import subprocess\nsubprocess.run(['ls'])\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert "subprocess" in result.blocked_imports
        assert result.exception_class == "ImportError"

    def test_allowlisted_math_import_passes(self):
        result = restricted_exec(
            "import math\nx = math.sqrt(4)\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.PASS, result.traceback

    def test_non_allowlisted_json_import_blocked(self):
        result = restricted_exec(
            "import json\nx = json.dumps({'a': 1})\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "ImportError"
        assert "json" in result.blocked_imports

    def test_extra_import_allowlist_permits_json(self):
        result = restricted_exec(
            "import json\nx = json.dumps({'a': 1})\n",
            timeout_seconds=10.0,
            extra_import_allowlist=frozenset({"json"}),
        )
        assert result.status == RuntimeStatus.PASS, result.traceback

    def test_extra_import_allowlist_does_not_override_denylist(self):
        result = restricted_exec(
            "import os\nx = os.getcwd()\n",
            timeout_seconds=10.0,
            extra_import_allowlist=frozenset({"os"}),
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "ImportError"
        assert "os" in result.blocked_imports

    @pytest.mark.parametrize(
        ("source", "blocked_name"),
        [
            ("import builtins\nx = builtins.eval('1+1')\n", "builtins"),
            (
                "import builtins\n"
                "f = builtins.open('analyzer/schemas.py', 'r', encoding='utf-8')\n",
                "builtins",
            ),
            (
                "import io\n"
                "f = io.open('analyzer/schemas.py', 'r', encoding='utf-8')\n",
                "io",
            ),
            (
                "from pathlib import Path\n"
                "data = Path('analyzer/schemas.py').read_text(encoding='utf-8')\n",
                "pathlib",
            ),
        ],
    )
    def test_non_allowlisted_import_bypass_attempts_blocked(
        self, source, blocked_name,
    ):
        result = restricted_exec(source, timeout_seconds=10.0)
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "ImportError"
        assert blocked_name in result.blocked_imports

    def test_eval_blocked_by_builtins_overlay(self):
        """builtins에서 eval 제거 → NameError → FAIL."""
        result = restricted_exec(
            "x = eval('1+1')\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "NameError"

    def test_exec_blocked_by_builtins_overlay(self):
        result = restricted_exec(
            "exec('y = 1')\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "NameError"

    def test_open_blocked_by_builtins_overlay(self):
        """open() 호출 차단."""
        result = restricted_exec(
            "f = open('/etc/passwd')\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "NameError"

    def test_runtime_error_in_user_code_returns_fail(self):
        """사용자 코드의 일반 예외도 FAIL로 정규화."""
        result = restricted_exec(
            "x = 1 / 0\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "ZeroDivisionError"
        assert result.traceback is not None

    def test_infinite_loop_timeout(self):
        """무한 루프 → TIMEOUT."""
        result = restricted_exec(
            "while True:\n    pass\n",
            timeout_seconds=2.0,
        )
        assert result.status == RuntimeStatus.TIMEOUT
        assert result.exception_class == "TimeoutError"

    def test_class_definition_works(self):
        """B-1 시나리오 — class M(nn.Module) 같은 코드는 (nn import는 차단되지만)
        class 정의 자체는 builtins overlay에서 동작해야 함.
        """
        result = restricted_exec(
            "class Demo:\n    def __init__(self): self.x = 1\n"
            "d = Demo()\n",
            timeout_seconds=10.0,
        )
        assert result.status == RuntimeStatus.PASS, (
            f"class 정의 실패. tb={result.traceback}"
        )

    def test_pass_result_compatible_with_yangyu_gate(self):
        """우리 PASS 결과가 양유상 _runtime_gate_passed()를 통과하는지."""
        from analyzer.validators.code_validator import _runtime_gate_passed
        result = restricted_exec("x = 1\n", timeout_seconds=10.0)
        assert _runtime_gate_passed(result.to_dict()) is True

    def test_fail_result_does_not_pass_yangyu_gate(self):
        from analyzer.validators.code_validator import _runtime_gate_passed
        result = restricted_exec(
            "import subprocess\n", timeout_seconds=10.0,
        )
        assert _runtime_gate_passed(result.to_dict()) is False


# ─────────────────────────────────────────────
# Phase 3 — 메모리 제한 (Linux/Mac만)
# ─────────────────────────────────────────────

class TestPhase3MemoryLimit:

    def test_memory_limit_triggers_memory_status(self):
        """Linux/Mac: setrlimit(RLIMIT_AS) → MemoryError → status=MEMORY_LIMIT.
        Windows: resource 모듈에 RLIMIT_AS 없어서 setrlimit 없음, 일반 PASS.
        """
        import sys as _sys
        if _sys.platform == "win32":
            pytest.skip("Linux/Mac only — RLIMIT_AS")

        result = restricted_exec(
            # 1GB bytearray 시도 — limit 64MB로 걸리면 MemoryError
            "x = bytearray(1024 * 1024 * 1024)\n",
            timeout_seconds=10.0,
            memory_limit_mb=64,
        )
        assert result.status == RuntimeStatus.MEMORY_LIMIT
        assert result.exception_class == "MemoryError"

    def test_memory_limit_does_not_block_normal_code(self):
        """일반 산술 같은 작은 코드는 메모리 제한과 무관."""
        result = restricted_exec(
            "x = sum(range(100))\n",
            timeout_seconds=10.0,
            memory_limit_mb=128,
        )
        assert result.status == RuntimeStatus.PASS


# ─────────────────────────────────────────────
# Phase 4 — orchestrator 호환 factory + end-to-end
# ─────────────────────────────────────────────

class TestPhase4OrchestratorIntegration:

    def test_factory_returns_callable_compatible_with_yangyu_orchestrator(self):
        """make_restricted_runtime_loader 반환 callable은 (repo_path,) → dict|None.
        양유상 ``Callable[[str], dict | None]`` 시그니처와 호환.
        """
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )
        sources = {"modeling.py": "x = 1\n"}
        loader = make_restricted_runtime_loader(sources)

        # repo_path만 받고 dict 반환
        result = loader("modeling.py")
        assert result is not None
        assert result["runtime_mode"] == "RESTRICTED_RUNTIME"
        assert result["status"] == "PASS"

    def test_factory_loader_returns_none_for_missing_path(self):
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )
        loader = make_restricted_runtime_loader({"a.py": "pass"})
        assert loader("missing.py") is None

    def test_end_to_end_run_validation_job(self):
        """양유상 run_validation_job + 우리 loader = 진짜 격리 실행 통합.

        B-1 후보 코드(정형 modeling, allowed API only) → restricted_exec PASS
        → 양유상 _runtime_gate_passed True → grade B-1, status PASS.
        """
        import hashlib
        from pathlib import PurePosixPath

        from analyzer.orchestrator import build_minimal_request, run_validation_job
        from analyzer.schemas import (
            ArtifactRef, FileKind, PolicyInfo, ValidationStatus,
        )
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )

        # 정형 modeling 코드 — 위험 import / call / 동적 패턴 없음
        source = (
            "from torch import nn\n"
            "class M(nn.Module):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "        self.fc = nn.Linear(2, 2)\n"
            "    def forward(self, x):\n"
            "        return self.fc(x)\n"
        )
        # 우리 격리 환경에선 torch import가 IMPORT_ALLOWLIST에 있긴 하지만
        # torch가 venv에 없으면 ImportError. 그래서 단순한 코드로 대체:
        source = (
            "x = 1\n"
            "class M:\n"
            "    def forward(self, x): return x\n"
            "m = M()\n"
            "result = m.forward(42)\n"
        )

        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        artifact = ArtifactRef(
            artifact_id=f"sha256:{digest}",
            repo_path="modeling_safe.py",
            file_name="modeling_safe.py",
            file_kind=FileKind.PYTHON,
            detected_extension=".py",
            media_type=None,
            size_bytes=len(source.encode("utf-8")),
            sha256=digest,
            source_url="https://huggingface.co/org/demo/resolve/main/modeling_safe.py",
            temp_local_path="/tmp/modeling_safe.py",
            referenced_by=[],
            is_generated=False,
        )
        policy = PolicyInfo(
            policy_version="policy-2026.05.07",
            whitelist_version="wl-2026.04.20",
            opcode_policy_version="opcode-2026.05.07",
            config_schema_version="cfg-2026.05.07",
            runtime_profile_version="rt-2026.05.07",
        )
        request = build_minimal_request(
            request_id="req-rt-1", job_id="job-rt-1",
            policy=policy, artifacts=[artifact],
        )

        sources = {"modeling_safe.py": source}
        response = run_validation_job(
            request,
            source_loader=sources,
            runtime_check_loader=make_restricted_runtime_loader(
                sources, timeout_seconds=10.0,
            ),
        )

        # 검증: artifact_results의 첫 결과가 runtime_check를 거쳐 처리됨
        assert len(response.artifact_results) == 1
        first = response.artifact_results[0]
        rt = first.details.get("runtime_check", {})
        assert rt.get("runtime_mode") == "RESTRICTED_RUNTIME"
        assert rt.get("status") == "PASS"
        # 양유상 등급 결정 — 실제 PASS 받았으면 B-1/PASS 또는 그 이상
        # (정확한 등급은 양유상 로직 — 우리는 runtime_check가 dict로 잘
        # 들어갔는지만 회귀)


# ─────────────────────────────────────────────
# Phase 5 — mock_hf 통합 회귀
# ─────────────────────────────────────────────

class TestPhase5MockHfIntegration:
    """양유상 정적 분석 + 우리 격리 흐름의 정합성 회귀.

    hm-04(악성)는 양유상 AST가 dangerous_calls(``__import__``)로 잡아 grade C.
    우리 restricted_exec까지 도달 안 함 (정상 흐름). overall_status = BLOCK.

    hm-05(안전 코드 + 악성 config)에서 modeling_safe.py만 보면 정적 안전 →
    B-1 후보 → 우리 격리로 옴. torch가 venv에 없으면 ModuleNotFoundError로
    FAIL — 안전 fallback (gate 통과 안 됨, false positive 0).
    """

    @pytest.fixture
    def mock_hf_path(self):
        from pathlib import Path
        return Path(__file__).resolve().parent.parent / "mock_hf"

    def test_hm04_dangerous_import_isolated_runtime(self, mock_hf_path):
        """hm-04 evil code를 우리 격리에 직접 통과시켰을 때.

        torch 없는 환경(테스트)에선 import 실패로 ModuleNotFoundError.
        Docker(torch 설치) 환경에선 ``__import__("builtins")`` 호출 자체는
        통과하지만 ``builtins`` 모듈 자체는 안전. 핵심: 어떤 환경이든
        status != PASS이므로 양유상 gate 통과 안 됨 (false positive 0).
        """
        src = (mock_hf_path / "hm-04-bad-py-import" / "modeling_evil.py").read_text(
            encoding="utf-8",
        )
        result = restricted_exec(src, timeout_seconds=10.0)
        # 어떤 결과가 나오든 PASS는 아니어야 함 (안전 fallback)
        assert result.status != RuntimeStatus.PASS, (
            f"hm-04가 PASS로 통과 — 위험. 실제 status={result.status}, "
            f"exception={result.exception_class}"
        )

    def test_dynamic_subprocess_import_blocked_by_runtime(self):
        """양유상 AST가 어떤 이유로 동적 import를 못 잡았을 때 우리 격리가
        2차 방어선으로 잡는지. ``__import__("subprocess")``는 우리 import hook이
        IMPORT_DENYLIST로 차단 → ImportError + blocked_imports.
        """
        src = (
            'mod = __import__("subprocess")\n'
            'mod.run(["echo", "hacked"])\n'
        )
        result = restricted_exec(src, timeout_seconds=10.0)
        assert result.status == RuntimeStatus.FAIL
        assert "subprocess" in result.blocked_imports

    def test_indirect_eval_via_getattr_blocked(self):
        """``getattr(__builtins__, "ev"+"al")(...)`` 같은 builtins 우회 시도.
        builtins overlay에서 eval/getattr 모두 제거됨 → NameError.
        """
        src = (
            'f = getattr(__builtins__, "ev" + "al")\n'
            'f("1+1")\n'
        )
        result = restricted_exec(src, timeout_seconds=10.0)
        assert result.status == RuntimeStatus.FAIL
        assert result.exception_class == "NameError"

    def test_socket_connect_blocked_by_audit_hook(self):
        """``socket.connect`` audit event를 hook이 차단 — ImportError(socket)가
        먼저 막아도 OK.
        """
        src = (
            'import socket\n'
            's = socket.socket()\n'
            's.connect(("evil.example.com", 80))\n'
        )
        result = restricted_exec(src, timeout_seconds=10.0)
        assert result.status == RuntimeStatus.FAIL
        # socket이 IMPORT_DENYLIST에 있으니 import 단계에서 막힘
        assert "socket" in result.blocked_imports

    def test_hm04_via_yangyu_orchestrator_grade_c_block(self):
        """hm-04 코드를 양유상 run_validation_job에 통과시키면 AST가
        dangerous_calls로 잡아 grade C / BLOCK. 우리 restricted_exec까지
        도달 안 함 (정상 흐름).
        """
        import hashlib
        from analyzer.orchestrator import build_minimal_request, run_validation_job
        from analyzer.schemas import (
            ArtifactRef, FileKind, PolicyInfo, ValidationStatus,
        )
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )
        from pathlib import Path

        mock_hf = Path(__file__).resolve().parent.parent / "mock_hf"
        src = (mock_hf / "hm-04-bad-py-import" / "modeling_evil.py").read_text(
            encoding="utf-8",
        )

        digest = hashlib.sha256(src.encode("utf-8")).hexdigest()
        artifact = ArtifactRef(
            artifact_id=f"sha256:{digest}",
            repo_path="modeling_evil.py",
            file_name="modeling_evil.py",
            file_kind=FileKind.PYTHON,
            detected_extension=".py",
            media_type=None,
            size_bytes=len(src.encode("utf-8")),
            sha256=digest,
            source_url="https://huggingface.co/hm-04/resolve/main/modeling_evil.py",
            temp_local_path="/tmp/modeling_evil.py",
            referenced_by=[],
            is_generated=False,
        )
        policy = PolicyInfo(
            policy_version="policy-2026.05.08",
            whitelist_version="wl-2026.04.20",
            opcode_policy_version="opcode-2026.05.08",
            config_schema_version="cfg-2026.05.08",
            runtime_profile_version="rt-2026.05.08",
        )
        request = build_minimal_request(
            request_id="req-hm04", job_id="job-hm04",
            policy=policy, artifacts=[artifact],
        )

        sources = {"modeling_evil.py": src}
        response = run_validation_job(
            request,
            source_loader=sources,
            runtime_check_loader=make_restricted_runtime_loader(
                sources, timeout_seconds=10.0,
            ),
        )

        # hm-04는 양유상 AST가 잡아서 BLOCK
        assert response.overall_status == ValidationStatus.BLOCK, (
            f"hm-04가 BLOCK 안 됨. status={response.overall_status}, "
            f"artifact_results={[(r.artifact.repo_path, r.status) for r in response.artifact_results]}"
        )


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

    def test_extra_import_allowlist_forwarded_to_runtime_check_loader(self):
        sources = {"modeling.py": "import json\nx = json.dumps({'a': 1})\n"}
        result = runtime_check_loader(
            "modeling.py",
            source_loader=sources,
            extra_import_allowlist=frozenset({"json"}),
        )
        assert result is not None
        assert result["status"] == RuntimeStatus.PASS

    def test_extra_import_allowlist_forwarded_to_factory_loader(self):
        from analyzer.validators.code_restricted_runtime import (
            make_restricted_runtime_loader,
        )

        sources = {"modeling.py": "import json\nx = json.dumps({'a': 1})\n"}
        loader = make_restricted_runtime_loader(
            sources,
            extra_import_allowlist=frozenset({"json"}),
        )
        result = loader("modeling.py")
        assert result is not None
        assert result["status"] == RuntimeStatus.PASS
