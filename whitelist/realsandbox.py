"""실제 Docker/runsc 샌드박스 실행 배선 (opt-in, env 게이트).

대시보드 '모델 검사'에서 B-2(gVisor) 단계를 **실제로 실행**하려면 Linux +
Docker + gVisor(runsc) 환경이 필요하다(=WSL2). 이 모듈은 그 환경에서만 켜지는
opt-in 글루다:

- ``HUGGINGMASK_ENABLE_REAL_SANDBOX`` 미설정(기본) → 아무것도 안 함. 기존
  Windows/dev/데모 경로 그대로(B-2는 PENDING 라우팅까지만).
- 설정 + Docker/runsc 가용 → ``B2HostRunner + RealDockerCommandRunner``를 구성해
  full_pipeline → orchestrator 로 전달. 커스텀 코드가 runsc 컨테이너에서 제한 실행.

구성 실패(이미지 없음 / Docker 미가용 / Windows)는 예외를 던지지 않고 ``None``을
반환해 **graceful degrade** 한다 — 실행 단계 배선이 환경을 깨지 않는다.

정직 라벨: 이 경로의 e2e(runsc 실제 실행)는 WSL2+Docker+gVisor 환경에서만
검증된다. 호스트측 배선/구성까지는 단위 테스트가 커버하고, runsc e2e는 셋업
완료 후 ``scripts/check_gvisor_setup.sh`` + 대시보드로 확인한다.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def real_sandbox_enabled() -> bool:
    """``HUGGINGMASK_ENABLE_REAL_SANDBOX`` opt-in 토글."""
    return os.getenv("HUGGINGMASK_ENABLE_REAL_SANDBOX", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def build_real_b2_context(
    *,
    snapshot_root: str | Path | None,
    evidence_dir: str | Path,
) -> dict[str, Any] | None:
    """env 토글 시 실제 B-2 러너 컨텍스트를 구성. 아니면/실패 시 ``None``.

    Returns ``{"b2_runner", "b2_output_dir", "source_resolver"}`` (run_full_validation
    이 그대로 forward) 또는 ``None``.
    """
    if not real_sandbox_enabled():
        return None
    try:
        from analyzer.snapshot_resolver import SnapshotSourceResolver
        from sandbox.b2.host_runner import B2DockerRuntimeConfig
        from sandbox.b2.host_runner_executor import B2HostRunner
        from sandbox.b2.real_command_runner import RealDockerCommandRunner

        # evidence/staging/runner 는 컨테이너(--user=1000:1000)가 쓰는 바인드마운트
        # 대상이므로 Linux 네이티브 FS여야 한다(/mnt/c 같은 DrvFs는 chmod 미지원으로
        # docker cp/write 실패). WSL2에서는 HUGGINGMASK_SANDBOX_EVIDENCE_DIR 로
        # ``~/hm-evidence`` 같은 홈 경로를 지정.
        evidence_path = Path(
            os.getenv("HUGGINGMASK_SANDBOX_EVIDENCE_DIR", "").strip() or evidence_dir
        )
        evidence_path.mkdir(parents=True, exist_ok=True)

        config = B2DockerRuntimeConfig(
            image_ref=os.getenv("HUGGINGMASK_B2_IMAGE", "huggingmask-b2-sandbox:local"),
            docker_runtime=os.getenv("HUGGINGMASK_B2_RUNTIME", "runsc"),
            docker_binary=os.getenv("HUGGINGMASK_DOCKER_BINARY", "docker"),
        )
        # runsc strace 캡처: 런타임이 ``--strace --debug --debug-log=<dir>`` 로 구성된
        # 경우 그 ``<dir>``을 지정하면 strace 관측 → #55 require_runsc_strace 게이트
        # 통과(clean review). 미지정이면 fail-closed(LOG_INCOMPLETE) 유지.
        runner_kwargs: dict[str, Any] = {"evidence_dir": evidence_path}
        strace_dir = os.getenv("HUGGINGMASK_B2_STRACE_LOG_DIR", "").strip()
        if strace_dir:
            runner_kwargs["runsc_strace_log_dir"] = Path(strace_dir)
        b2_runner = B2HostRunner(
            config=config,
            output_dir=evidence_path / "runner",
            command_runner=RealDockerCommandRunner(**runner_kwargs),
            repo_root=Path.cwd(),
        )
        resolver = (
            SnapshotSourceResolver(model_snapshot_root=snapshot_root)
            if snapshot_root
            else None
        )
        return {
            "b2_runner": b2_runner,
            "b2_output_dir": str(evidence_path / "staging"),
            "source_resolver": resolver,
        }
    except Exception:  # noqa: BLE001 — 환경 미비는 graceful degrade(기존 경로 유지)
        return None
