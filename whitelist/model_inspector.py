"""대시보드 '모델 검사' 가시화용 서버측 글루.

브라우저는 HuggingFace 모델을 직접 받을 수 없으므로, repo_id를 받아서
서버에서 텍스트 아티팩트(가중치 제외 가능)를 내려받아 분류한 뒤 기존 통합
검증(:func:`whitelist.full_pipeline.run_full_validation`)에 그대로 태운다.

이 모듈은 **글루**다 — 새 검증 로직을 만들지 않고, 기존 분류기/통합 파이프라인을
공개 인터페이스로만 호출한다. 반환값은 ``/validation/full``과 동일한
``ValidationJobResponse`` + 다운로드/분류 메타(가시화용)를 한 번에 묶은 dict.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from analyzer.classifier import classify_file_kind
from analyzer.schemas import FileKind
from whitelist.full_pipeline import run_full_validation

# 가중치는 핵심 코드/메타 검사 데모에서 GB 단위 다운로드를 피하기 위해 옵션으로 제외.
_WEIGHT_KINDS = {FileKind.SAFETENSORS, FileKind.PICKLE}
# --skip-weights 시 내려받을 작은 메타/코드 파일 패턴(데모 경로와 동일).
_TEXT_ALLOW_PATTERNS = ["*.json", "*.txt", "*.py", "*.md"]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_inspect_artifacts(
    local_dir: Path, repo_id: str, skip_weights: bool
) -> tuple[list[dict], list[str], list[str]]:
    """다운로드된 디렉토리를 검증 아티팩트 dict 목록으로.

    Returns ``(artifacts, skipped_other, skipped_weights)``. ``OTHER``로 분류되는
    파일은 검증 경로가 없어 제외(가시화에서 '검사 제외'로 표기), ``skip_weights``면
    safetensors/pickle도 제외.
    """
    artifacts: list[dict] = []
    skipped_other: list[str] = []
    skipped_weights: list[str] = []

    for path in sorted(local_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(local_dir).as_posix()
        kind = classify_file_kind(rel)
        if kind is FileKind.OTHER:
            skipped_other.append(rel)
            continue
        if skip_weights and kind in _WEIGHT_KINDS:
            skipped_weights.append(rel)
            continue

        digest = _sha256_file(path)
        artifacts.append(
            {
                "artifact_id": f"sha256:{digest}",
                "repo_path": rel,
                "file_name": path.name,
                "file_kind": kind.value,
                "detected_extension": path.suffix.lower(),
                "size_bytes": path.stat().st_size,
                "sha256": digest,
                "source_url": f"https://huggingface.co/{repo_id}/blob/main/{rel}",
                "temp_local_path": str(path),
            }
        )

    return artifacts, skipped_other, skipped_weights


def inspect_artifacts(
    artifacts: list[dict],
    *,
    db: Session,
    repo_id: str = "",
    enable_path_b: bool = False,
    notes: str = "",
    snapshot_root: str | None = None,
    revision: str = "main",
) -> "object":
    """이미 빌드된 아티팩트 목록을 통합 검증에 태우고 응답 객체를 반환.

    네트워크 없이 동작 — 단위 테스트는 이 함수를 fixture 경로로 직접 호출한다.

    ``HUGGINGMASK_ENABLE_REAL_SANDBOX`` opt-in + Docker/runsc 가용 시 B-2 커스텀
    코드를 실제 runsc 샌드박스에서 실행한다(미설정/실패 시 기존 PENDING 경로).
    """
    job = {
        "request_id": str(uuid.uuid4()),
        "job_id": str(uuid.uuid4()),
        "artifacts": artifacts,
        "enable_path_b": enable_path_b,
        "policy_fingerprint": "dashboard-inspect-policy",
        "notes": notes or f"dashboard inspect for {repo_id}",
    }
    if snapshot_root:
        job["model_snapshot_root"] = snapshot_root

    # opt-in 실제 B-2 runsc 샌드박스 실행 컨텍스트(미설정/실패 시 None → 기존 경로)
    from whitelist.realsandbox import build_real_b2_context

    b2_ctx = build_real_b2_context(
        snapshot_root=snapshot_root,
        evidence_dir=os.path.join("evidence", "sandbox", "dashboard"),
    )
    if b2_ctx is not None:
        return run_full_validation(job, db=db, revision=revision, **b2_ctx)
    return run_full_validation(job, db=db)


# B-2 샌드박스 데모 타깃 — 파일명 modeling_*.py 로 MODELING 분류, self.custom_activation
# 은 미등록 API ref(pending_api_refs) 라 B-2/CODE_SANDBOX_RUNTIME 로 라우팅되고
# _requires_b2_sandbox 를 만족한다. 위험/동적/난독화 패턴은 없어 정적 차단 안 됨.
_B2_DEMO_SOURCE = (
    "class DemoModel:\n"
    "    def custom_activation(self, x):\n"
    "        return x\n\n"
    "    def forward(self, x):\n"
    "        return self.custom_activation(x)\n"
)


def _inspect_b2_demo(*, db: Session, enable_path_b: bool = False) -> dict:
    """내장 B-2 샌드박스 데모. Linux 네이티브 임시 디렉토리에 데모 코드를 써서
    검사 — 실 sandbox 토글 ON 이면 runsc 에서 실제 실행된다."""
    import tempfile

    snapshot_root = Path(tempfile.mkdtemp(prefix="hm-b2-demo-"))
    repo_path = "modeling_b2_demo.py"
    target = snapshot_root / repo_path
    target.write_text(_B2_DEMO_SOURCE, encoding="utf-8")
    data = target.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    artifacts = [
        {
            "artifact_id": f"sha256:{digest}",
            "repo_path": repo_path,
            "file_name": repo_path,
            "file_kind": "PYTHON",
            "detected_extension": ".py",
            "size_bytes": len(data),
            "sha256": digest,
            "source_url": "local://demo/b2-sandbox",
            "temp_local_path": str(target),
        }
    ]
    response = inspect_artifacts(
        artifacts,
        db=db,
        repo_id="demo:b2-sandbox",
        enable_path_b=enable_path_b,
        notes="B-2 gVisor 샌드박스 내장 데모",
        snapshot_root=str(snapshot_root),
    )
    return {
        "ok": True,
        "repo_id": "demo:b2-sandbox (내장 B-2 데모)",
        "revision": "local",
        "skip_weights": True,
        "validated_count": len(artifacts),
        "skipped_other": [],
        "skipped_weights": [],
        "response": response,
    }


def inspect_model_repo(
    repo_id: str,
    *,
    db: Session,
    revision: str = "main",
    skip_weights: bool = True,
    enable_path_b: bool = False,
    cache_dir: str | None = None,
) -> dict:
    """repo_id를 받아 다운로드→분류→통합 검증까지 한 번에. 가시화용 dict 반환.

    실패(huggingface_hub 미설치, 다운로드 오류, 검증 대상 0개)는 예외를 던지지
    않고 ``{"ok": False, "error": ...}``로 반환해 대시보드가 친절히 표시하게 한다.
    """
    repo_id = (repo_id or "").strip()
    if not repo_id:
        return {"ok": False, "error": "repo_id를 입력하세요.", "error_code": "EMPTY_REPO_ID"}

    # 내장 B-2 샌드박스 데모 — HF 다운로드 없이 _requires_b2_sandbox 를 확실히
    # 트리거하는 benign 커스텀 코드(self.custom_activation = 미등록 API ref)를
    # 검사. 실 sandbox 토글이 켜져 있으면 runsc 에서 실제 실행된다.
    if repo_id in {"demo:b2-sandbox", "demo:gvisor"}:
        return _inspect_b2_demo(db=db, enable_path_b=enable_path_b)

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        return {
            "ok": False,
            "error": "huggingface_hub가 설치돼 있지 않습니다 (pip install huggingface_hub).",
            "error_code": "HF_HUB_MISSING",
        }

    allow = _TEXT_ALLOW_PATTERNS if skip_weights else None
    try:
        local_dir = snapshot_download(
            repo_id=repo_id,
            revision=revision,
            cache_dir=cache_dir,
            allow_patterns=allow,
        )
    except Exception as exc:  # noqa: BLE001 — 다운로드 실패 사유를 그대로 전달
        return {
            "ok": False,
            "error": f"'{repo_id}' 다운로드 실패: {exc}",
            "error_code": "DOWNLOAD_FAILED",
            "repo_id": repo_id,
        }

    artifacts, skipped_other, skipped_weights = build_inspect_artifacts(
        Path(local_dir), repo_id, skip_weights
    )
    if not artifacts:
        return {
            "ok": False,
            "error": "검증 대상 아티팩트가 없습니다 (FileKind 매핑되는 파일 없음).",
            "error_code": "NO_ARTIFACTS",
            "repo_id": repo_id,
            "skipped_other": skipped_other,
            "skipped_weights": skipped_weights,
        }

    response = inspect_artifacts(
        artifacts,
        db=db,
        repo_id=repo_id,
        enable_path_b=enable_path_b,
        notes=f"dashboard inspect for {repo_id}@{revision}",
        snapshot_root=str(local_dir),
        revision=revision,
    )

    return {
        "ok": True,
        "repo_id": repo_id,
        "revision": revision,
        "skip_weights": skip_weights,
        "validated_count": len(artifacts),
        "skipped_other": skipped_other,
        "skipped_weights": skipped_weights,
        "response": response,
    }
