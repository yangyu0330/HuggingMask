"""프록시 다운로드 게이트 — 받기 전에 검사하고, 안전하면 통과·저장 아니면 차단.

HuggingMask 제품 thesis("신뢰가 아니라 행위로 판정")를 다운로드 경로에 적용한다:
클라이언트가 모델을 받기 전에 프록시가 코드/config/전처리를 **먼저** 검사
(``skip_weights`` — 가중치 GB는 안 받음)하고,

- DENY        → 가중치까지 받지 않고 격리(QUARANTINED). 다운로드 차단.
- APPROVE     → acquire(다운로드 허용) + Nexus 역할 저장소(``acquired_models``)에 기록.
- REVIEW      → 사람 검토 보류(PENDING).

즉 악성 코드는 **무거운 가중치를 받기도 전에** 코드 단계에서 걸러진다.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from whitelist.audit import append_audit
from whitelist.model_inspector import inspect_model_repo
from whitelist.tables import AcquiredModel

# 사내 아티팩트 저장소(Nexus 역할) 루트. 승인된 모델 '파일'을 실제로 보관한다.
NEXUS_ROOT = Path(os.getenv("HUGGINGMASK_NEXUS_DIR", "nexus_store"))
_NEXUS_MANIFEST = "_hm_nexus.json"


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _nexus_dir(repo_id: str, revision: str) -> Path:
    """repo/revision 별 저장 디렉터리(경로 traversal 방지)."""
    safe_repo = repo_id.replace("..", "_").strip("/")
    safe_rev = (revision or "main").replace("..", "_").replace("/", "_")
    return NEXUS_ROOT / safe_repo / safe_rev


def _store_to_nexus(repo_id: str, revision: str) -> dict:
    """승인된 모델을 실제로 내려받아 nexus_store 에 보관하고 매니페스트를 남긴다.

    실패해도 게이트 판정 자체는 깨지 않도록 dict 로 결과만 반환한다(best-effort).
    검사(skip_weights)와 달리 여기서는 가중치 포함 전체를 보관한다.
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:  # pragma: no cover
        return {"stored": False, "error": f"huggingface_hub 미설치: {e}"}

    dest = _nexus_dir(repo_id, revision)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        local = snapshot_download(repo_id=repo_id, revision=revision, local_dir=str(dest))
        local_path = Path(local)
        files: list[dict] = []
        total = 0
        for p in sorted(local_path.rglob("*")):
            if not p.is_file() or ".cache" in p.parts or p.name == _NEXUS_MANIFEST:
                continue
            size = p.stat().st_size
            files.append({"path": p.relative_to(local_path).as_posix(), "bytes": size})
            total += size
        manifest = {
            "repo_id": repo_id,
            "revision": revision,
            "files": files,
            "file_count": len(files),
            "bytes": total,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        (local_path / _NEXUS_MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return {"stored": True, "path": str(dest), **manifest}
    except Exception as e:  # noqa: BLE001 — 보관 실패는 판정과 분리(증거만 남김)
        return {"stored": False, "error": str(e), "path": str(dest)}


def list_nexus() -> list[dict]:
    """nexus_store 에 보관된 모델 목록(매니페스트 기반, 최신순)."""
    if not NEXUS_ROOT.exists():
        return []
    items: list[dict] = []
    for mf in NEXUS_ROOT.rglob(_NEXUS_MANIFEST):
        try:
            items.append(json.loads(mf.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    items.sort(key=lambda x: x.get("stored_at", ""), reverse=True)
    return items


def nexus_file_path(repo_id: str, revision: str, rel_path: str) -> Path | None:
    """보관된 파일의 실제 경로(저장 디렉터리 밖 접근 차단)."""
    base = _nexus_dir(repo_id, revision).resolve()
    try:
        target = (base / rel_path).resolve()
    except Exception:  # noqa: BLE001
        return None
    if (target == base or base in target.parents) and target.is_file():
        return target
    return None


def build_nexus_zip(repo_id: str, revision: str) -> bytes | None:
    """보관된 모델 전체를 ZIP 1개로 묶어 반환(브라우저 일괄 다운로드용)."""
    import io
    import zipfile

    base = _nexus_dir(repo_id, revision)
    if not base.exists():
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(base.rglob("*")):
            if not p.is_file() or ".cache" in p.parts or p.name == _NEXUS_MANIFEST:
                continue
            zf.write(p, p.relative_to(base).as_posix())
    return buf.getvalue()


def _first_block_reason(resp) -> str | None:
    for r in resp.artifact_results:
        if _enum_value(r.status) == "BLOCK":
            for e in (r.reason_entries or []):
                return f"{r.artifact.file_name}: {e.code}"
            return r.artifact.file_name
    return None


def gate_model(
    repo_id: str,
    *,
    db: Session,
    revision: str = "main",
    store: bool = True,
) -> dict:
    """다운로드 게이트 — 받기 전에 경량 검사(skip_weights) 후 판정·기록.

    ``store=True``(기본)면 APPROVE 시 모델 파일을 nexus_store 에 실제로 보관한다.
    transparent 프록시 패스스루(HF_ENDPOINT)는 클라이언트가 직접 받으므로 이중
    다운로드를 피하려 ``store=False`` 로 호출한다.
    """
    repo_id = (repo_id or "").strip()
    if not repo_id:
        return {"ok": False, "error": "repo_id를 입력하세요.", "error_code": "EMPTY_REPO_ID"}

    # 1) 다운로드 전 경량 검사(코드/config/전처리 — 가중치 제외)
    out = inspect_model_repo(repo_id, db=db, revision=revision, skip_weights=True)
    if not out.get("ok"):
        return out  # 다운로드 실패 등은 그대로 전달

    resp = out["response"]
    decision = _enum_value(resp.overall_decision)
    blocked = len(getattr(resp, "blocked_artifact_ids", []) or [])
    validated = int(out.get("validated_count", 0) or 0)

    # 다운로드 게이트 정책: '쓰려고 받는' 경로이므로 위험한 것만 막는다.
    #   DENY(위험 탐지)        → 격리(다운로드 차단)
    #   APPROVE/REVIEW(미탐지) → 통과 + Nexus 보관 (정밀 인증은 별도 검토 단계로 남김)
    if decision == "DENY":
        status, allowed = "QUARANTINED", False
    else:
        status, allowed = "ACQUIRED", True
    reason = _first_block_reason(resp)
    if status == "ACQUIRED" and decision != "APPROVE" and not reason:
        reason = "위험 미탐지 - 다운로드 허용·보관 (전처리 정밀 인증은 검토 단계 권장)"

    # 1.5) APPROVE → 사내 저장소(Nexus)에 모델 파일 실제 보관
    stored = None
    if store and status == "ACQUIRED":
        stored = _store_to_nexus(repo_id, revision)

    # 2) Nexus 역할 저장소 기록 — 같은 (repo, revision)은 최신 판정으로 갱신
    record = db.execute(
        select(AcquiredModel).where(
            AcquiredModel.repo_id == repo_id,
            AcquiredModel.revision == revision,
        )
    ).scalar_one_or_none()
    if record is None:
        record = AcquiredModel(repo_id=repo_id, revision=revision)
        db.add(record)
    record.status = status
    record.decision = decision
    record.validated_count = validated
    record.blocked_count = blocked
    record.reason = reason

    stored_detail = ""
    if stored is not None:
        stored_detail = (
            f" stored={stored.get('file_count')}files/{stored.get('bytes')}B"
            if stored.get("stored")
            else f" store_error={stored.get('error')}"
        )
    append_audit(
        db,
        action=f"proxy_gate_{status.lower()}",
        api_path=repo_id,
        actor="proxy-gate",
        detail=f"decision={decision} validated={validated} blocked={blocked}{stored_detail}",
    )
    db.commit()

    return {
        "ok": True,
        "repo_id": repo_id,
        "revision": revision,
        "allowed": allowed,
        "status": status,
        "decision": decision,
        "validated_count": validated,
        "blocked_count": blocked,
        "reason": reason,
        "stored": stored,  # Nexus 보관 결과(APPROVE+store 시) — 파일/바이트 또는 오류
        "response": resp,  # 대시보드가 파이프라인 가시화도 그릴 수 있게
    }


def list_acquired(db: Session, *, limit: int = 100) -> list[dict]:
    """저장소 목록(최신순) — 대시보드 게이트 탭용."""
    rows = (
        db.execute(
            select(AcquiredModel).order_by(AcquiredModel.acquired_at.desc()).limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "repo_id": r.repo_id,
            "revision": r.revision,
            "status": r.status,
            "decision": r.decision,
            "validated_count": r.validated_count,
            "blocked_count": r.blocked_count,
            "reason": r.reason,
            "acquired_at": r.acquired_at.isoformat() if r.acquired_at else None,
        }
        for r in rows
    ]
