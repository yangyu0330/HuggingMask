"""실제 HuggingFace 모델 e2e 검증 데모 클라이언트.

HF Hub에서 모델 repo를 다운로드 → 파일별로 sha256 + FileKind 분류 →
``POST /internal/v1/validation/full``로 검증 요청 → 결과를 표로 출력.

기본값은 통합 엔드포인트(``/validation/full``)이며, ``--weight-only``를 주면
기존 가중치 전용 엔드포인트(``/validation/jobs``)로 요청한다.

사전 준비:
    pip install huggingface_hub safetensors torch numpy
    uvicorn proxy.app.main:app --host 127.0.0.1 --port 8000   # 별도 터미널

사용:
    python scripts/demo_validate_hf.py vmaca123/korean-pii-ner-v3
    python scripts/demo_validate_hf.py <repo_id> --api http://127.0.0.1:8000 --enable-path-b
    python scripts/demo_validate_hf.py <repo_id> --skip-weights   # 큰 safetensors 빼고 빠르게
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import uuid
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analyzer.classifier import classify_file_kind as classify_core_file_kind
from analyzer.schemas import FileKind

DEFAULT_API_BASE = "http://127.0.0.1:8000"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_artifacts(local_dir: Path, repo_id: str, skip_weights: bool) -> list[dict]:
    artifacts = []
    skipped_other = []
    skipped_weights = []

    for path in sorted(local_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(local_dir).as_posix()
        kind = classify_core_file_kind(rel)
        if kind is FileKind.OTHER:
            skipped_other.append(rel)
            continue
        if skip_weights and kind in {FileKind.SAFETENSORS, FileKind.PICKLE}:
            skipped_weights.append(rel)
            continue

        digest = sha256_file(path)
        artifacts.append({
            "artifact_id": f"sha256:{digest}",
            "repo_path": rel,
            "file_name": path.name,
            "file_kind": kind.value,
            "detected_extension": path.suffix.lower(),
            "size_bytes": path.stat().st_size,
            "sha256": digest,
            "source_url": f"https://huggingface.co/{repo_id}/blob/main/{rel}",
            "temp_local_path": str(path),
        })

    if skipped_other:
        print(f"\n[분류 제외 - core FileKind=OTHER] {len(skipped_other)}개")
        for r in skipped_other:
            print(f"    · {r}")

    if skipped_weights:
        print(f"\n[사용자 옵션 제외 - --skip-weights] {len(skipped_weights)}개")
        for r in skipped_weights:
            print(f"    · {r}")

    return artifacts


def print_report(resp_json: dict, artifacts: list[dict]) -> None:
    by_id = {a["artifact_id"]: a for a in artifacts}

    print("\n" + "=" * 72)
    print(f"  전체 판정: {resp_json.get('overall_decision')} "
          f"/ status={resp_json.get('overall_status')} "
          f"/ release={resp_json.get('release_action')}")
    print("=" * 72)
    print(f"  {'파일':<26} {'종류':<22} {'결과':<10} {'등급':<6} 사유")
    print(f"  {'-'*26} {'-'*22} {'-'*10} {'-'*6} {'-'*20}")

    for r in resp_json.get("artifact_results", []):
        art = r.get("artifact", {})
        fname = art.get("file_name", "?")[:26]
        kind = art.get("file_kind", "?")[:22]
        status = r.get("status", "?")
        grade = r.get("grade", "") or ""
        reasons = r.get("reason_entries", [])
        reason = reasons[0].get("code", "") if reasons else ""
        print(f"  {fname:<26} {kind:<22} {status:<10} {grade:<6} {reason}")

    print()
    print(f"  승인 artifact: {len(resp_json.get('approved_artifact_ids', []))}개")
    print(f"  차단 artifact: {len(resp_json.get('blocked_artifact_ids', []))}개")
    print(f"  검토대기 artifact: {len(resp_json.get('pending_artifact_ids', []))}개")
    gen = resp_json.get("generated_artifacts", [])
    if gen:
        print(f"  생성 artifact(변환 safetensors): {len(gen)}개")


def main() -> int:
    # Windows 콘솔(cp949)에서도 UTF-8 출력이 깨지지 않게.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    p = argparse.ArgumentParser(description="실제 HF 모델 e2e 검증 데모")
    p.add_argument("repo_id", help="예: vmaca123/korean-pii-ner-v3")
    p.add_argument("--api", default=DEFAULT_API_BASE, help="프록시 base URL")
    p.add_argument("--revision", default="main")
    p.add_argument("--enable-path-b", action="store_true",
                   help="pickle Path B(Docker 샌드박스) 활성화 — runsc + 이미지 필요")
    p.add_argument("--skip-weights", action="store_true",
                   help="safetensors/pickle 가중치 제외(큰 파일 다운로드 생략)")
    p.add_argument("--weight-only", action="store_true",
                   help="/validation/jobs(가중치 전용) 사용. 기본은 /validation/full "
                        "(가중치+코드+config+화이트리스트+제한런타임 통합)")
    p.add_argument("--cache-dir", default=None, help="다운로드 캐시 경로")
    args = p.parse_args()

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("huggingface_hub가 필요합니다: pip install huggingface_hub", file=sys.stderr)
        return 1

    print(f"[1/3] '{args.repo_id}' 다운로드 중... (큰 모델은 시간이 걸립니다)")
    allow = None
    if args.skip_weights:
        # 가중치 제외 — 빠른 데모용. 작은 메타 파일만.
        allow = ["*.json", "*.txt", "*.py", "*.md"]
    local_dir = snapshot_download(
        repo_id=args.repo_id,
        revision=args.revision,
        cache_dir=args.cache_dir,
        allow_patterns=allow,
    )
    local_path = Path(local_dir)
    print(f"      → {local_path}")

    print("[2/3] 파일 분류 + sha256 계산 중...")
    artifacts = build_artifacts(local_path, args.repo_id, args.skip_weights)
    if not artifacts:
        print("검증 대상 artifact가 없습니다 (FileKind 매핑되는 파일 없음).", file=sys.stderr)
        return 1
    print(f"      → 검증 대상 {len(artifacts)}개")

    job = {
        "request_id": str(uuid.uuid4()),
        "job_id": str(uuid.uuid4()),
        "artifacts": artifacts,
        "enable_path_b": args.enable_path_b,
        "policy_fingerprint": "demo-cli-policy",
        "notes": f"e2e demo for {args.repo_id}",
    }

    endpoint = "jobs" if args.weight_only else "full"
    print(f"[3/3] POST {args.api}/internal/v1/validation/{endpoint} ...")
    with httpx.Client(timeout=300) as client:
        try:
            r = client.post(f"{args.api}/internal/v1/validation/{endpoint}", json=job)
            r.raise_for_status()
        except httpx.HTTPError as e:
            print(f"검증 요청 실패: {e}", file=sys.stderr)
            return 1

    print_report(r.json(), artifacts)
    print(f"\n대시보드: {args.api}/dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
