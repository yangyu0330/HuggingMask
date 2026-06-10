"""게이트가 특정 repo 의 config.json 을 왜 막는지 정확히 진단.

    python scripts/diag_gate.py
    DIAG_REPO=다른/repo python scripts/diag_gate.py

서버 venv 에서 실행. HF_ENDPOINT 를 제거해 실제 HF 로 직접 받는다(프록시 루프 배제).
config.json 의 실제 다운로드 내용 + validator 판정/사유/parse_error 를 그대로 출력.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# 레포 루트를 sys.path 에 추가(scripts/ 에서 실행해도 whitelist import 되게)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 진단은 항상 실제 HF 로 직접 — 프록시 루프 가능성 배제
for k in ("HF_ENDPOINT", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(k, None)

REPO = os.environ.get("DIAG_REPO", "hf-internal-testing/tiny-random-bert")
print(f"=== 진단 repo: {REPO} (HF_ENDPOINT 제거됨, 실 HF 직접) ===\n")

# 1) config.json 실제 내용이 유효한 JSON 인지 직접 확인
try:
    from huggingface_hub import hf_hub_download

    p = hf_hub_download(repo_id=REPO, filename="config.json")
    raw = open(p, "r", encoding="utf-8").read()
    print(f"[1] config.json 다운로드 OK ({len(raw)} bytes). 앞부분:")
    print("    " + raw[:200].replace("\n", "\n    "))
    try:
        json.loads(raw)
        print("    => 유효한 JSON ✅")
    except Exception as e:  # noqa: BLE001
        print(f"    => JSON 파싱 실패 ❌: {e}  (내용이 깨졌다는 뜻)")
except Exception as e:  # noqa: BLE001
    print(f"[1] config.json 다운로드 실패: {type(e).__name__}: {e}")

# 2) 게이트와 동일 경로(inspect)로 돌려 config.json 판정/사유 확인
print("\n[2] inspect_model_repo(skip_weights=True) 결과:")
os.environ.setdefault("DATABASE_URL", "sqlite:///./whitelist.db")
from whitelist.database import SessionLocal, init_db

init_db()
db = SessionLocal()
from whitelist.model_inspector import inspect_model_repo

out = inspect_model_repo(REPO, db=db, skip_weights=True)
if not out.get("ok"):
    print("   inspect NOT ok:", out.get("error_code"), out.get("error"))
    sys.exit(0)
resp = out["response"]
dec = getattr(resp, "overall_decision", None)
print("   overall_decision:", getattr(dec, "value", dec))
for r in resp.artifact_results:
    st = getattr(r.status, "value", r.status)
    codes = [getattr(e, "code", e) for e in (r.reason_entries or [])]
    print(f"\n   --- {r.artifact.file_name}  ->  {st}  {codes}")
    if r.artifact.file_name == "config.json":
        d = r.details or {}
        cs = d.get("config_scan") or {}
        print("       config_scan.schema_valid:", cs.get("schema_valid"))
        print("       config_scan.parse_error :", cs.get("parse_error"))
        print("       effective_status        :", d.get("effective_status"))
        print("       trigger_fields          :", d.get("trigger_fields"))
