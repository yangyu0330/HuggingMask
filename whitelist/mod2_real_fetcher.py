"""
모듈 2 실제 HuggingFace API 구현체

HuggingFace Hub API를 호출하여 Verified Org의 인기 모델 .py 파일과
config.json을 수집한 뒤 ``VerifiedOrgAnalyzer``에 위임한다.

캐시 위치: ``data/org_analysis_cache/latest_analysis.json`` —
다른 모듈(``cache_loader.py``)에서 PendingApi에 자동 채워주기 위해 읽는다.

CLI 진입점::

    python -m whitelist.mod2_real_fetcher --models 5
    python -m whitelist.mod2_real_fetcher --org meta-llama
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from whitelist.mod2_verified_org import (
    ApiUsage, HfApiFetcher, OrgAnalysisResult, VerifiedOrgAnalyzer,
    aggregate_org_results,
)
from whitelist.rules import VERIFIED_ORGANIZATIONS


logger = logging.getLogger(__name__)


HF_API_BASE = "https://huggingface.co/api"
HF_RAW_BASE = "https://huggingface.co"


# ─────────────────────────────────────────────
# 실제 HuggingFace Hub API 클라이언트
# ─────────────────────────────────────────────

class HuggingFaceApiFetcher:
    """HuggingFace Hub API 호출 (HTTPS + rate limit + 토큰 옵션)."""

    def __init__(
        self,
        token: str | None = None,
        timeout: float = 30.0,
        rate_limit: float = 1.0,
    ) -> None:
        headers = {
            "User-Agent": "HuggingMask-AdaptiveWhitelist/1.0",
            "Accept": "application/json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            timeout=timeout, verify=True, headers=headers,
        )
        self._rate_limit = rate_limit
        self._last_req = 0.0

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_req
        if elapsed < self._rate_limit:
            time.sleep(self._rate_limit - elapsed)
        self._last_req = time.time()

    def list_models(self, org_id: str, limit: int = 10) -> list[dict]:
        """조직의 모델 목록 (다운로드 수 내림차순) + 파일 목록."""
        self._throttle()
        url = f"{HF_API_BASE}/models"
        params = {
            "author": org_id, "sort": "downloads",
            "direction": "-1", "limit": limit,
        }
        response = self._client.get(url, params=params)
        response.raise_for_status()
        models_data = response.json()

        results: list[dict] = []
        for model in models_data:
            model_id = model.get("id", "")
            if not model_id:
                continue
            files = self._get_model_files(model_id)
            results.append({
                "id": model_id,
                "files": files,
                "downloads": model.get("downloads", 0),
                "tags": model.get("tags", []),
            })
        logger.info("조직 %s: %d개 모델 조회", org_id, len(results))
        return results

    def _get_model_files(self, model_id: str) -> list[str]:
        self._throttle()
        url = f"{HF_API_BASE}/models/{model_id}"
        try:
            response = self._client.get(url)
            response.raise_for_status()
            data = response.json()
            siblings = data.get("siblings", [])
            return [s.get("rfilename", "") for s in siblings if s.get("rfilename")]
        except Exception as e:
            logger.warning("파일 목록 조회 실패: %s — %s", model_id, e)
            return []

    def get_file(self, model_id: str, filename: str) -> str:
        """모델 저장소의 raw 파일 내용 (1MB 상한)."""
        self._throttle()
        url = f"{HF_RAW_BASE}/{model_id}/raw/main/{filename}"
        response = self._client.get(url)
        response.raise_for_status()
        if len(response.text) > 1_000_000:
            logger.warning(
                "파일 크기 초과: %s/%s (%d bytes)",
                model_id, filename, len(response.text),
            )
            return ""
        return response.text

    def close(self) -> None:
        self._client.close()


# ─────────────────────────────────────────────
# 통합 production 분석기
# ─────────────────────────────────────────────

DEFAULT_CACHE_DIR = "data/org_analysis_cache"


class RealOrgAnalyzer:
    """HuggingFaceApiFetcher + VerifiedOrgAnalyzer + 캐시 저장."""

    def __init__(
        self,
        hf_token: str | None = None,
        model_limit: int = 5,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
    ) -> None:
        self._fetcher = HuggingFaceApiFetcher(token=hf_token)
        self._analyzer = VerifiedOrgAnalyzer(self._fetcher)
        self._model_limit = model_limit
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def analyze_single_org(self, org_id: str) -> OrgAnalysisResult:
        return self._analyzer.analyze_org(org_id, model_limit=self._model_limit)

    def analyze_all_orgs(self) -> list[OrgAnalysisResult]:
        return self._analyzer.analyze_all_orgs(model_limit=self._model_limit)

    def analyze_all_and_aggregate(
        self, existing_whitelist: set[str],
    ) -> dict:
        results = self.analyze_all_orgs()
        unregistered = aggregate_org_results(results, existing_whitelist)
        summary = {
            "orgs_analyzed": len(results),
            "total_models": sum(len(r.models_analyzed) for r in results),
            "total_apis_found": sum(len(r.apis_found) for r in results),
            "unregistered_apis": len(unregistered),
            "top_unregistered": [
                {
                    "api": u.api_path,
                    "org_count": len(u.used_by_orgs),
                    "orgs": u.used_by_orgs,
                }
                for u in unregistered[:20]
            ],
            "errors": sum(len(r.errors) for r in results),
        }
        self._save_cache(results, unregistered, summary)
        return {
            "org_results": results,
            "unregistered_apis": unregistered,
            "summary": summary,
        }

    def _save_cache(
        self,
        results: list[OrgAnalysisResult],
        unregistered: list[ApiUsage],
        summary: dict,
    ) -> None:
        cache_data = {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "org_details": [
                {
                    "org_id": r.org_id,
                    "org_name": r.org_name,
                    "models": r.models_analyzed,
                    "api_count": len(r.apis_found),
                    "top_apis": sorted(
                        r.apis_found.items(), key=lambda x: x[1], reverse=True
                    )[:50],
                    "errors": r.errors,
                }
                for r in results
            ],
            "unregistered_apis": [
                {
                    "api_path": u.api_path,
                    "used_by_orgs": u.used_by_orgs,
                    "used_by_models": u.used_by_models[:5],
                    "total_count": u.total_count,
                }
                for u in unregistered
            ],
        }
        path = self._cache_dir / "latest_analysis.json"
        path.write_text(
            json.dumps(cache_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("분석 결과 캐시 저장: %s", path)

    def close(self) -> None:
        self._fetcher.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    p = argparse.ArgumentParser(description="HuggingMask Mod2 — Verified Org 분석기")
    p.add_argument("--org", help="특정 조직만 분석 (예: meta-llama)")
    p.add_argument("--models", type=int, default=5, help="조직당 분석할 모델 수")
    p.add_argument("--token", help="HuggingFace API 토큰 (선택)")
    p.add_argument("--output", default="data/org_analysis_output.json")
    p.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    args = p.parse_args()

    from whitelist.seed import ALL_SEED_APIS
    existing = set(ALL_SEED_APIS)

    with RealOrgAnalyzer(
        hf_token=args.token,
        model_limit=args.models,
        cache_dir=args.cache_dir,
    ) as analyzer:
        if args.org:
            result = analyzer.analyze_single_org(args.org)
            print(f"\n조직: {result.org_name}")
            print(f"분석 모델: {len(result.models_analyzed)}개")
            print(f"발견 API: {len(result.apis_found)}개")
            if result.errors:
                print(f"오류: {len(result.errors)}건")
            top = sorted(result.apis_found.items(), key=lambda x: x[1], reverse=True)[:20]
            print("\n상위 API:")
            for api, count in top:
                marker = "OK" if api in existing else " ?"
                print(f"  [{marker}] {api} ({count}회)")
        else:
            output = analyzer.analyze_all_and_aggregate(existing)
            summary = output["summary"]
            print("=" * 60)
            print(f"  분석 완료")
            print(f"  조직: {summary['orgs_analyzed']}개")
            print(f"  모델: {summary['total_models']}개")
            print(f"  발견 API: {summary['total_apis_found']}개")
            print(f"  미등록: {summary['unregistered_apis']}개")
            print(f"  오류: {summary['errors']}건")
            print(f"\n  미등록 API Top 10:")
            for item in summary["top_unregistered"][:10]:
                print(f"    {item['api']} — {item['org_count']}개 조직: {item['orgs']}")
            print("=" * 60)

            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps({"summary": summary}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"  결과 저장: {args.output}")


if __name__ == "__main__":
    main()
