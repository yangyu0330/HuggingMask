"""
모듈 1 실제 크롤링 구현체 — httpx + BeautifulSoup

PyTorch / Transformers / NumPy 공식 문서를 실제 HTTP로 크롤하고 BS4로
정밀 파싱한다. ``mod1_doc_crawler``의 추상 인터페이스 위에 production
구현을 얹은 것이다.

CLI 진입점::

    python -m whitelist.mod1_real_crawler --library all --cache-dir data/crawl_cache

캐시:
- HTML 응답을 ``data/crawl_cache/<sha16>.json``으로 저장 (TTL 7일)
- 같은 URL 재요청 시 캐시 hit으로 외부 요청 절약
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup, Tag

from whitelist.mod1_doc_crawler import (
    CrawlResult, ExtractedApi, OfficialDocCrawler,
    classify_crawled_apis,
)
from whitelist.rules import (
    ALLOWED_CRAWL_DOMAINS, CRAWL_SPIKE_THRESHOLD, CRAWL_TARGETS,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 실제 HTTP 클라이언트
# ─────────────────────────────────────────────

class HttpxFetcher:
    """httpx 기반 production HTTP fetcher.

    보안 (상세설계 9.1절):
      - HTTPS만 허용 (scheme 강제)
      - TLS 인증서 검증 (verify=True)
      - 도메인 화이트리스트 (rules.ALLOWED_CRAWL_DOMAINS)
      - 타임아웃, rate limiting, 재시도
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        rate_limit_delay: float = 1.0,
    ) -> None:
        self._client = httpx.Client(
            timeout=timeout,
            verify=True,
            follow_redirects=True,
            headers={
                "User-Agent": "HuggingMask-AdaptiveWhitelist/1.0 (security-research)",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

    def get(self, url: str) -> str:
        """HTML 콘텐츠 반환. 도메인/스킴 검증 + rate limit + 재시도."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"HTTPS만 허용: {url}")
        host = parsed.hostname or ""
        # 정확 도메인 또는 dot-경계 하위 도메인만 허용 — suffix 우회 방어
        # (양유상 PR #16 리뷰, 2026-05-06): host.endswith("pytorch.org")만 쓰면
        # "evilpytorch.org"도 통과하는 취약점이 있다.
        if not any(
            host == d or host.endswith("." + d)
            for d in ALLOWED_CRAWL_DOMAINS
        ):
            raise ValueError(f"허용되지 않은 도메인: {host}")

        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)

        last_error: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._client.get(url)
                response.raise_for_status()
                self._last_request_time = time.time()
                logger.info(
                    "GET %s → %d (%d bytes)",
                    url, response.status_code, len(response.text),
                )
                return response.text
            except httpx.HTTPError as e:
                last_error = e
                logger.warning(
                    "GET %s 실패 (시도 %d/%d): %s",
                    url, attempt, self._max_retries, e,
                )
                if attempt < self._max_retries:
                    time.sleep(self._retry_delay * attempt)
        assert last_error is not None
        raise last_error

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ─────────────────────────────────────────────
# BeautifulSoup 정밀 파서
# ─────────────────────────────────────────────

class PyTorchSoupParser:
    """PyTorch Sphinx 문서를 정밀 파싱."""

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        soup = BeautifulSoup(html, "lxml")
        apis: list[ExtractedApi] = []
        seen: set[str] = set()

        for dt in soup.find_all("dt"):
            dt_id = dt.get("id", "")
            if not dt_id or not self._is_valid_api_path(dt_id) or dt_id in seen:
                continue
            seen.add(dt_id)
            namespace = dt_id.rsplit(".", 1)[0] if "." in dt_id else dt_id
            apis.append(ExtractedApi(
                full_path=dt_id,
                namespace=namespace,
                source_url=source_url,
                version_tag=self._extract_version_info(dt),
                signature=self._extract_signature(dt),
            ))

        for dl in soup.find_all(
            "dl", class_=re.compile(r"py\s+(function|class|method|attribute)"),
        ):
            for dt in dl.find_all("dt", recursive=False):
                dt_id = dt.get("id", "")
                if dt_id and self._is_valid_api_path(dt_id) and dt_id not in seen:
                    seen.add(dt_id)
                    apis.append(ExtractedApi(
                        full_path=dt_id,
                        namespace=dt_id.rsplit(".", 1)[0],
                        source_url=source_url,
                        version_tag=self._extract_version_info(dt),
                        signature=self._extract_signature(dt),
                    ))
        logger.info("PyTorch 파서: %s에서 %d개 API 추출", source_url, len(apis))
        return apis

    @staticmethod
    def _is_valid_api_path(path: str) -> bool:
        if not path or not (path.startswith("torch.") or path.startswith("numpy.")):
            return False
        if path.count(".") < 1:
            return False
        return bool(re.match(r"^[a-zA-Z0-9_.]+$", path))

    @staticmethod
    def _extract_version_info(dt_tag: Tag) -> str:
        parent = dt_tag.find_parent("dl")
        if not parent:
            return ""
        for div in parent.find_all("div", class_=re.compile(r"version(added|changed)")):
            text = div.get_text(strip=True)
            match = re.search(r"version\s+([\d.]+)", text)
            if match:
                return f"PyTorch {match.group(1)}"
        return ""

    @staticmethod
    def _extract_signature(dt_tag: Tag) -> str:
        text = dt_tag.get_text(strip=True)
        return text if "(" in text else ""


class TransformersSoupParser:
    """HuggingFace Transformers 문서 파싱."""

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        soup = BeautifulSoup(html, "lxml")
        apis: list[ExtractedApi] = []
        seen: set[str] = set()

        for heading in soup.find_all(["h2", "h3", "h4"]):
            h_id = heading.get("id", "")
            if h_id and h_id.startswith("transformers.") and h_id not in seen:
                if self._is_valid_path(h_id):
                    seen.add(h_id)
                    apis.append(ExtractedApi(
                        full_path=h_id,
                        namespace=h_id.rsplit(".", 1)[0],
                        source_url=source_url,
                    ))

        for a_tag in soup.find_all("a", id=True):
            a_id = a_tag["id"]
            if (
                a_id.startswith("transformers.")
                and a_id not in seen
                and self._is_valid_path(a_id)
            ):
                seen.add(a_id)
                apis.append(ExtractedApi(
                    full_path=a_id,
                    namespace=a_id.rsplit(".", 1)[0],
                    source_url=source_url,
                ))

        for div in soup.find_all("div", class_="docstring"):
            header = div.find(["h3", "h4", "strong"])
            if header:
                text = header.get_text(strip=True)
                match = re.search(r"(transformers\.[a-zA-Z0-9_.]+)", text)
                if match and match.group(1) not in seen:
                    path = match.group(1)
                    seen.add(path)
                    apis.append(ExtractedApi(
                        full_path=path,
                        namespace=path.rsplit(".", 1)[0],
                        source_url=source_url,
                    ))
        logger.info("Transformers 파서: %s에서 %d개 API 추출", source_url, len(apis))
        return apis

    @staticmethod
    def _is_valid_path(path: str) -> bool:
        if not path.startswith("transformers."):
            return False
        if path.count(".") < 1:
            return False
        return bool(re.match(r"^[a-zA-Z0-9_.]+$", path))


class NumpySoupParser:
    """NumPy Sphinx 문서 파싱 (PyTorch와 유사)."""

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        soup = BeautifulSoup(html, "lxml")
        apis: list[ExtractedApi] = []
        seen: set[str] = set()
        for dt in soup.find_all("dt"):
            dt_id = dt.get("id", "")
            if (
                dt_id and dt_id.startswith("numpy.")
                and dt_id not in seen
                and re.match(r"^[a-zA-Z0-9_.]+$", dt_id)
            ):
                seen.add(dt_id)
                apis.append(ExtractedApi(
                    full_path=dt_id,
                    namespace=dt_id.rsplit(".", 1)[0],
                    source_url=source_url,
                ))
        logger.info("NumPy 파서: %s에서 %d개 API 추출", source_url, len(apis))
        return apis


# ─────────────────────────────────────────────
# 캐시 — TTL 기반 JSON 저장
# ─────────────────────────────────────────────

class CrawlCache:
    """크롤링 결과를 로컬 JSON으로 캐시 (TTL 7일)."""

    def __init__(self, cache_dir: str | Path = "data/crawl_cache") -> None:
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _key(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def get(self, url: str, ttl_hours: int = 168) -> str | None:
        path = self._dir / f"{self._key(url)}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        cached_at = datetime.fromisoformat(data["cached_at"])
        age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
        if age_hours > ttl_hours:
            return None
        return data["html"]

    def put(self, url: str, html: str) -> None:
        path = self._dir / f"{self._key(url)}.json"
        data = {
            "url": url,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "html": html,
        }
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


class CachedFetcher:
    """캐시 레이어를 씌운 Fetcher (decorator 패턴)."""

    def __init__(self, fetcher: HttpxFetcher, cache: CrawlCache) -> None:
        self._fetcher = fetcher
        self._cache = cache

    def get(self, url: str) -> str:
        cached = self._cache.get(url)
        if cached:
            logger.info("캐시 히트: %s", url)
            return cached
        html = self._fetcher.get(url)
        self._cache.put(url, html)
        return html


# ─────────────────────────────────────────────
# 통합 production 크롤러
# ─────────────────────────────────────────────

SOUP_PARSERS = {
    "pytorch":      PyTorchSoupParser(),
    "transformers": TransformersSoupParser(),
    "numpy":        NumpySoupParser(),
}


class RealDocCrawler:
    """실제 production 크롤러 — fetcher + cache + soup 파서 통합."""

    def __init__(
        self,
        cache_dir: str | Path = "data/crawl_cache",
        timeout: float = 30.0,
        rate_limit: float = 1.5,
    ) -> None:
        self._fetcher = HttpxFetcher(
            timeout=timeout,
            rate_limit_delay=rate_limit,
        )
        self._cache = CrawlCache(cache_dir)
        self._cached_fetcher = CachedFetcher(self._fetcher, self._cache)

    def crawl_library(
        self, library: str, existing_apis: set[str],
    ) -> CrawlResult:
        if library not in CRAWL_TARGETS:
            return CrawlResult(
                library=library, crawled_at=datetime.now(timezone.utc),
                total_extracted=0, new_apis=[], known_apis=[],
                errors=[f"Unknown library: {library}"],
            )
        config = CRAWL_TARGETS[library]
        parser = SOUP_PARSERS.get(library)
        if not parser:
            return CrawlResult(
                library=library, crawled_at=datetime.now(timezone.utc),
                total_extracted=0, new_apis=[], known_apis=[],
                errors=[f"No parser: {library}"],
            )

        all_extracted: list[ExtractedApi] = []
        errors: list[str] = []
        for page in config["pages"]:
            url = config["base_url"] + page
            try:
                html = self._cached_fetcher.get(url)
                apis = parser.extract(html, url)
                all_extracted.extend(apis)
            except Exception as e:
                errors.append(f"{url}: {e}")
                logger.error("크롤링 실패: %s — %s", url, e)

        new_apis = [a for a in all_extracted if a.full_path not in existing_apis]
        known = [a.full_path for a in all_extracted if a.full_path in existing_apis]
        spike = len(new_apis) > CRAWL_SPIKE_THRESHOLD
        if spike:
            logger.warning(
                "SPIKE: %s — %d개 신규 API (임계값 %d)",
                library, len(new_apis), CRAWL_SPIKE_THRESHOLD,
            )
        return CrawlResult(
            library=library, crawled_at=datetime.now(timezone.utc),
            total_extracted=len(all_extracted),
            new_apis=new_apis, known_apis=known,
            spike_detected=spike, errors=errors,
        )

    def crawl_all(self, existing_apis: set[str]) -> list[CrawlResult]:
        results: list[CrawlResult] = []
        for lib in CRAWL_TARGETS:
            logger.info("=== 크롤링 시작: %s ===", lib)
            result = self.crawl_library(lib, existing_apis)
            results.append(result)
            logger.info(
                "=== %s 완료: 전체 %d개, 신규 %d개, 오류 %d개 ===",
                lib, result.total_extracted,
                len(result.new_apis), len(result.errors),
            )
        return results

    def crawl_and_classify(self, existing_apis: set[str]) -> dict[str, Any]:
        results = self.crawl_all(existing_apis)
        all_new: list[ExtractedApi] = []
        for r in results:
            all_new.extend(r.new_apis)
        classified = classify_crawled_apis(all_new)
        summary = {
            "total_crawled": sum(r.total_extracted for r in results),
            "total_new": len(all_new),
            "auto_approve": len(classified.get("AUTO_APPROVE", [])),
            "conditional": len(classified.get("CONDITIONAL", [])),
            "manual": len(classified.get("MANUAL", [])),
            "blocked": len(classified.get("BLOCKED", [])),
            "spike_detected": any(r.spike_detected for r in results),
            "errors": sum(len(r.errors) for r in results),
        }
        return {
            "crawl_results": results,
            "classified": classified,
            "summary": summary,
        }

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

    p = argparse.ArgumentParser(
        description="HuggingMask Mod1 — 공식 문서 크롤러",
    )
    p.add_argument(
        "--library", choices=["pytorch", "transformers", "numpy", "all"],
        default="all",
    )
    p.add_argument("--cache-dir", default="data/crawl_cache")
    p.add_argument("--output", default="data/crawl_output.json")
    p.add_argument(
        "--apply", action="store_true",
        help="크롤 결과 중 AUTO_APPROVE 분류 API를 ApprovedApi(source=AUTO_CRAWL)로 자동 등록",
    )
    p.add_argument(
        "--apply-classifications",
        default="AUTO_APPROVE",
        help="자동 등록 허용 분류 (콤마 구분, 예: AUTO_APPROVE,CONDITIONAL)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="--apply 와 함께 사용 시 실제 DB 변경 없이 카운트만 보고",
    )
    args = p.parse_args()

    from whitelist.seed import ALL_SEED_APIS
    existing = set(ALL_SEED_APIS)

    with RealDocCrawler(cache_dir=args.cache_dir) as crawler:
        if args.library == "all":
            output = crawler.crawl_and_classify(existing)
        else:
            result = crawler.crawl_library(args.library, existing)
            output = {
                "crawl_results": [result],
                "summary": {
                    "total_crawled": result.total_extracted,
                    "total_new": len(result.new_apis),
                    "errors": len(result.errors),
                },
            }

    summary = output.get("summary", {})
    print("=" * 60)
    print(f"  크롤링 완료")
    print(f"  전체: {summary.get('total_crawled', 0)}개")
    print(f"  신규: {summary.get('total_new', 0)}개")
    if "auto_approve" in summary:
        print(f"    자동 승인: {summary['auto_approve']}개")
        print(f"    조건부:    {summary['conditional']}개")
        print(f"    수동 리뷰: {summary['manual']}개")
        print(f"    차단:      {summary['blocked']}개")
    print(f"  오류: {summary.get('errors', 0)}건")
    print("=" * 60)

    serializable = {
        "summary": summary,
        "new_apis": [
            {
                "full_path": api.full_path,
                "namespace": api.namespace,
                "source_url": api.source_url,
                "version_tag": api.version_tag,
            }
            for r in output["crawl_results"]
            for api in r.new_apis
        ],
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(serializable, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  결과 저장: {args.output}")

    # ── --apply: ApprovedApi에 자동 등록 ──
    if args.apply and "classified" in output:
        from whitelist.cache_loader import apply_crawl_results_to_db
        from whitelist.database import SessionLocal, init_db

        init_db()
        allow = [c.strip().upper() for c in args.apply_classifications.split(",") if c.strip()]
        db = SessionLocal()
        try:
            counts = apply_crawl_results_to_db(
                output["classified"], db,
                allow_classifications=allow,
                dry_run=args.dry_run,
            )
            if not args.dry_run:
                db.commit()
        finally:
            db.close()
        print("=" * 60)
        print(f"  ApprovedApi 자동 등록 ({'dry-run' if args.dry_run else 'applied'}):")
        print(f"    added:           {counts['added']}")
        print(f"    skipped:         {counts['skipped']}")
        print(f"    blocked_by_perm: {counts['blocked_by_perm']}")
        print("=" * 60)


if __name__ == "__main__":
    main()
