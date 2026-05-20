"""
모듈 1: 공식 문서 크롤러 (mockable 추상 인터페이스 + regex 파서)

PyTorch / Transformers / NumPy 공식 문서에서 API 시그니처를 추출하여
화이트리스트 갱신 후보를 생성한다.

크롤링 결과는 직접 화이트리스트에 반영되지 않고, 분류기 + 보안 담당자
승인을 거친다 (engine.md:21 — block > allow > pending > unknown 우선순위).

보안 (상세설계 9.1절):
- HTTPS만 사용, TLS 인증서 검증 필수
- 도메인 화이트리스트 적용 (pytorch.org, huggingface.co, numpy.org 외 차단)
- 코드 실행 없이 텍스트/HTML 파싱만 수행
- 급격한 변화 탐지 (한 번에 100+개 API 추가 시 자동 플래그)

이 파일은 fetcher 추상 Protocol(``HttpFetcher``)을 받는다. 실제 HTTP 호출은
``mod1_real_crawler.py``의 ``HttpxFetcher``를 주입한다. 테스트는 in-memory
fixture를 주입.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from whitelist.rules import (
    ALLOWED_CRAWL_DOMAINS, CRAWL_SPIKE_THRESHOLD, CRAWL_TARGETS,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 타입 정의
# ─────────────────────────────────────────────

@dataclass
class ExtractedApi:
    """크롤링으로 추출된 API 정보"""
    full_path: str          # 예: torch.nn.functional.scaled_dot_product_attention
    namespace: str          # 예: torch.nn.functional
    source_url: str         # 추출 원본 URL
    version_tag: str = ""   # 예: "PyTorch 2.0"
    signature: str = ""     # 함수 시그니처 (있는 경우)


@dataclass
class CrawlResult:
    """한 번의 크롤링 실행 결과"""
    library: str
    crawled_at: datetime
    total_extracted: int
    new_apis: list[ExtractedApi]     # 기존 화이트리스트에 없는 API
    known_apis: list[str]            # 이미 등록된 API
    spike_detected: bool = False     # 급격한 변화 탐지
    errors: list[str] = field(default_factory=list)


class HttpFetcher(Protocol):
    """HTTP 요청 추상화 — 테스트 시 모킹 가능"""
    def get(self, url: str) -> str: ...


# ─────────────────────────────────────────────
# HTML 파싱 — 라이브러리별 regex 기반 (가벼움, 의존성 없음)
# 정확도가 더 필요하면 mod1_real_crawler의 BS4 파서를 사용.
# ─────────────────────────────────────────────

class PyTorchDocParser:
    """PyTorch 공식 문서 HTML에서 API 시그니처를 추출.

    대상: ``<dt id="torch.nn.Linear">`` 같은 Sphinx 패턴.
    """

    API_ID_PATTERN = re.compile(
        r'<dt\s+id="(torch\.[a-zA-Z0-9_.]+)"',
        re.MULTILINE,
    )
    VERSION_PATTERN = re.compile(
        r'(?:New|Added|Changed)\s+in\s+version\s+([\d.]+)',
        re.IGNORECASE,
    )

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        apis: list[ExtractedApi] = []
        seen: set[str] = set()
        for match in self.API_ID_PATTERN.finditer(html):
            full_path = match.group(1)
            if full_path in seen:
                continue
            seen.add(full_path)
            namespace = full_path.rsplit(".", 1)[0] if "." in full_path else full_path
            context = html[match.end():match.end() + 500]
            ver = self.VERSION_PATTERN.search(context)
            apis.append(ExtractedApi(
                full_path=full_path,
                namespace=namespace,
                source_url=source_url,
                version_tag=f"PyTorch {ver.group(1)}" if ver else "",
            ))
        return apis


class TransformersDocParser:
    """HuggingFace Transformers 문서 추출 (Markdown→HTML 렌더 후)."""

    API_PATTERN = re.compile(
        r'(?:id|name)="(transformers\.[a-zA-Z0-9_.]+)"',
        re.MULTILINE,
    )
    CODE_PATTERN = re.compile(
        r'<code[^>]*>(transformers\.[a-zA-Z0-9_.]+)</code>',
    )

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        apis: list[ExtractedApi] = []
        seen: set[str] = set()
        for pattern in (self.API_PATTERN, self.CODE_PATTERN):
            for match in pattern.finditer(html):
                full_path = match.group(1)
                if full_path in seen:
                    continue
                seen.add(full_path)
                namespace = full_path.rsplit(".", 1)[0] if "." in full_path else full_path
                apis.append(ExtractedApi(
                    full_path=full_path,
                    namespace=namespace,
                    source_url=source_url,
                ))
        return apis


class NumpyDocParser:
    """NumPy 공식 문서 추출 (Sphinx 기반)."""

    API_PATTERN = re.compile(
        r'<dt\s+id="(numpy\.[a-zA-Z0-9_.]+)"',
        re.MULTILINE,
    )

    def extract(self, html: str, source_url: str) -> list[ExtractedApi]:
        apis: list[ExtractedApi] = []
        seen: set[str] = set()
        for match in self.API_PATTERN.finditer(html):
            full_path = match.group(1)
            if full_path in seen:
                continue
            seen.add(full_path)
            namespace = full_path.rsplit(".", 1)[0] if "." in full_path else full_path
            apis.append(ExtractedApi(
                full_path=full_path,
                namespace=namespace,
                source_url=source_url,
            ))
        return apis


# ─────────────────────────────────────────────
# 크롤러 메인 클래스
# ─────────────────────────────────────────────

PARSERS = {
    "pytorch":      PyTorchDocParser(),
    "transformers": TransformersDocParser(),
    "numpy":        NumpyDocParser(),
}


class OfficialDocCrawler:
    """공식 문서 크롤러 — 모듈 1 메인 클래스.

    사용 예::

        crawler = OfficialDocCrawler(fetcher=my_fetcher)
        result = crawler.crawl_library("pytorch", existing_apis={"torch.nn.Linear"})
    """

    def __init__(self, fetcher: HttpFetcher) -> None:
        self._fetcher = fetcher

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
        parser = PARSERS.get(library)
        if not parser:
            return CrawlResult(
                library=library, crawled_at=datetime.now(timezone.utc),
                total_extracted=0, new_apis=[], known_apis=[],
                errors=[f"No parser for: {library}"],
            )

        all_extracted: list[ExtractedApi] = []
        errors: list[str] = []
        for page in config["pages"]:
            url = config["base_url"] + page
            if not self._is_allowed_domain(url):
                errors.append(f"도메인 차단: {url}")
                continue
            try:
                html = self._fetcher.get(url)
                apis = parser.extract(html, url)
                all_extracted.extend(apis)
                logger.info("크롤링 완료: %s → %d개 API", url, len(apis))
            except Exception as e:
                errors.append(f"크롤링 실패: {url} — {e}")
                logger.error("크롤링 실패: %s — %s", url, e)

        new_apis = [a for a in all_extracted if a.full_path not in existing_apis]
        known = [a.full_path for a in all_extracted if a.full_path in existing_apis]
        spike = len(new_apis) > CRAWL_SPIKE_THRESHOLD
        if spike:
            logger.warning(
                "급격한 변화 탐지: %s에서 %d개 신규 API (임계값 %d)",
                library, len(new_apis), CRAWL_SPIKE_THRESHOLD,
            )
        return CrawlResult(
            library=library, crawled_at=datetime.now(timezone.utc),
            total_extracted=len(all_extracted),
            new_apis=new_apis, known_apis=known,
            spike_detected=spike, errors=errors,
        )

    def crawl_all(self, existing_apis: set[str]) -> list[CrawlResult]:
        return [self.crawl_library(lib, existing_apis) for lib in CRAWL_TARGETS]

    @staticmethod
    def _is_allowed_domain(url: str) -> bool:
        """정확 도메인 또는 dot-경계 하위 도메인만 허용.

        단순 ``host.endswith(d)``는 ``pytorch.org`` 허용 시 ``evilpytorch.org``
        같은 suffix 우회 도메인도 통과시키는 취약점이 있다. 정확 매칭 + dot
        경계로 강화 (양유상 PR #16 리뷰, 2026-05-06).
        """
        from urllib.parse import urlparse
        try:
            host = urlparse(url).hostname or ""
            return any(
                host == d or host.endswith("." + d)
                for d in ALLOWED_CRAWL_DOMAINS
            )
        except Exception:
            return False


# ─────────────────────────────────────────────
# 안전도 분류 적용 — engine._Classifier 재사용
# ─────────────────────────────────────────────

def classify_crawled_apis(
    new_apis: list[ExtractedApi],
) -> dict[str, list[ExtractedApi]]:
    """크롤링 결과를 우리 엔진 분류기로 분류.

    Returns:
        {"AUTO_APPROVE": [...], "CONDITIONAL": [...], "MANUAL": [...], "BLOCKED": [...]}

    bucket 키는 ``PendingClassification`` enum value 그대로.
    """
    from whitelist.engine import _Classifier
    classifier = _Classifier()
    buckets: dict[str, list[ExtractedApi]] = {
        "AUTO_APPROVE": [], "CONDITIONAL": [], "MANUAL": [], "BLOCKED": [],
    }
    for api in new_apis:
        base, _matched = classifier.match_namespace(api.full_path)
        risks = classifier.find_risk_keywords(api.full_path)
        final = classifier.escalate(base, risks)
        buckets[final.value].append(api)
    return buckets


__all__ = [
    "ExtractedApi", "CrawlResult", "HttpFetcher",
    "PyTorchDocParser", "TransformersDocParser", "NumpyDocParser",
    "OfficialDocCrawler", "classify_crawled_apis", "PARSERS",
]
