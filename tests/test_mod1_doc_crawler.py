"""
모듈 1 doc crawler 단위 테스트 (regex 파서 + 추상 OfficialDocCrawler).

httpx 실제 네트워크는 사용하지 않는다. ``HttpFetcher`` Protocol을 만족하는
in-memory dict fetcher를 주입.
"""

from dataclasses import dataclass

import pytest

from whitelist.mod1_doc_crawler import (
    CrawlResult, ExtractedApi, NumpyDocParser, OfficialDocCrawler,
    PyTorchDocParser, TransformersDocParser, classify_crawled_apis,
)


@dataclass
class FakeFetcher:
    """url → html 매핑을 들고 있는 mock fetcher."""
    pages: dict[str, str]

    def get(self, url: str) -> str:
        if url not in self.pages:
            raise KeyError(f"no fixture for {url}")
        return self.pages[url]


# ─────────────────────────────────────────────
# regex 파서 정확성
# ─────────────────────────────────────────────

class TestPyTorchParser:

    def test_extract_basic(self):
        html = '''
        <dt id="torch.nn.Linear"><em>class</em> torch.nn.Linear</dt>
        <dt id="torch.nn.functional.relu"></dt>
        '''
        apis = PyTorchDocParser().extract(html, "https://pytorch.org/x")
        paths = {a.full_path for a in apis}
        assert "torch.nn.Linear" in paths
        assert "torch.nn.functional.relu" in paths

    def test_extract_with_version(self):
        html = '''<dt id="torch.nn.NewLayer">def</dt>
        <p>New in version 2.5</p>'''
        apis = PyTorchDocParser().extract(html, "url")
        assert len(apis) == 1
        assert apis[0].version_tag == "PyTorch 2.5"

    def test_namespace_split(self):
        html = '<dt id="torch.nn.Linear"></dt>'
        apis = PyTorchDocParser().extract(html, "url")
        assert apis[0].namespace == "torch.nn"

    def test_dedup(self):
        html = '<dt id="torch.foo"></dt><dt id="torch.foo"></dt>'
        apis = PyTorchDocParser().extract(html, "url")
        assert len(apis) == 1


class TestTransformersParser:

    def test_extract_id_attribute(self):
        html = '<h2 id="transformers.AutoModel">Auto Model</h2>'
        apis = TransformersDocParser().extract(html, "url")
        assert any(a.full_path == "transformers.AutoModel" for a in apis)

    def test_extract_code_block(self):
        html = '<code>transformers.AutoTokenizer</code>'
        apis = TransformersDocParser().extract(html, "url")
        assert any(a.full_path == "transformers.AutoTokenizer" for a in apis)


class TestNumpyParser:

    def test_extract_basic(self):
        html = '<dt id="numpy.array"></dt><dt id="numpy.zeros"></dt>'
        apis = NumpyDocParser().extract(html, "url")
        paths = {a.full_path for a in apis}
        assert paths == {"numpy.array", "numpy.zeros"}


# ─────────────────────────────────────────────
# OfficialDocCrawler — mock fetcher 주입
# ─────────────────────────────────────────────

class TestOfficialDocCrawler:

    def _crawler(self, pages: dict[str, str]) -> OfficialDocCrawler:
        return OfficialDocCrawler(fetcher=FakeFetcher(pages=pages))

    def test_unknown_library_returns_error(self):
        crawler = self._crawler({})
        result = crawler.crawl_library("unknown-lib", existing_apis=set())
        assert result.errors
        assert "Unknown library" in result.errors[0]

    def test_pytorch_crawl_returns_extracted(self):
        # CRAWL_TARGETS["pytorch"]의 첫 페이지 URL 시뮬레이트
        from whitelist.rules import CRAWL_TARGETS
        url = CRAWL_TARGETS["pytorch"]["base_url"] + CRAWL_TARGETS["pytorch"]["pages"][0]
        html = '<dt id="torch.nn.Linear"></dt><dt id="torch.nn.NewLayer"></dt>'
        crawler = self._crawler({url: html})
        result = crawler.crawl_library("pytorch", existing_apis={"torch.nn.Linear"})
        # other 페이지는 fetcher가 KeyError로 errors에 누적되지만 첫 페이지는 성공
        assert "torch.nn.NewLayer" in {a.full_path for a in result.new_apis}
        assert "torch.nn.Linear" in result.known_apis

    def test_disallowed_domain_blocked(self):
        # 도메인 화이트리스트 외 — 가짜 URL을 직접 만들 수는 없으니
        # _is_allowed_domain 단위 검증
        assert not OfficialDocCrawler._is_allowed_domain("https://evil.example.com/x")
        assert OfficialDocCrawler._is_allowed_domain("https://pytorch.org/docs")
        assert OfficialDocCrawler._is_allowed_domain("https://huggingface.co/x")
        assert OfficialDocCrawler._is_allowed_domain("https://numpy.org/x")

    def test_spike_detection(self):
        from whitelist.rules import CRAWL_SPIKE_THRESHOLD, CRAWL_TARGETS
        url = CRAWL_TARGETS["pytorch"]["base_url"] + CRAWL_TARGETS["pytorch"]["pages"][0]
        # spike threshold 보다 많은 dt 만들기
        ids = [f"torch.nn.New{i}" for i in range(CRAWL_SPIKE_THRESHOLD + 5)]
        html = "".join(f'<dt id="{i}"></dt>' for i in ids)
        crawler = self._crawler({url: html})
        result = crawler.crawl_library("pytorch", existing_apis=set())
        assert result.spike_detected


# ─────────────────────────────────────────────
# classify_crawled_apis — 우리 엔진 분류기 통합
# ─────────────────────────────────────────────

class TestClassifyCrawledApis:

    def _api(self, path: str) -> ExtractedApi:
        ns = path.rsplit(".", 1)[0] if "." in path else path
        return ExtractedApi(full_path=path, namespace=ns, source_url="x")

    def test_torch_nn_is_auto_approve(self):
        result = classify_crawled_apis([self._api("torch.nn.SomeNew")])
        assert any(a.full_path == "torch.nn.SomeNew" for a in result["AUTO_APPROVE"])

    def test_pickle_is_blocked(self):
        result = classify_crawled_apis([self._api("pickle.something")])
        assert any(a.full_path == "pickle.something" for a in result["BLOCKED"])

    def test_load_keyword_escalates_to_manual(self):
        # torch.nn.* 매칭이지만 'load' 키워드 → MANUAL 격상
        result = classify_crawled_apis([self._api("torch.nn.Module.load_state_dict")])
        assert any(
            a.full_path == "torch.nn.Module.load_state_dict"
            for a in result["MANUAL"]
        )

    def test_unknown_namespace_is_manual(self):
        result = classify_crawled_apis([self._api("my_lib.SomeThing")])
        assert any(a.full_path == "my_lib.SomeThing" for a in result["MANUAL"])
