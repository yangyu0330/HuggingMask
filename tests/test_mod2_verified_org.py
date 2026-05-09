"""
모듈 2 verified org 단위 테스트.

PythonApiExtractor / extract_apis_from_config / VerifiedOrgAnalyzer (mock fetcher)
/ aggregate_org_results 회귀.
"""

import json

import pytest

from whitelist.mod2_verified_org import (
    PythonApiExtractor, VerifiedOrgAnalyzer, aggregate_org_results,
    extract_apis_from_config,
)


# ─────────────────────────────────────────────
# PythonApiExtractor
# ─────────────────────────────────────────────

class TestPythonApiExtractor:

    def test_import_simple(self):
        e = PythonApiExtractor()
        apis = e.extract_imports("import torch\nimport numpy as np\n")
        assert "torch" in apis
        assert "numpy" in apis  # asname은 import 자체엔 영향 없고 alias_map에서 처리

    def test_import_from(self):
        e = PythonApiExtractor()
        apis = e.extract_imports("from torch import nn, optim\n")
        assert "torch.nn" in apis
        assert "torch.optim" in apis

    def test_resolves_alias_in_calls(self):
        e = PythonApiExtractor()
        src = "from torch import nn\nx = nn.Linear(2, 2)\n"
        calls = e.extract_api_calls(src)
        assert "torch.nn.Linear" in calls

    def test_extract_all_combines_imports_and_calls(self):
        e = PythonApiExtractor()
        src = "from torch import nn\nimport numpy as np\nx = nn.Linear(2, 2)\ny = np.zeros(3)\n"
        all_apis = e.extract_all(src)
        assert "torch.nn" in all_apis
        assert "torch.nn.Linear" in all_apis
        assert "numpy.zeros" in all_apis  # alias np → numpy 해소

    def test_syntax_error_returns_empty(self):
        e = PythonApiExtractor()
        assert e.extract_all("def broken(:") == set()


# ─────────────────────────────────────────────
# extract_apis_from_config
# ─────────────────────────────────────────────

class TestExtractFromConfig:

    def test_architectures(self):
        cfg = json.dumps({"architectures": ["LlamaForCausalLM", "LlamaModel"]})
        apis = extract_apis_from_config(cfg)
        assert "transformers.LlamaForCausalLM" in apis
        assert "transformers.LlamaModel" in apis

    def test_auto_map_standard(self):
        # 점이 없는 standard auto_map (transformers 표준)
        cfg = json.dumps({"auto_map": {"AutoModel": "ModelClass"}})
        apis = extract_apis_from_config(cfg)
        assert "transformers.AutoModel" in apis

    def test_auto_map_with_dot_excluded(self):
        # value에 점 포함 → trust_remote_code 트리거 — key는 추출하되 value 자체는 안 씀
        cfg = json.dumps({"auto_map": {"AutoModelForCausalLM": "modeling_xxx.LlamaForCausalLM"}})
        apis = extract_apis_from_config(cfg)
        # AutoModelForCausalLM key는 transformers.AutoModelForCausalLM로 추출
        assert "transformers.AutoModelForCausalLM" in apis
        # value의 modeling_xxx.LlamaForCausalLM은 추출 대상 아님
        assert "modeling_xxx.LlamaForCausalLM" not in apis

    def test_model_type(self):
        cfg = json.dumps({"model_type": "llama"})
        apis = extract_apis_from_config(cfg)
        assert "transformers.LlamaConfig" in apis

    def test_model_type_snake_case(self):
        cfg = json.dumps({"model_type": "gpt_neo"})
        apis = extract_apis_from_config(cfg)
        assert "transformers.GptNeoConfig" in apis

    def test_invalid_json_returns_empty(self):
        assert extract_apis_from_config("not json {") == set()

    def test_empty(self):
        assert extract_apis_from_config(json.dumps({})) == set()


# ─────────────────────────────────────────────
# VerifiedOrgAnalyzer with mock fetcher
# ─────────────────────────────────────────────

class FakeFetcher:
    """모델별 파일 내용을 들고 있는 mock fetcher."""

    def __init__(self, models_by_org: dict, files_by_model: dict):
        self.models_by_org = models_by_org
        self.files_by_model = files_by_model

    def list_models(self, org_id: str, limit: int) -> list[dict]:
        return self.models_by_org.get(org_id, [])

    def get_file(self, model_id: str, filename: str) -> str:
        return self.files_by_model.get((model_id, filename), "")


class TestVerifiedOrgAnalyzer:

    def test_py_path_extracts_apis(self):
        fetcher = FakeFetcher(
            models_by_org={
                "meta-llama": [{"id": "meta-llama/Llama-3", "files": ["modeling_llama.py"]}],
            },
            files_by_model={
                ("meta-llama/Llama-3", "modeling_llama.py"):
                    "from torch import nn\nclass M(nn.Module):\n    def forward(self, x): return x\n",
            },
        )
        analyzer = VerifiedOrgAnalyzer(fetcher=fetcher)
        result = analyzer.analyze_org("meta-llama", model_limit=5)
        # nn.Module은 호출이 아니라서 alias_map에 의해 풀리진 않지만,
        # extract_imports에서 torch.nn은 잡힘
        assert "torch.nn" in result.apis_found
        assert result.errors == []

    def test_config_fallback(self):
        # .py 없는 표준 모델 — config.json 폴백
        fetcher = FakeFetcher(
            models_by_org={
                "google": [{"id": "google/standard", "files": ["config.json"]}],
            },
            files_by_model={
                ("google/standard", "config.json"):
                    json.dumps({"architectures": ["BertModel"], "model_type": "bert"}),
            },
        )
        analyzer = VerifiedOrgAnalyzer(fetcher=fetcher)
        result = analyzer.analyze_org("google", model_limit=5)
        assert "transformers.BertModel" in result.apis_found
        assert "transformers.BertConfig" in result.apis_found

    def test_py_extraction_skips_config_fallback(self):
        # .py에서 추출 성공하면 config.json 폴백 안 함
        fetcher = FakeFetcher(
            models_by_org={
                "google": [{"id": "google/x", "files": ["modeling.py", "config.json"]}],
            },
            files_by_model={
                ("google/x", "modeling.py"): "from transformers import AutoModel\n",
                ("google/x", "config.json"): json.dumps({"architectures": ["BertModel"]}),
            },
        )
        analyzer = VerifiedOrgAnalyzer(fetcher=fetcher)
        result = analyzer.analyze_org("google", model_limit=5)
        # .py에서 transformers.AutoModel 추출됨
        assert "transformers.AutoModel" in result.apis_found
        # config 폴백은 사용 안 함 — BertModel은 없어야 함 (이 테스트의 목적)
        assert "transformers.BertModel" not in result.apis_found

    def test_list_models_failure_returns_error(self):
        class BrokenFetcher:
            def list_models(self, *a, **k): raise RuntimeError("API down")
            def get_file(self, *a, **k): return ""
        analyzer = VerifiedOrgAnalyzer(fetcher=BrokenFetcher())
        result = analyzer.analyze_org("meta-llama")
        assert result.errors
        assert "API down" in result.errors[0]


# ─────────────────────────────────────────────
# aggregate_org_results
# ─────────────────────────────────────────────

class TestAggregate:

    def _make_result(
        self, org_id: str, apis: dict[str, int],
        models=None, apis_by_model=None,
    ):
        from whitelist.mod2_verified_org import OrgAnalysisResult
        return OrgAnalysisResult(
            org_id=org_id, org_name=org_id,
            models_analyzed=models or [f"{org_id}/x"],
            apis_found=apis,
            apis_by_model=apis_by_model or {},
        )

    def test_filters_existing_whitelist(self):
        results = [
            self._make_result("meta-llama", {"torch.nn.Linear": 5, "transformers.NewClass": 3}),
        ]
        agg = aggregate_org_results(results, existing_whitelist={"torch.nn.Linear"})
        paths = {u.api_path for u in agg}
        assert "torch.nn.Linear" not in paths  # 등록된 건 제외
        assert "transformers.NewClass" in paths

    def test_aggregates_orgs(self):
        results = [
            self._make_result("meta-llama", {"transformers.X": 3}),
            self._make_result("google", {"transformers.X": 2}),
        ]
        agg = aggregate_org_results(results, existing_whitelist=set())
        assert len(agg) == 1
        assert set(agg[0].used_by_orgs) == {"meta-llama", "google"}
        assert agg[0].total_count == 5

    def test_sort_by_org_count_desc(self):
        results = [
            self._make_result("a", {"api.X": 1}),
            self._make_result("b", {"api.X": 1, "api.Y": 1}),
            self._make_result("c", {"api.X": 1}),
        ]
        agg = aggregate_org_results(results, existing_whitelist=set())
        # api.X는 3개 org, api.Y는 1개 org
        assert agg[0].api_path == "api.X"
        assert len(agg[0].used_by_orgs) == 3


# ─────────────────────────────────────────────
# 양유상 PR #16 리뷰 회귀
# ─────────────────────────────────────────────

class TestYangyuPR16Regression:
    """양유상 PR #16 리뷰 (2026-05-06):
    1) used_by_models가 조직 전체 모델로 부풀어오는 버그
    2) (별도 파일) 도메인 화이트리스트 suffix 우회 취약점
    """

    def _make_result(
        self, org_id: str, apis: dict[str, int],
        models=None, apis_by_model=None,
    ):
        from whitelist.mod2_verified_org import OrgAnalysisResult
        return OrgAnalysisResult(
            org_id=org_id, org_name=org_id,
            models_analyzed=models or [f"{org_id}/x"],
            apis_found=apis,
            apis_by_model=apis_by_model or {},
        )

    def test_used_by_models_only_actual_users(self):
        """A 모델만 X API, B 모델만 Y API를 써도 두 API 모두 [A, B]로
        부풀어오르지 않아야 한다. 양유상 재현 시나리오 그대로.
        """
        result = self._make_result(
            "meta-llama",
            apis={"torch.nn.Linear": 1, "numpy.zeros": 1},
            models=["meta-llama/A", "meta-llama/B"],
            apis_by_model={
                "torch.nn.Linear": ["meta-llama/A"],   # A만 사용
                "numpy.zeros":     ["meta-llama/B"],   # B만 사용
            },
        )
        agg = aggregate_org_results([result], existing_whitelist=set())
        by_path = {u.api_path: u for u in agg}

        assert by_path["torch.nn.Linear"].used_by_models == ["meta-llama/A"]
        assert by_path["numpy.zeros"].used_by_models == ["meta-llama/B"]
        # 부풀어오르면 안 됨
        assert "meta-llama/B" not in by_path["torch.nn.Linear"].used_by_models
        assert "meta-llama/A" not in by_path["numpy.zeros"].used_by_models

    def test_apis_by_model_populated_by_analyzer(self):
        """VerifiedOrgAnalyzer.analyze_org가 apis_by_model을 정확히 채우는지."""
        from whitelist.mod2_verified_org import VerifiedOrgAnalyzer

        class MultiModelFetcher:
            def list_models(self, org_id, limit):
                return [
                    {"id": "org/A", "files": ["modeling_a.py"]},
                    {"id": "org/B", "files": ["modeling_b.py"]},
                ]

            def get_file(self, model_id, filename):
                if model_id == "org/A" and filename == "modeling_a.py":
                    return "from torch import nn\nx = nn.Linear(2,2)\n"
                if model_id == "org/B" and filename == "modeling_b.py":
                    return "import numpy as np\ny = np.zeros(3)\n"
                return ""

        analyzer = VerifiedOrgAnalyzer(fetcher=MultiModelFetcher())
        result = analyzer.analyze_org("meta-llama", model_limit=10)

        # apis_by_model이 모델별 실제 사용 API만 가져야 함
        # A는 torch.nn 관련만, B는 numpy 관련만
        for api, models in result.apis_by_model.items():
            assert len(models) >= 1
            if api.startswith("torch"):
                assert "org/A" in models
                assert "org/B" not in models  # 부풀어오르면 안 됨
            if api.startswith("numpy"):
                assert "org/B" in models
                assert "org/A" not in models  # 부풀어오르면 안 됨


class TestDomainAllowlistSuffixBypass:
    """양유상 PR #16 리뷰 1번 — host.endswith(d)는 evilpytorch.org도 통과시킴.
    OfficialDocCrawler._is_allowed_domain + HttpxFetcher.get 둘 다 정확
    매칭으로 강화.
    """

    def test_exact_domain_allowed(self):
        from whitelist.mod1_doc_crawler import OfficialDocCrawler
        assert OfficialDocCrawler._is_allowed_domain("https://pytorch.org/docs")
        assert OfficialDocCrawler._is_allowed_domain("https://numpy.org/")
        assert OfficialDocCrawler._is_allowed_domain("https://huggingface.co/x")

    def test_subdomain_allowed(self):
        from whitelist.mod1_doc_crawler import OfficialDocCrawler
        assert OfficialDocCrawler._is_allowed_domain("https://docs.pytorch.org/x")
        assert OfficialDocCrawler._is_allowed_domain("https://www.numpy.org/")

    def test_suffix_bypass_blocked(self):
        from whitelist.mod1_doc_crawler import OfficialDocCrawler
        # 양유상 재현: evilpytorch.org는 pytorch.org와 무관한 도메인이지만
        # endswith("pytorch.org") 통과해버리는 취약점
        assert not OfficialDocCrawler._is_allowed_domain(
            "https://evilpytorch.org/x"
        )
        assert not OfficialDocCrawler._is_allowed_domain(
            "https://fakehuggingface.co/x"
        )
        assert not OfficialDocCrawler._is_allowed_domain(
            "https://pytorch.org.attacker.com/x"
        )

    def test_unrelated_domain_blocked(self):
        from whitelist.mod1_doc_crawler import OfficialDocCrawler
        assert not OfficialDocCrawler._is_allowed_domain("https://evil.com/")
        # http 등 비-https는 HttpxFetcher.get에서 별도 차단 (아래 test 참조)

    def test_real_fetcher_rejects_non_https(self):
        """HttpxFetcher.get은 https가 아니면 ValueError."""
        from whitelist.mod1_real_crawler import HttpxFetcher

        fetcher = HttpxFetcher(timeout=5.0, rate_limit_delay=0.0)
        try:
            with pytest.raises(ValueError, match="HTTPS만 허용"):
                fetcher.get("http://pytorch.org/api")
        finally:
            fetcher.close()

    def test_real_fetcher_blocks_suffix_bypass(self):
        """HttpxFetcher.get도 같은 패턴으로 강화돼있는지."""
        from whitelist.mod1_real_crawler import HttpxFetcher

        fetcher = HttpxFetcher(timeout=5.0, rate_limit_delay=0.0)
        try:
            with pytest.raises(ValueError, match="허용되지 않은 도메인"):
                fetcher.get("https://evilpytorch.org/api")
        finally:
            fetcher.close()
