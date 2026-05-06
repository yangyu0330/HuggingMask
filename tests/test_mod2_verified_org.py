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

    def _make_result(self, org_id: str, apis: dict[str, int], models=None):
        from whitelist.mod2_verified_org import OrgAnalysisResult
        return OrgAnalysisResult(
            org_id=org_id, org_name=org_id,
            models_analyzed=models or [f"{org_id}/x"],
            apis_found=apis,
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
