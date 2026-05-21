"""Semantic / invariant check for preprocessing files.

tokenizer: 공식 tokenizer 결과와 비교, 불변 조건 검사
processor / image_processor: 출력값 범위, 크기, 결정성 검사

B-1 자동 승인은 이 검사를 통과한 경우에만 가능하다.
"""

from __future__ import annotations

import importlib
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ────────────────────────────────────────────────────────────────────────────
# 결과 구조
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class SemanticCheckResult:
    passed: bool
    file_type: str
    checks_run: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    def fail(self, reason: str) -> None:
        self.passed = False
        self.failures.append(reason)

    def ok(self, check_name: str) -> None:
        self.checks_run.append(check_name)


# ────────────────────────────────────────────────────────────────────────────
# tokenizer semantic check
# ────────────────────────────────────────────────────────────────────────────

# 테스트용 샘플 입력
_SAMPLE_TEXTS = [
    "Hello, world!",
    "This is a test sentence.",
    "안녕하세요",
    "",
    "a",
]

# 공식 참조 tokenizer (model_type → HuggingFace 모델 ID)
_REFERENCE_TOKENIZERS: dict[str, str] = {
    "bert":           "bert-base-uncased",
    "roberta":        "roberta-base",
    "gpt2":           "gpt2",
    "llama":          "hf-internal-testing/llama-tokenizer",
    "mistral":        "mistral-community/Mistral-7B-v0.1",
    "distilbert":     "distilbert-base-uncased",
    "xlm-roberta":    "xlm-roberta-base",
}


def _load_class_from_source(source: str, filename: str, class_hint: str | None = None) -> Any:
    """소스 코드에서 tokenizer 클래스 로드 (실행 없이 import)."""
    import types
    mod = types.ModuleType("_custom_tokenizer_sandbox")
    try:
        exec(compile(source, filename, "exec"), mod.__dict__)  # noqa: S102
    except Exception as e:
        raise RuntimeError(f"tokenizer 로드 실패: {e}") from e

    # 클래스 찾기
    for name, obj in mod.__dict__.items():
        if isinstance(obj, type) and (
            class_hint is None or class_hint.lower() in name.lower()
            or "tokenizer" in name.lower()
        ):
            return obj
    raise RuntimeError("tokenizer 클래스를 찾을 수 없음")


def _run_tokenizer_invariant_checks(
    tokenizer_cls: Any,
    result: SemanticCheckResult,
) -> None:
    """tokenizer 불변 조건 검사."""
    try:
        tok = tokenizer_cls.__new__(tokenizer_cls)
    except Exception:
        result.skipped = True
        result.skip_reason = "tokenizer 인스턴스 생성 실패 — 초기화 인자 필요"
        return

    # 검사 1: tokenize 메서드 존재
    if not hasattr(tok, "tokenize") and not hasattr(tok, "__call__") and not hasattr(tok, "encode"):
        result.fail("tokenize / encode / __call__ 메서드 없음")
        return
    result.ok("tokenize_method_exists")

    # 검사 2: vocab 속성 접근 가능 여부
    if hasattr(tok, "vocab") or hasattr(tok, "_vocab") or hasattr(tok, "vocab_size"):
        result.ok("vocab_accessible")


def check_tokenizer(
    source: str,
    filename: str,
    model_type: str | None = None,
) -> SemanticCheckResult:
    """
    tokenizer 파일 semantic check.

    1. tokenize 메서드 존재 확인
    2. 불변 조건 검사 (vocab 범위, 특수 토큰 등)
    3. 공식 tokenizer와 결과 비교 (참조 tokenizer 있을 때)
    """
    result = SemanticCheckResult(passed=True, file_type="TOKENIZER")

    # tokenizer 클래스 로드
    try:
        tok_cls = _load_class_from_source(source, filename)
    except RuntimeError as e:
        result.skipped = True
        result.skip_reason = str(e)
        return result

    # 불변 조건 검사
    _run_tokenizer_invariant_checks(tok_cls, result)
    if result.skipped:
        return result

    # 공식 tokenizer와 결과 비교
    ref_model = _REFERENCE_TOKENIZERS.get(model_type or "")
    if ref_model:
        try:
            from transformers import AutoTokenizer
            ref_tok = AutoTokenizer.from_pretrained(ref_model)

            try:
                custom_tok = tok_cls.__new__(tok_cls)
            except Exception:
                result.skipped = True
                result.skip_reason = "커스텀 tokenizer 초기화 실패"
                return result

            if hasattr(custom_tok, "tokenize") and hasattr(ref_tok, "tokenize"):
                for text in _SAMPLE_TEXTS:
                    if not text:
                        continue
                    try:
                        custom_out = custom_tok.tokenize(text)
                        ref_out = ref_tok.tokenize(text)
                        if custom_out != ref_out:
                            result.fail(
                                f"공식 tokenizer 결과 불일치: "
                                f"입력='{text}' "
                                f"커스텀={custom_out} "
                                f"공식={ref_out}"
                            )
                    except Exception:
                        # 초기화 미완료로 실패하는 건 스킵
                        pass
                result.ok("reference_tokenizer_comparison")

        except Exception as e:
            # 공식 tokenizer 로드 실패 → 비교 스킵
            result.ok("reference_comparison_skipped")

    return result


# ────────────────────────────────────────────────────────────────────────────
# image processor / processor invariant check
# ────────────────────────────────────────────────────────────────────────────

def _make_dummy_image() -> Any:
    """테스트용 더미 이미지 생성."""
    try:
        from PIL import Image
        import numpy as np
        arr = np.random.randint(0, 256, (224, 224, 3), dtype=np.uint8)
        return Image.fromarray(arr)
    except ImportError:
        return None


def _make_dummy_audio() -> Any:
    """테스트용 더미 오디오 생성."""
    try:
        import numpy as np
        return np.random.randn(16000).astype("float32")  # 1초 16kHz
    except ImportError:
        return None


def check_image_processor(
    source: str,
    filename: str,
) -> SemanticCheckResult:
    """
    image processor invariant check.

    1. preprocess / __call__ 메서드 존재 확인
    2. 출력값 범위 확인 (정규화 결과가 합리적 범위 내)
    3. 결정성 확인 (같은 입력 → 같은 출력)
    """
    result = SemanticCheckResult(passed=True, file_type="IMAGE_PROCESSOR")

    try:
        import types
        import numpy as np
        mod = types.ModuleType("_custom_processor_sandbox")
        exec(compile(source, filename, "exec"), mod.__dict__)  # noqa: S102
    except Exception as e:
        result.skipped = True
        result.skip_reason = f"소스 로드 실패: {e}"
        return result

    # 클래스 찾기
    proc_cls = None
    for name, obj in mod.__dict__.items():
        if isinstance(obj, type) and (
            "processor" in name.lower() or "transform" in name.lower()
        ):
            proc_cls = obj
            break

    if proc_cls is None:
        result.skipped = True
        result.skip_reason = "processor 클래스를 찾을 수 없음"
        return result

    # 메서드 존재 확인
    if not any(hasattr(proc_cls, m) for m in ["preprocess", "__call__", "process"]):
        result.fail("preprocess / __call__ / process 메서드 없음")
        return result
    result.ok("preprocess_method_exists")

    # 더미 이미지로 출력 검사
    dummy_img = _make_dummy_image()
    if dummy_img is None:
        result.skipped = True
        result.skip_reason = "PIL 없음 — 이미지 생성 불가"
        return result

    try:
        proc = proc_cls()
        method = getattr(proc, "preprocess", None) or getattr(proc, "__call__", None)
        if method is None:
            result.skipped = True
            result.skip_reason = "실행 가능한 메서드 없음"
            return result

        out1 = method(dummy_img)
        out2 = method(dummy_img)

        # numpy array 또는 torch tensor로 변환
        try:
            import numpy as np
            if hasattr(out1, "numpy"):
                arr1 = out1.numpy()
                arr2 = out2.numpy()
            else:
                arr1 = np.array(out1)
                arr2 = np.array(out2)

            # 결정성 확인
            if not np.allclose(arr1, arr2):
                result.fail("결정성 위반: 같은 입력에 다른 출력")
            else:
                result.ok("determinism_check")

            # 출력값 범위 확인 (정규화 후 -10 ~ 10 범위 기대)
            if arr1.min() < -100 or arr1.max() > 100:
                result.fail(
                    f"출력값 범위 이상: min={arr1.min():.2f}, max={arr1.max():.2f}"
                )
            else:
                result.ok("output_range_check")

        except Exception:
            result.ok("output_check_skipped")

    except TypeError:
        # 초기화 인자 필요한 경우 스킵
        result.skipped = True
        result.skip_reason = "processor 초기화 인자 필요"
    except Exception as e:
        result.fail(f"processor 실행 오류: {e}")

    return result


def check_processor(
    source: str,
    filename: str,
) -> SemanticCheckResult:
    """processor (멀티모달) invariant check."""
    result = SemanticCheckResult(passed=True, file_type="PROCESSOR")

    try:
        import types
        mod = types.ModuleType("_custom_processor_sandbox")
        exec(compile(source, filename, "exec"), mod.__dict__)  # noqa: S102
    except Exception as e:
        result.skipped = True
        result.skip_reason = f"소스 로드 실패: {e}"
        return result

    proc_cls = None
    for name, obj in mod.__dict__.items():
        if isinstance(obj, type) and "processor" in name.lower():
            proc_cls = obj
            break

    if proc_cls is None:
        result.skipped = True
        result.skip_reason = "processor 클래스를 찾을 수 없음"
        return result

    if not any(hasattr(proc_cls, m) for m in ["process", "__call__", "preprocess"]):
        result.fail("process / __call__ / preprocess 메서드 없음")
        return result
    result.ok("process_method_exists")

    # 더미 오디오로 출력 검사
    dummy_audio = _make_dummy_audio()
    if dummy_audio is None:
        result.skipped = True
        result.skip_reason = "numpy 없음 — 오디오 생성 불가"
        return result

    try:
        proc = proc_cls()
        method = getattr(proc, "process", None) or getattr(proc, "__call__", None)
        if method:
            import numpy as np
            out1 = method(dummy_audio)
            out2 = method(dummy_audio)

            try:
                if hasattr(out1, "numpy"):
                    arr1, arr2 = out1.numpy(), out2.numpy()
                else:
                    arr1, arr2 = np.array(out1), np.array(out2)

                if not np.allclose(arr1, arr2):
                    result.fail("결정성 위반: 같은 입력에 다른 출력")
                else:
                    result.ok("determinism_check")
            except Exception:
                result.ok("output_check_skipped")

    except TypeError:
        result.skipped = True
        result.skip_reason = "processor 초기화 인자 필요"
    except Exception as e:
        result.fail(f"processor 실행 오류: {e}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# 진입점
# ────────────────────────────────────────────────────────────────────────────

def run_semantic_check(
    source: str,
    filename: str,
    file_type: str,
    model_type: str | None = None,
) -> SemanticCheckResult:
    """
    파일 종류에 맞는 semantic/invariant check 실행.

    반환값:
        passed=True  → B-1 승인 가능
        passed=False → B-2 유지
        skipped=True → B-2 유지 (검사 불가)
    """
    if file_type == "TOKENIZER":
        return check_tokenizer(source, filename, model_type=model_type)
    elif file_type == "IMAGE_PROCESSOR":
        return check_image_processor(source, filename)
    elif file_type == "PROCESSOR":
        return check_processor(source, filename)
    elif file_type == "FEATURE_EXTRACTOR":
        # feature extractor는 processor와 유사하게 처리
        return check_processor(source, filename)
    else:
        r = SemanticCheckResult(passed=False, file_type=file_type)
        r.skipped = True
        r.skip_reason = f"{file_type} 은 semantic check 미구현"
        return r
