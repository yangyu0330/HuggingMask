"""
화이트리스트 규칙 — namespace 매칭 + 영구 차단 + 위험 키워드

설계 원칙 (whitelist/rules.md):
- 위험 API는 명시적 block 목록에 둔다.
- torch.nn.* 같은 namespace allow는 범위를 좁게 유지한다.
- 규칙 변경 시 whitelist version을 갱신한다.

규칙은 결정론적이며 LLM을 사용하지 않는다 (감사 가능성 보장).
"""

from whitelist.models import PendingClassification


# ─────────────────────────────────────────────
# 정책 버전 — 규칙 변경 시 반드시 갱신
# 형식: wl-YYYY.MM.DD (인터페이스 정의서 14.2절 예시 기준)
# ─────────────────────────────────────────────

WHITELIST_VERSION = "wl-2026.06.08"


# ─────────────────────────────────────────────
# 네임스페이스 기반 분류 권고 규칙
# longest-prefix match로 매칭하여 PendingClassification 권고값 결정
# ─────────────────────────────────────────────

NAMESPACE_RULES: dict[str, PendingClassification] = {
    # 자동 승인 권고: 순수 텐서 연산
    "torch.nn.":                  PendingClassification.AUTO_APPROVE,
    "torch.nn.functional.":       PendingClassification.AUTO_APPROVE,
    "torch.Tensor.":              PendingClassification.AUTO_APPROVE,
    "torch.autograd.":            PendingClassification.AUTO_APPROVE,
    "torch.linalg.":              PendingClassification.AUTO_APPROVE,
    "torch.fft.":                 PendingClassification.AUTO_APPROVE,
    "torch.special.":             PendingClassification.AUTO_APPROVE,

    # 조건부: 대부분 안전하나 주의 필요
    "torch.optim.":               PendingClassification.CONDITIONAL,
    "torch.cuda.":                PendingClassification.CONDITIONAL,
    "torch.amp.":                 PendingClassification.CONDITIONAL,
    "torch.backends.":            PendingClassification.CONDITIONAL,
    "numpy.":                     PendingClassification.CONDITIONAL,
    "transformers.":              PendingClassification.CONDITIONAL,

    # 수동 리뷰: 파일 I/O, 네트워크, 동적 코드 가능
    "torch.utils.":               PendingClassification.MANUAL,
    "torch.distributed.":         PendingClassification.MANUAL,
    "torch.jit.":                 PendingClassification.MANUAL,
    "torch.onnx.":                PendingClassification.MANUAL,
    "torch.multiprocessing.":     PendingClassification.MANUAL,
    "torch.hub.":                 PendingClassification.MANUAL,

    # 명시적 위험 (sub-namespace)
    "pickle.":                    PendingClassification.BLOCKED,
    "os.":                        PendingClassification.BLOCKED,
    "subprocess.":                PendingClassification.BLOCKED,
    "importlib.":                 PendingClassification.BLOCKED,
    "ctypes.":                    PendingClassification.BLOCKED,
}


# ─────────────────────────────────────────────
# 제어 대상 라이브러리 루트 (top-level 모듈)
# 이 루트로 시작하는 API만 namespace/위험 규칙으로 정밀 분류한다. 그 외 루트
# (로컬 변수 메서드 `t.append`, 빌트인 `type` 등)는 외부 라이브러리 API가 아니므로
# 화이트리스트 제어 대상이 아니다 → 위험 키워드만 없으면 자동 승인 권고.
# (위험 키워드 write/load/run/exec... 는 escalate()에서 MANUAL 로 격상되어 안전.)
# ─────────────────────────────────────────────

LIBRARY_ROOTS: set[str] = {
    # ML/수치
    "torch", "torchvision", "torchaudio", "numpy", "np", "scipy", "pandas", "sklearn",
    "transformers", "tensorflow", "tf", "keras", "jax", "jaxlib", "flax", "PIL", "cv2",
    "matplotlib", "datasets", "accelerate", "safetensors", "tokenizers", "huggingface_hub",
    "onnx", "onnxruntime", "timm", "einops", "sentencepiece",
    # 직렬화/동적실행/시스템/네트워크 (위험 sink 포함)
    "os", "sys", "subprocess", "shutil", "pathlib", "io", "socket", "ssl", "requests",
    "urllib", "urllib3", "httpx", "aiohttp", "pickle", "cloudpickle", "dill", "joblib",
    "marshal", "shelve", "importlib", "ctypes", "cffi", "yaml", "json", "builtins",
    "threading", "multiprocessing", "asyncio", "tempfile", "glob", "zipfile", "tarfile",
    "gzip", "base64", "codecs", "struct", "mmap", "pty", "platform", "signal",
}


# ─────────────────────────────────────────────
# 명시적 양성 리프 — 빌트인 / 순수 데이터구조·문자열 연산
# (위험 키워드 write/read/load/save/open/exec/eval/run/call/system 등은 절대 포함 안 함)
# "루트가 LIBRARY_ROOTS 가 아니고(로컬 변수/빌트인) AND 리프가 이 집합" 일 때만 자동 승인.
# → 미지 서드파티 라이브러리(`my_lib.UnknownClass`)·모호한 메서드(`conn.send`)는 MANUAL 유지.
# ─────────────────────────────────────────────

BENIGN_LEAF_NAMES: set[str] = {
    # builtins
    "type", "len", "isinstance", "issubclass", "hasattr", "repr", "str", "int", "float",
    "bool", "bytes", "bytearray", "list", "dict", "set", "tuple", "frozenset", "range",
    "enumerate", "zip", "map", "filter", "sorted", "reversed", "min", "max", "sum", "abs",
    "round", "all", "any", "print", "format", "ord", "chr", "hex", "oct", "bin", "divmod",
    "pow", "vars", "dir",
    # list/set/dict 메서드 (순수 데이터 연산)
    "append", "extend", "insert", "pop", "remove", "clear", "index", "count", "sort",
    "reverse", "copy", "get", "keys", "values", "items", "setdefault", "update", "add",
    "discard", "union", "intersection", "difference", "symmetric_difference", "issubset",
    "issuperset", "popitem",
    # str 메서드
    "join", "split", "rsplit", "strip", "lstrip", "rstrip", "lower", "upper", "title",
    "capitalize", "casefold", "swapcase", "replace", "find", "rfind", "ljust", "rjust",
    "center", "zfill", "splitlines", "startswith", "endswith", "encode", "decode",
    "expandtabs", "isdigit", "isalpha", "isalnum", "isspace", "isupper", "islower",
}


# ─────────────────────────────────────────────
# 명시적 차단 목록 (block 우선 — engine.md:21)
# 어떤 경우에도 ALLOWED가 될 수 없다
# ─────────────────────────────────────────────

PERMANENTLY_BLOCKED_APIS: set[str] = {
    "torch.load",
    "torch.save",
    "torch.hub.load",                     # 원격 저장소 코드 다운로드+실행 (설계상 RCE)
    "torch.hub.load_state_dict_from_url", # 원격 fetch
    "pickle.load",
    "pickle.loads",
    "numpy.load",
    "numpy.save",
    "shelve.open",
    "marshal.load",
    "marshal.loads",
    "joblib.load",                        # 내부적으로 pickle 역직렬화 → RCE
    "dill.load",                          # pickle superset
    "dill.loads",
    "yaml.load",          # yaml.safe_load만 허용
    "yaml.unsafe_load",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
    "builtins.compile",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "importlib.import_module",
    "ctypes.cdll",
    "ctypes.CDLL",
}


# ─────────────────────────────────────────────
# 위험 키워드 — 함수명에 포함 시 권고 등급 격상
# (자동 승인 namespace에 속해도 격상)
# ─────────────────────────────────────────────

DANGER_KEYWORDS_IO: set[str] = {
    "load", "save", "dump", "open", "write", "read",
    "download", "fetch", "upload", "from_pretrained",
}

DANGER_KEYWORDS_EXEC: set[str] = {
    "exec", "eval", "compile", "system", "popen",
    "spawn", "fork", "call", "run",
}

DANGER_KEYWORDS: set[str] = DANGER_KEYWORDS_IO | DANGER_KEYWORDS_EXEC


# ─────────────────────────────────────────────
# 오탐 피드백 SLA (시간) — review_status별 응답 목표
# ─────────────────────────────────────────────

SLA_HOURS: dict[PendingClassification, int] = {
    PendingClassification.AUTO_APPROVE: 4,
    PendingClassification.CONDITIONAL:  24,
    PendingClassification.MANUAL:       48,
    PendingClassification.BLOCKED:      0,
}


# ─────────────────────────────────────────────
# 모듈 1 — 공식 문서 크롤링 대상
# ─────────────────────────────────────────────

CRAWL_TARGETS: dict[str, dict] = {
    "pytorch": {
        "base_url": "https://pytorch.org/docs/stable/",
        "pages": [
            "nn.html",
            "nn.functional.html",
            "torch.html",
            "tensors.html",
            "optim.html",
            "autograd.html",
            "cuda.html",
            "linalg.html",
            "fft.html",
            "special.html",
        ],
    },
    "transformers": {
        "base_url": "https://huggingface.co/docs/transformers/",
        "pages": [
            "main_classes/model",
            "main_classes/configuration",
            "main_classes/tokenizer",
            "main_classes/trainer",
        ],
    },
    "numpy": {
        "base_url": "https://numpy.org/doc/stable/reference/",
        "pages": [
            "routines.array-creation.html",
            "routines.array-manipulation.html",
            "routines.math.html",
            "routines.linalg.html",
        ],
    },
}

# 한 번의 크롤링에서 이 수 이상 신규 API가 발견되면 자동 플래그 (상세설계 9.3절)
CRAWL_SPIKE_THRESHOLD: int = 100

# 도메인 화이트리스트 (HTTPS 외 차단, 외부 도메인 접근 차단)
ALLOWED_CRAWL_DOMAINS: set[str] = {
    "pytorch.org",
    "huggingface.co",
    "numpy.org",
}


# ─────────────────────────────────────────────
# 모듈 2 — 검증된 조직 (HuggingFace Verified Org)
# ─────────────────────────────────────────────

VERIFIED_ORGANIZATIONS: dict[str, str] = {
    "meta-llama":   "Meta AI",
    "google":       "Google",
    "mistralai":    "Mistral AI",
    "microsoft":    "Microsoft",
    "bigscience":   "BigScience",
    "EleutherAI":   "EleutherAI",
    "Qwen":         "Alibaba Qwen",
    "deepseek-ai":  "DeepSeek",
    "THUDM":        "Tsinghua THUDM",
}


# ─────────────────────────────────────────────
# 외부 참조 URL 생성 (PendingApiRecord.documentation_url)
# ─────────────────────────────────────────────

def documentation_url_for(api_path: str) -> str | None:
    """API 경로 → 공식 문서 링크 추정.

    매칭되지 않으면 None. 추후 모듈 1 크롤러가 정확한 URL을 채울 수 있다.
    """
    if api_path.startswith("torch."):
        return f"https://pytorch.org/docs/stable/generated/{api_path}.html"
    if api_path.startswith("transformers."):
        return f"https://huggingface.co/docs/transformers/main_classes/model"
    if api_path.startswith("numpy."):
        sym = api_path.split(".", 1)[1]
        return f"https://numpy.org/doc/stable/reference/generated/numpy.{sym}.html"
    return None
