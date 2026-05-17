"""
AI 모델 공급망 보안 프록시 — 전처리 파일 AST 검증
AST 정적 분석 파트 — tokenizer / processor / image processor 계열 .py 파일 검증

실행: python preprocessing_validator.py
"""

import ast
import re
import json
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path

# ────────────────────────────────────────────────
# 색상 출력
# ────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def blue(s):   return f"{C.BLUE}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"


# ────────────────────────────────────────────────
# 파일 종류 분류
# ────────────────────────────────────────────────

FILE_TYPE_PATTERNS = {
    "TOKENIZER":         ["tokenization_", "tokenizer_"],
    "PROCESSOR":         ["processing_", "processor_"],
    "IMAGE_PROCESSOR":   ["image_processing_", "image_processor_"],
    "FEATURE_EXTRACTOR": ["feature_extraction_", "feature_extractor_"],
    "MODELING":          ["modeling_", "model_"],
    "CONFIGURATION":     ["configuration_", "config_"],
}


def classify_file(filename: str) -> str:
    """파일 이름 패턴으로 파일 종류 분류"""
    name = Path(filename).name.lower()
    for file_type, patterns in FILE_TYPE_PATTERNS.items():
        for pattern in patterns:
            if name.startswith(pattern):
                return file_type
    return "UNKNOWN"


# ────────────────────────────────────────────────
# 공통 위험 패턴 정의
# ────────────────────────────────────────────────

# 즉시 차단 — 위험 함수 호출 (ast.Name)
# 주의: system, popen은 너무 일반적인 이름이라 제외
#       from os import system 탐지는 DANGEROUS_FROM_IMPORTS로 처리
DANGEROUS_CALL_NAMES = {
    "eval", "exec", "compile",
    "__import__",
    "setattr", "delattr",
}

# 즉시 차단 — 위험 메서드 호출 (ast.Attribute)
# (객체, 메서드) 쌍
DANGEROUS_ATTR_CALLS = {
    ("torch",      "load"),          # pickle 역직렬화
    ("torch",      "hub"),           # 외부 저장소 로드
    ("pickle",     "load"),          # pickle 역직렬화
    ("pickle",     "loads"),         # pickle 역직렬화
    ("subprocess", "run"),           # 외부 프로세스 실행
    ("subprocess", "Popen"),         # 외부 프로세스 실행
    ("subprocess", "call"),          # 외부 프로세스 실행
    ("os",         "system"),        # 쉘 명령 실행
    ("os",         "popen"),         # 쉘 명령 실행
    ("os",         "environ"),       # 환경변수 접근 (API 키 탈취)
    ("importlib",  "import_module"), # 동적 모듈 로드
    ("requests",   "get"),           # 외부 URL 접근
    ("requests",   "post"),          # 외부 URL 접근
    ("urllib",     "urlopen"),       # 외부 URL 접근
    ("urllib",     "urlretrieve"),   # 외부 파일 다운로드
    ("yaml",       "load"),          # YAML 역직렬화 (yaml.safe_load는 허용)
    ("tarfile",    "extractall"),    # 아카이브 슬립
    ("joblib",     "load"),          # joblib 역직렬화
}

# from X import Y 형태의 위험 패턴
# "from os import system" 같은 우회 탐지
DANGEROUS_FROM_IMPORTS = {
    # (모듈, 이름) 쌍
    ("os",         "system"),
    ("os",         "popen"),
    ("os",         "environ"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("pickle",     "load"),
    ("pickle",     "loads"),
    ("importlib",  "import_module"),
    ("builtins",   "eval"),
    ("builtins",   "exec"),
    ("builtins",   "compile"),
}

# 위험 import 모듈
DANGEROUS_IMPORTS = {
    "subprocess", "socket", "pickle",
    "ctypes", "cffi", "pty",
}

# 주의 import 모듈 (파일 종류에 따라 허용 여부 판단)
SUSPICIOUS_IMPORTS = {
    "os", "sys", "shutil", "tempfile",
    "importlib", "builtins",
}

# 난독화 패턴 탐지용 키워드
OBFUSCATION_PATTERNS = {
    "base64", "b64decode", "b64encode",
    "codecs", "rot13", "zlib",
    "marshal",
}

# URL 패턴
URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)

# ────────────────────────────────────────────────
# 신규 API 분류 — 계산 전용은 B-1 유지
# ────────────────────────────────────────────────

# 외부 통신/파일 실행 없는 순수 계산 라이브러리
# → 신규 API여도 B-1 유지 (B-2 격상 안 함)
SAFE_NEW_APIS = {
    # 수학/과학 계산
    "scipy", "sklearn", "skimage",
    # 음성 처리
    "librosa", "torchaudio", "soundfile",
    # 이미지 처리
    "torchvision", "cv2", "imageio",
    # 데이터 처리
    "pandas", "h5py",
    # 기타 유틸
    "tqdm", "einops", "timm",
}

# 네트워크/파일 실행 가능 → 신규 API면 B-2 격상
DANGEROUS_NEW_APIS = {
    "requests", "httpx", "aiohttp",
    "paramiko", "ftplib", "smtplib",
    "boto3", "google", "azure",
}


# ────────────────────────────────────────────────
# 파일 종류별 허용 API
# ────────────────────────────────────────────────

ALLOWED_IMPORTS_BY_TYPE = {
    "TOKENIZER": {
        "re", "unicodedata", "collections", "json",
        "os",          # os.path 한정 — 값 패턴 검사로 추가 탐지
        "string", "itertools", "functools",
        "typing", "abc", "copy", "math",
        "logging", "warnings",
    },
    "PROCESSOR": {
        "numpy", "torch", "math",
        "collections", "typing", "functools",
        "copy", "itertools", "logging", "warnings",
        "abc",
    },
    "IMAGE_PROCESSOR": {
        "numpy", "PIL", "torch",
        "torchvision", "cv2",
        "math", "typing", "collections",
        "copy", "logging", "warnings",
        "functools", "itertools",
    },
    "FEATURE_EXTRACTOR": {
        "numpy", "torch", "math",
        "typing", "collections", "copy",
        "logging", "warnings", "functools",
    },
    "MODELING": {
        "torch", "math", "typing",
        "collections", "copy", "functools",
        "logging", "warnings", "abc",
    },
    "CONFIGURATION": {
        "json", "os", "typing",
        "collections", "copy", "logging",
        "warnings", "math",
    },
    "UNKNOWN": {
        "torch", "math", "typing",
        "logging", "warnings",
    },
}


# ────────────────────────────────────────────────
# 결과 데이터 구조
# ────────────────────────────────────────────────

@dataclass
class ASTValidationResult:
    filename: str
    file_type: str = "UNKNOWN"
    grade: str = "B-1"                      # A / B-1 / B-2 / C
    verification_step: str = "CODE_AST_SCAN"
    status: str = "PASS"                    # PASS / FLAGGED / BLOCKED
    flags: list = field(default_factory=list)
    new_apis: list = field(default_factory=list)   # 허용 목록에 없는 신규 API
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def block(self, reason: str):
        self.status = "BLOCKED"
        self.grade  = "C"
        self.verification_step = "CODE_AST_SCAN"
        self.flags.append(reason)

    def flag(self, message: str):
        if self.status != "BLOCKED":
            self.status = "FLAGGED"
        self.flags.append(message)

    def add_new_api(self, api: str):
        """화이트리스트에 없는 신규 API 기록 → B-2로 격상"""
        if self.status == "PASS":
            self.status = "FLAGGED"
        if self.grade == "B-1":
            self.grade = "B-2"
            self.verification_step = "CODE_SANDBOX_RUNTIME"
        if api not in self.new_apis:
            self.new_apis.append(api)


# ────────────────────────────────────────────────
# 검증 단계별 함수
# ────────────────────────────────────────────────

def step1_parse(code: str, result: ASTValidationResult) -> Optional[ast.Module]:
    """① 문법 파싱 — 오류 시 즉시 BLOCKED"""
    try:
        return ast.parse(code)
    except SyntaxError as e:
        result.block(f"문법 오류 — {e}")
        return None


def step2_common_danger_scan(tree: ast.Module, result: ASTValidationResult):
    """② 공통 위험 패턴 검사 (파일 종류 무관 전부 차단)"""
    for node in ast.walk(tree):

        # 위험 import 탐지 (import X)
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in DANGEROUS_IMPORTS:
                    result.block(f"위험 모듈 import 탐지: '{alias.name}'")
                    return

        # from X import Y 우회 탐지
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]

            # 위험 모듈 전체 import
            if mod in DANGEROUS_IMPORTS:
                result.block(f"위험 모듈 from import 탐지: '{node.module}'")
                return

            # 위험 함수만 가져오는 경우 탐지
            # 예: from os import system
            for alias in node.names:
                pair = (mod, alias.name)
                if pair in DANGEROUS_FROM_IMPORTS:
                    result.block(
                        f"위험 함수 from import 탐지: "
                        f"from {node.module} import {alias.name}"
                    )
                    return

        if not isinstance(node, ast.Call):
            continue

        # 위험 함수 호출 탐지 (eval, exec 등)
        if isinstance(node.func, ast.Name):
            if node.func.id in DANGEROUS_CALL_NAMES:
                result.block(f"위험 함수 호출 탐지: {node.func.id}()")
                return

        # getattr(os, "system") 같은 위험한 조합 탐지
        # 단순 getattr 사용은 허용 (self._vocab 같은 정상 패턴)
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                # 첫 번째 인자가 위험 모듈인지 확인
                first = node.args[0]
                second = node.args[1]
                dangerous_objs = {"os", "subprocess", "sys", "builtins"}
                obj_name = first.id if isinstance(first, ast.Name) else None
                attr_val = second.value if isinstance(second, ast.Constant) else None
                if obj_name in dangerous_objs:
                    result.block(
                        f"위험한 getattr 탐지: getattr({obj_name}, '{attr_val}') "
                        f"— 동적 속성 접근으로 탐지 우회 시도"
                    )
                    return

        # 위험 메서드 호출 탐지 (torch.load, pickle.load 등)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in DANGEROUS_ATTR_CALLS:
                    if pair == ("os", "environ"):
                        result.flag(
                            "os.environ 접근 탐지 — API 키 탈취 가능성"
                        )
                    else:
                        result.block(
                            f"위험 메서드 호출 탐지: "
                            f"{node.func.value.id}.{node.func.attr}()"
                        )
                        return

            # os.environ.get() 처럼 체인된 경우 탐지
            # node.func = Attribute(value=Attribute(value=Name('os'), attr='environ'), attr='get')
            if isinstance(node.func.value, ast.Attribute):
                inner = node.func.value
                if (isinstance(inner.value, ast.Name) and
                        inner.value.id == "os" and
                        inner.attr == "environ"):
                    result.flag("os.environ 접근 탐지 — API 키 탈취 가능성")

        # numpy.load allow_pickle 탐지
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == "numpy" and
                node.func.attr == "load"):
                for kw in node.keywords:
                    if kw.arg == "allow_pickle":
                        if isinstance(kw.value, ast.Constant) and kw.value.value:
                            result.block(
                                "numpy.load(allow_pickle=True) 탐지 "
                                "— pickle 기반 역직렬화 위험"
                            )
                            return

    # 난독화 패턴 탐지 (이름 기반)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id in OBFUSCATION_PATTERNS:
                result.flag(f"난독화 의심 패턴 탐지: '{node.id}'")

        if isinstance(node, ast.Attribute):
            if node.attr in OBFUSCATION_PATTERNS:
                result.flag(f"난독화 의심 패턴 탐지: '.{node.attr}'")

    # chr() 연속 조합 탐지 (문자열 우회 생성)
    chr_count = sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "chr"
    )
    if chr_count >= 3:
        result.flag(f"chr() 연속 조합 탐지 ({chr_count}회) — 문자열 난독화 의심")


def step3_allowed_api_check(
    tree: ast.Module,
    code: str,
    result: ASTValidationResult
):
    """③ 파일 종류별 허용 API 대조
    - 허용 목록에 있음 → 통과
    - SAFE_NEW_APIS에 있음 → 참고 로그만 (B-1 유지)
    - 그 외 신규 API → B-2 격상
    - DANGEROUS_NEW_APIS → 즉시 차단
    """
    allowed = ALLOWED_IMPORTS_BY_TYPE.get(result.file_type, set())

    for node in ast.walk(tree):

        # import X 검사
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in allowed or mod in DANGEROUS_IMPORTS:
                    continue

                if mod in DANGEROUS_NEW_APIS:
                    result.block(f"네트워크 접근 가능 모듈 탐지: '{alias.name}'")
                    return
                elif mod in SAFE_NEW_APIS:
                    # 계산 전용 라이브러리 — B-1 유지, 로그만
                    result.flag(
                        f"계산 전용 신규 API: 'import {alias.name}' "
                        f"(안전 라이브러리 — B-1 유지)"
                    )
                elif mod in SUSPICIOUS_IMPORTS:
                    result.flag(f"주의 모듈 import: '{alias.name}'")
                else:
                    # 알 수 없는 신규 API → B-2
                    result.add_new_api(f"import {alias.name}")

        # from X import Y 검사
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in allowed or mod in DANGEROUS_IMPORTS:
                continue

            if mod in DANGEROUS_NEW_APIS:
                result.block(f"네트워크 접근 가능 모듈 탐지: 'from {node.module} import ...'")
                return
            elif mod in SAFE_NEW_APIS:
                result.flag(
                    f"계산 전용 신규 API: 'from {node.module} import ...' "
                    f"(안전 라이브러리 — B-1 유지)"
                )
            elif mod not in SUSPICIOUS_IMPORTS:
                result.add_new_api(f"from {node.module} import ...")

    # URL 패턴이 코드 문자열 상수에 있는지 검사
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if URL_PATTERN.match(node.value):
                result.flag(f"코드 내 외부 URL 탐지: '{node.value[:50]}'")


def step4_grade_finalize(result: ASTValidationResult):
    """④ 최종 등급 확정"""
    if result.status == "BLOCKED":
        result.grade = "C"
        result.verification_step = "CODE_AST_SCAN"
        result.status = "BLOCKED"
    elif result.new_apis:
        # 진짜 신규 API (알 수 없는 것) 있으면 B-2
        result.grade = "B-2"
        result.verification_step = "CODE_SANDBOX_RUNTIME"
        result.status = "FLAGGED"
    elif result.flags:
        # 계산 전용 신규 API 플래그만 있는 경우 B-1 유지
        only_safe_flags = all(
            "계산 전용 신규 API" in f or
            "주의 모듈" in f
            for f in result.flags
        )
        if only_safe_flags:
            result.grade = "B-1"
            result.verification_step = "CODE_RESTRICTED_RUNTIME"
            result.status = "PASS"
        else:
            # os.environ, 난독화 의심 등 → B-2
            result.grade = "B-2"
            result.verification_step = "CODE_SANDBOX_RUNTIME"
            result.status = "FLAGGED"
    else:
        result.grade = "B-1"
        result.verification_step = "CODE_RESTRICTED_RUNTIME"
        result.status = "PASS"


# ────────────────────────────────────────────────
# 메인 검증 함수
# ────────────────────────────────────────────────

def validate_preprocessing_file(
    code: str,
    filename: str = "unknown.py"
) -> ASTValidationResult:

    result = ASTValidationResult(
        filename=filename,
        file_type=classify_file(filename),
    )

    _print_header(filename, result.file_type)

    # ① 파싱
    _print_step("① AST 파싱", end=" ")
    tree = step1_parse(code, result)
    if tree is None:
        print(red("FAIL"))
        _print_result(result)
        return result
    print(green("OK"))

    # ② 공통 위험 패턴
    _print_step("② 공통 위험 패턴 검사", end=" ")
    step2_common_danger_scan(tree, result)
    if result.status == "BLOCKED":
        print(red("BLOCKED"))
        step4_grade_finalize(result)
        _print_result(result)
        return result
    elif result.flags:
        print(yellow(f"주의 ({len(result.flags)}건)"))
    else:
        print(green("OK"))

    # ③ 허용 API 대조
    _print_step("③ 허용 API 대조", end=" ")
    step3_allowed_api_check(tree, code, result)
    if result.new_apis:
        print(yellow(f"신규 API {len(result.new_apis)}개"))
    else:
        print(green("OK"))

    # ④ 등급 확정
    _print_step("④ 등급 결정", end=" ")
    step4_grade_finalize(result)
    grade_str = (
        green(result.grade)  if result.grade in ("A", "B-1") else
        yellow(result.grade) if result.grade == "B-2" else
        red(result.grade)
    )
    print(f"등급 {grade_str}  →  {dim(result.verification_step)}")

    _print_result(result)
    return result


# ────────────────────────────────────────────────
# 출력 함수
# ────────────────────────────────────────────────

def _print_header(filename: str, file_type: str):
    print(f"\n{bold('─' * 55)}")
    print(f"  🔍 검증 대상: {cyan(filename)}")
    print(f"  📂 파일 종류: {blue(file_type)}")
    print(bold('─' * 55))


def _print_step(name: str, end="\n"):
    print(f"  {blue(name):<32}", end=end)


def _print_result(result: ASTValidationResult):
    status_map = {
        "PASS":    green("✅ PASS    — 다음 단계로 전달"),
        "FLAGGED": yellow("⚠️  FLAGGED — 검토 필요"),
        "BLOCKED": red("🚫 BLOCKED — 차단"),
    }
    step_map = {
        "CODE_AST_SCAN":           dim("CODE_AST_SCAN"),
        "CODE_RESTRICTED_RUNTIME": green("CODE_RESTRICTED_RUNTIME"),
        "CODE_SANDBOX_RUNTIME":    yellow("CODE_SANDBOX_RUNTIME"),
    }

    print(f"\n  {'판정':<10}: {status_map[result.status]}")
    print(f"  {'등급':<10}: {bold(result.grade)}")
    print(f"  {'다음 단계':<10}: {step_map.get(result.verification_step, result.verification_step)}")
    print(f"  {'시각':<10}: {dim(result.timestamp)}")

    if result.flags:
        print(f"\n  {yellow('🚨 플래그 목록')}:")
        for f in result.flags:
            print(f"    - {f}")

    if result.new_apis:
        print(f"\n  {cyan('🆕 신규 API (B-2 격상 사유)')}:")
        for api in result.new_apis:
            print(f"    → {api}")
    print()


def _print_summary(results: list):
    print(bold(cyan("\n" + "═" * 55)))
    print(bold(cyan("  📊 전체 결과 요약")))
    print(bold(cyan("═" * 55)))
    print(f"  {'파일명':<35} {'종류':<18} {'등급':^4}  {'상태'}")
    print(f"  {'─'*35} {'─'*18} {'─'*4}  {'─'*10}")
    for title, r in results:
        short = title[:35]
        ftype = r.file_type[:18]
        grade_c = (
            green(r.grade)  if r.grade in ("A", "B-1") else
            yellow(r.grade) if r.grade == "B-2" else
            red(r.grade)
        )
        status_c = (
            green(r.status)  if r.status == "PASS"    else
            yellow(r.status) if r.status == "FLAGGED" else
            red(r.status)
        )
        print(f"  {short:<35} {ftype:<18} [{grade_c}]  {status_c}")
    print()


# ────────────────────────────────────────────────
# 데모 시나리오

if __name__ == "__main__":
    import sys
    filename = sys.argv[1] if len(sys.argv) > 1 else "unknown.py"
    code = sys.stdin.read().strip()
    if code:
        validate_preprocessing_file(code, filename=filename)
