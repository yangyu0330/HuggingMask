"""전처리 baseline 레지스트리 시드 — 인기 base 모델의 tokenizer/config 정상본 해시 등록.

    python scripts/seed_baselines.py

huggingface_hub 으로 각 모델의 메타/전처리 파일을 받아 sha256 을 레지스트리에 등록한다.
같은 토크나이저는 수많은 파인튜닝 모델에서 내용이 동일하므로, 적은 시드로 대부분의 전처리가
자동 통과(BASELINE_MATCH)된다. (서버 셸엔 HF_ENDPOINT 없이 실 HF 로 직접 받아야 함.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for k in ("HF_ENDPOINT", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(k, None)
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

from analyzer.validators.baseline_registry import register_baseline, reload  # noqa: E402

# 검증된/인기 base 모델 — 파인튜닝 모델 대부분이 이 토크나이저를 그대로 씀
SEED_REPOS = [
    "bert-base-uncased",
    "bert-base-cased",
    "distilbert-base-uncased",
    "roberta-base",
    "gpt2",
    "sentence-transformers/all-MiniLM-L6-v2",
    # 데모 모델
    "hf-internal-testing/tiny-random-bert",
]

# 전처리/메타 텍스트 파일(가중치 제외)
META_FILES = [
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "vocab.txt",
    "vocab.json",
    "merges.txt",
    "added_tokens.json",
]


def main() -> None:
    from huggingface_hub import hf_hub_download
    from huggingface_hub.utils import EntryNotFoundError

    registered = 0
    for repo in SEED_REPOS:
        for fname in META_FILES:
            try:
                path = hf_hub_download(repo_id=repo, filename=fname)
            except EntryNotFoundError:
                continue  # 그 모델엔 없는 파일 — 정상
            except Exception as e:  # noqa: BLE001
                print(f"  [skip] {repo}/{fname}: {type(e).__name__}")
                continue
            data = Path(path).read_bytes()
            if not data:
                continue
            register_baseline(data, repo_id=repo, file_name=fname, note="seed", persist=False)
            registered += 1
            print(f"  [ok] {repo}/{fname} ({len(data)} bytes)")

    # 한 번에 저장(persist=False 로 모았다가 마지막에 flush)
    from analyzer.validators.baseline_registry import _load, _save  # noqa

    _save(_load())
    reload()
    print(f"\n등록 완료: {registered}개 파일. 레지스트리: analyzer/assets/preprocessing_baselines.json")


if __name__ == "__main__":
    main()
