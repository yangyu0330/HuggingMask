import json
import argparse
from pathlib import Path

from analyzer.validators.weight.pipeline import validate


def _infer_file_kind(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".safetensors":
        return "SAFETENSORS"
    return "PICKLE"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validate a weight artifact.")
    parser.add_argument("file_path")
    parser.add_argument("--policy-fingerprint", default="cli-policy")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--file-kind", choices=["SAFETENSORS", "PICKLE"])
    parser.add_argument("--enable-path-b", action="store_true")
    args = parser.parse_args(argv)

    result = validate(
        args.file_path,
        policy_fingerprint=args.policy_fingerprint,
        expected_sha256=args.expected_sha256,
        file_kind=args.file_kind or _infer_file_kind(args.file_path),
        enable_path_b=args.enable_path_b,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
