import json
import sys

from validators.weigth.pipeline import validate


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m validators.weigth.cli <file_path>")
        sys.exit(1)

    path = sys.argv[1]
    result = validate(path)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()