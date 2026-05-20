from __future__ import annotations

import json
import os
import secrets
import subprocess
from pathlib import Path


RESULT_PREFIX = "HM_SANDBOX_RESULT"


def _parse_sandbox_result(stdout: str, nonce: str) -> dict:
    expected_prefix = f"{RESULT_PREFIX}:{nonce}:"

    for line in reversed(stdout.splitlines()):
        if not line.startswith(expected_prefix):
            continue

        payload = line[len(expected_prefix):]
        parsed = json.loads(payload)

        if not isinstance(parsed, dict):
            raise ValueError("sandbox result is not a JSON object")

        if parsed.get("status") not in {"PASS", "BLOCK", "SKIP", "SKIPPED"}:
            raise ValueError("sandbox result has invalid status")

        return parsed

    raise ValueError("sandbox result line with expected prefix/nonce not found")


def run_in_docker(
    file_path: str,
    image_name: str = "weight-sandbox",
    timeout_sec: int = 10,
    runtime: str = "runsc",
    docker_bin: str | None = None,
) -> dict:
    host_path = Path(file_path).resolve()
    docker_cmd = docker_bin or os.getenv("DOCKER_BIN", "docker")
    nonce = secrets.token_hex(16)

    mount_arg = f"{host_path}:/input/model.pkl:ro"

    cmd = [
        docker_cmd,
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--memory=1g",
        "--cpus=1",
        "--runtime",
        runtime,
        "-e",
        f"HM_SANDBOX_NONCE={nonce}",
        "-v",
        mount_arg,
        image_name,
        "python",
        "/app/load_and_extract.py",
        "/input/model.pkl",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )

        if result.returncode != 0:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                "reason": "DOCKER_NON_ZERO_EXIT",
                "runtime": runtime,
                "stderr": result.stderr.strip(),
                "stdout": result.stdout.strip(),
                "cmd": cmd,
            }

        try:
            parsed = _parse_sandbox_result(result.stdout, nonce)
        except (json.JSONDecodeError, ValueError) as e:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                "reason": f"INVALID_SANDBOX_JSON: {e}",
                "runtime": runtime,
                "stdout": result.stdout.strip(),
                "cmd": cmd,
            }

        parsed["runtime"] = runtime
        return parsed

    except subprocess.TimeoutExpired:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
            "reason": "DOCKER_TIMEOUT",
            "runtime": runtime,
            "cmd": cmd,
        }

    except FileNotFoundError as e:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_NOT_AVAILABLE",
            "reason": f"Docker executable not available: {e}",
            "runtime": runtime,
            "cmd": cmd,
        }

    except OSError as e:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_NOT_AVAILABLE",
            "reason": f"Docker/gVisor Path B not available: {e}",
            "runtime": runtime,
            "cmd": cmd,
        }