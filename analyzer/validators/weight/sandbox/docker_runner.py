from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def run_in_docker(
    file_path: str,
    image_name: str = "weight-sandbox",
    timeout_sec: int = 10,
    runtime: str = "runc",
    docker_bin: str | None = None,
) -> dict:
    host_path = Path(file_path).resolve()
    docker_cmd = docker_bin or os.getenv("DOCKER_BIN", "docker")

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
            try:
                parsed = json.loads(result.stdout)
                return parsed
            except Exception:
                return {
                    "status": "BLOCK",
                    "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                    "reason": "DOCKER_NON_ZERO_EXIT",
                    "stderr": result.stderr.strip(),
                    "stdout": result.stdout.strip(),
                    "cmd": cmd,
                }

        try:
            parsed = json.loads(result.stdout)
            return parsed
        except json.JSONDecodeError:
            return {
                "status": "BLOCK",
                "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
                "reason": "INVALID_SANDBOX_JSON",
                "stdout": result.stdout.strip(),
                "cmd": cmd,
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
            "reason": "DOCKER_TIMEOUT",
            "cmd": cmd,
        }
    except Exception as e:
        return {
            "status": "BLOCK",
            "reason_code": "PICKLE_PATH_B_EXECUTION_FAILED",
            "reason": f"DOCKER_EXCEPTION: {e}",
            "cmd": cmd,
        }