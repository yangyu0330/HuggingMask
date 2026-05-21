import json
import subprocess
from pathlib import Path

import pytest

import sandbox.b2.real_command_runner as real_command_runner
from sandbox.b2.real_command_runner import RealDockerCommandRunner, redact_evidence_value, redact_text


def test_subprocess_run_uses_shell_false_and_step_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(argv: list[str], **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="container-id\n", stderr="")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)
    runner = RealDockerCommandRunner(step_timeouts={"create": 7.0})

    result = runner("create", ["docker", "create", "--name", "demo"])

    assert result.exit_code == 0
    assert result.stdout == "container-id\n"
    assert calls == [
        (
            ["docker", "create", "--name", "demo"],
            {
                "shell": False,
                "check": False,
                "capture_output": True,
                "text": True,
                "encoding": "utf-8",
                "errors": "replace",
                "timeout": 7.0,
            },
        )
    ]


def test_inspect_step_parses_stdout_json_and_redacts_sensitive_values(monkeypatch: pytest.MonkeyPatch) -> None:
    inspect_payload = [
        {
            "Args": [
                "-i",
                "HF_TOKEN=hf_12345678901234567890",
                "tokenizer_class=DemoTokenizer",
            ],
            "Config": {
                "Env": [
                    "AWS_SECRET_ACCESS_KEY=raw-secret",
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                ],
                "Labels": {"api_key": "label-secret", "tokenizer_class": "DemoTokenizer"},
            },
        }
    ]

    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(inspect_payload),
            stderr="Authorization=Bearer hf_abcdefghijklmnopqrstuvwxyz",
        )

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner()("inspect", ["docker", "inspect", "demo"])

    redacted_payload = result.fixtures["post_start_inspect"]
    serialized = json.dumps(redacted_payload)
    assert result.exit_code == 0
    assert "raw-secret" not in serialized
    assert "label-secret" not in serialized
    assert "hf_12345678901234567890" not in result.stdout
    assert "AWS_SECRET_ACCESS_KEY=[REDACTED]" in serialized
    assert redacted_payload[0]["Config"]["Labels"]["api_key"] == "[REDACTED]"
    assert redacted_payload[0]["Config"]["Labels"]["tokenizer_class"] == "DemoTokenizer"
    assert "hf_abcdefghijklmnopqrstuvwxyz" not in result.stderr


def test_logs_step_preserves_stdout_and_logs_fixture_after_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_logs = (
        '1 openat(AT_FDCWD, "/run/secrets/token", O_RDONLY|O_CLOEXEC) = -1 EACCES\n'
        "2 write(2, \"HF_TOKEN=hf_12345678901234567890\", 40) = 40\n"
    )

    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=raw_logs, stderr="")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner()("logs", ["docker", "logs", "demo"])

    assert result.exit_code == 0
    assert result.stdout == result.fixtures["logs"]
    assert "/run/secrets/[REDACTED]" in result.stdout
    assert "hf_12345678901234567890" not in result.stdout


def test_cp_step_reads_runner_result_json_into_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner_result_path = tmp_path / "runner_result.json"
    runner_result_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "request_id": "req-b2",
                "nonce": "nonce-123",
                "manifest_verified": True,
                "hf_token": "hf_12345678901234567890",
            }
        ),
        encoding="utf-8",
    )

    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner()(
        "cp",
        ["docker", "cp", "demo:/tmp/huggingmask/runner_result.json", str(runner_result_path)],
    )

    assert result.exit_code == 0
    assert result.fixtures["runner_result"]["nonce"] == "nonce-123"
    assert result.fixtures["runner_result"]["hf_token"] == "[REDACTED]"


def test_wait_step_records_container_exit_code_without_stopping_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="7\n", stderr="")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner()("wait", ["docker", "wait", "demo"])

    assert result.exit_code == 0
    assert result.fixtures["container_exit_code"] == 7


def test_evidence_dir_writes_redacted_step_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    inspect_payload = [
        {
            "Config": {"Labels": {"api_key": "label-secret"}},
            "HostConfig": {"Runtime": "runsc"},
        }
    ]

    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(inspect_payload), stderr="")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner(evidence_dir=tmp_path)("inspect", ["docker", "inspect", "demo"])

    assert result.exit_code == 0
    assert (tmp_path / "docker_inspect.json").is_file()
    inspect_text = (tmp_path / "docker_inspect.json").read_text(encoding="utf-8")
    step_text = (tmp_path / "docker_inspect_result.json").read_text(encoding="utf-8")
    assert "label-secret" not in inspect_text
    assert "label-secret" not in step_text
    assert '"api_key": "[REDACTED]"' in inspect_text


def test_rm_failure_returns_command_result_not_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="rm failed HF_TOKEN=hf_12345678901234567890")

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner()("rm", ["docker", "rm", "-f", "demo"])

    assert result.exit_code == 1
    assert "HF_TOKEN=[REDACTED]" in result.stderr
    assert "hf_12345678901234567890" not in result.stderr


def test_timeout_returns_command_result_without_secret_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=argv,
            timeout=kwargs["timeout"],
            output="HF_TOKEN=hf_12345678901234567890",
            stderr="AWS_SECRET_ACCESS_KEY=raw-secret",
        )

    monkeypatch.setattr(real_command_runner.subprocess, "run", fake_run)

    result = RealDockerCommandRunner(step_timeouts={"wait": 2.0})("wait", ["docker", "wait", "demo"])

    assert result.exit_code == 124
    assert result.stdout == "HF_TOKEN=[REDACTED]"
    assert "raw-secret" not in result.stderr
    assert "COMMAND_TIMEOUT:wait:2" in result.stderr


def test_redaction_keeps_tokenizer_terms_but_removes_credentials() -> None:
    text = "tokenizer_class=DemoTokenizer HF_TOKEN=hf_12345678901234567890 password=secret"

    redacted = redact_text(text)

    assert "tokenizer_class=DemoTokenizer" in redacted
    assert "HF_TOKEN=[REDACTED]" in redacted
    assert "password=[REDACTED]" in redacted


def test_redaction_preserves_security_event_schema_keys() -> None:
    redacted = redact_evidence_value(
        {
            "api_key": "raw-secret",
            "security_events": {
                "secret_path_access": [
                    {"path": "/run/secrets/token", "detail": "HF_TOKEN=hf_12345678901234567890"}
                ]
            },
        }
    )

    assert redacted["api_key"] == "[REDACTED]"
    assert isinstance(redacted["security_events"]["secret_path_access"], list)
    event = redacted["security_events"]["secret_path_access"][0]
    assert event["path"] == "/run/secrets/[REDACTED]"
    assert event["detail"] == "HF_TOKEN=[REDACTED]"
