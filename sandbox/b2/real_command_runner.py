"""Real subprocess-backed command runner for B-2 Docker lifecycle steps."""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sandbox.b2.host_runner_executor import CommandResult

DEFAULT_STEP_TIMEOUTS: dict[str, float] = {
    "create": 30.0,
    "start": 30.0,
    "wait": 60.0,
    "inspect": 15.0,
    "logs": 15.0,
    "cp": 15.0,
    "rm": 15.0,
}

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(token|secret|password|passwd|pwd|credentials?|api_key|access_key|private_key|authorization|bearer)($|_)",
    re.IGNORECASE,
)
_SCHEMA_KEY_ALLOWLIST = frozenset({"secret_path_access"})
_ASSIGNMENT_RE = re.compile(r"(?P<key>\b[A-Za-z_][A-Za-z0-9_-]{1,120})=(?P<value>[^,\s\"']+)")
_QUERY_ASSIGNMENT_RE = re.compile(r"(?P<prefix>[?&;](?P<key>[A-Za-z_][A-Za-z0-9_-]{1,120})=)(?P<value>[^&;\s\"']+)")
_JSON_STRING_RE = re.compile(r'(?P<prefix>"(?P<key>[^"]+)"\s*:\s*")(?P<value>[^"]*)(")')
_BEARER_RE = re.compile(r"\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_URL_USERINFO_RE = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
_TOKEN_VALUE_PATTERNS = (
    re.compile(r"\bhf_[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
)
_SECRET_PATH_PATTERNS = (
    (re.compile(r"(/run/secrets/)[^\"'\s,)]+"), r"\1[REDACTED]"),
    (re.compile(r"(/root/\.aws/)[^\"'\s,)]+"), r"\1[REDACTED]"),
    (re.compile(r"(/home/[^/\"'\s,)]+/\.aws/)[^\"'\s,)]+"), r"\1[REDACTED]"),
)


@dataclass(frozen=True)
class RealDockerCommandRunner:
    """Execute planned Docker lifecycle argv lists and collect evidence fixtures.

    runsc strace 캡처(#55 companion):
        ``runsc_strace_log_dir``가 설정되면 ``logs`` 스텝에서 그 디렉토리의 runsc
        debug/strace 로그를 읽어 **신뢰 가능한 ``runsc_logs`` 소스**로 포장한다.
        설정되지 않거나 파일이 없으면 ``docker logs`` stdout(``logs`` 키)만 남고
        이는 strace 관측 근거가 아니므로(#55) decision은 fail-closed된다.

        ⚠️ 전제(gVisor 호스트 운영 설정): runsc 런타임이 ``--strace --debug
        --debug-log=<dir>`` 로 구성돼 있어야 한다(``/etc/docker/daemon.json``의
        ``runtimes.runsc.runtimeArgs``). ``runsc_strace_log_dir``는 그 ``<dir>``과
        일치해야 한다. 본 캡처 배선의 호스트측 로직(파일 수집/포장)은 단위테스트로
        검증되지만, **runsc가 실제 strace를 그 경로에 쓰는지는 Linux+gVisor 호스트가
        있어야 e2e 검증 가능**(이 PR 미검증).
    """

    step_timeouts: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_STEP_TIMEOUTS))
    default_timeout: float = 30.0
    evidence_dir: Path | None = None
    runsc_strace_log_dir: Path | None = None
    runsc_strace_log_min_mtime: float | None = field(default_factory=time.time)

    def __call__(self, step_name: str, argv: list[str]) -> CommandResult:
        command = list(argv)
        timeout = self._timeout_for(step_name)
        try:
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return self._record_evidence(
                step_name,
                command,
                CommandResult(
                    exit_code=124,
                    stdout=redact_text(_timeout_output(exc)),
                    stderr=redact_text(f"COMMAND_TIMEOUT:{step_name}:{timeout:g}:{_timeout_stderr(exc)}"),
                ),
            )
        except FileNotFoundError as exc:
            return self._record_evidence(
                step_name,
                command,
                CommandResult(
                    exit_code=127,
                    stdout="",
                    stderr=redact_text(f"COMMAND_NOT_FOUND:{step_name}:{exc}"),
                ),
            )
        except OSError as exc:
            return self._record_evidence(
                step_name,
                command,
                CommandResult(
                    exit_code=126,
                    stdout="",
                    stderr=redact_text(f"COMMAND_OS_ERROR:{step_name}:{type(exc).__name__}:{exc}"),
                ),
            )
        except ValueError as exc:
            return self._record_evidence(
                step_name,
                command,
                CommandResult(
                    exit_code=127,
                    stdout="",
                    stderr=redact_text(f"COMMAND_INVALID:{step_name}:{exc}"),
                ),
            )

        stdout = redact_text(_to_text(completed.stdout))
        stderr = redact_text(_to_text(completed.stderr))
        exit_code = int(completed.returncode)
        fixtures, fixture_error, fixture_exit_code = _fixtures_for_step(
            step_name,
            command,
            completed,
            runsc_strace_log_dir=self.runsc_strace_log_dir,
            runsc_strace_log_min_mtime=self.runsc_strace_log_min_mtime,
        )
        if fixture_error:
            stderr = _append_stderr(stderr, fixture_error)
        if fixture_exit_code is not None and exit_code == 0:
            exit_code = fixture_exit_code
        return self._record_evidence(
            step_name,
            command,
            CommandResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                fixtures=fixtures,
            ),
        )

    def _timeout_for(self, step_name: str) -> float:
        return float(self.step_timeouts.get(step_name, self.default_timeout))

    def _record_evidence(self, step_name: str, argv: list[str], result: CommandResult) -> CommandResult:
        error = _write_step_evidence(self.evidence_dir, step_name, argv, result)
        if not error:
            return result
        return CommandResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=_append_stderr(result.stderr, error),
            fixtures=result.fixtures,
        )


def redact_evidence_value(value: Any) -> Any:
    """Return a JSON-compatible evidence value with credentials removed."""

    if isinstance(value, Mapping):
        return {
            key: _REDACTED if _is_sensitive_key(str(key)) else redact_evidence_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_evidence_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_evidence_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    if not text:
        return ""

    redacted = _URL_USERINFO_RE.sub("://[REDACTED]@", text)
    redacted = _BEARER_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _ASSIGNMENT_RE.sub(_redact_assignment_match, redacted)
    redacted = _QUERY_ASSIGNMENT_RE.sub(_redact_query_match, redacted)
    redacted = _JSON_STRING_RE.sub(_redact_json_match, redacted)
    for pattern in _TOKEN_VALUE_PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    for pattern, replacement in _SECRET_PATH_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _fixtures_for_step(
    step_name: str,
    argv: list[str],
    completed: subprocess.CompletedProcess[str],
    runsc_strace_log_dir: Path | None = None,
    runsc_strace_log_min_mtime: float | None = None,
) -> tuple[dict[str, Any], str, int | None]:
    if int(completed.returncode) != 0:
        if step_name == "logs":
            return _logs_fixtures(argv, completed, runsc_strace_log_dir, runsc_strace_log_min_mtime)
        return {}, "", None

    if step_name == "inspect":
        return _inspect_fixture(_to_text(completed.stdout))
    if step_name == "wait":
        return _wait_fixture(_to_text(completed.stdout))
    if step_name == "logs":
        return _logs_fixtures(argv, completed, runsc_strace_log_dir, runsc_strace_log_min_mtime)
    if step_name == "cp":
        return _cp_fixture(argv)
    return {}, "", None


def _logs_fixtures(
    argv: list[str],
    completed: subprocess.CompletedProcess[str],
    runsc_strace_log_dir: Path | None,
    runsc_strace_log_min_mtime: float | None = None,
) -> tuple[dict[str, Any], str, int | None]:
    """``logs`` 스텝 fixtures. runsc strace가 캡처되면 신뢰 ``runsc_logs``로 포장.

    docker logs stdout(``logs``)은 strace 단독 근거가 아니므로(#55), runsc_logs가
    잡혀야만 decision이 clean review 경로로 갈 수 있다. runsc_strace_log_dir 미설정
    또는 파일 부재면 runsc_logs는 비고 → strace 미관측(fail-closed) 유지.
    """
    fixtures: dict[str, Any] = {}
    if runsc_strace_log_dir is not None:
        strace = _read_runsc_strace(
            runsc_strace_log_dir,
            _container_from_logs_argv(argv),
            min_mtime=runsc_strace_log_min_mtime,
        )
        if strace:
            fixtures["runsc_logs"] = redact_text(strace)
    logs = redact_text(_to_text(completed.stdout))
    if logs:
        fixtures["logs"] = logs
    return fixtures, "", None


def _container_from_logs_argv(argv: list[str]) -> str:
    """``docker logs <container>`` 에서 컨테이너 이름(마지막 비-플래그 토큰).

    서브커맨드 토큰(``docker``/``logs``)은 컨테이너로 오인하지 않는다.
    """
    for token in reversed(argv):
        if token and not token.startswith("-") and token not in {"docker", "logs"}:
            return token
    return ""


def _read_runsc_strace(log_dir: Path | str, container: str, *, min_mtime: float | None = None) -> str | None:
    """runsc ``--debug-log`` 디렉토리에서 이 컨테이너의 strace/debug 로그 수집.

    파일명 또는 상위 디렉토리명에 컨테이너 식별자가 포함된 파일을 모아 합친다.
    파일이 없으면 None → 호출측에서 runsc_logs 미포장(strace 미관측).
    """
    directory = Path(log_dir)
    if not directory.is_dir():
        return None
    paths = _runsc_strace_paths(directory, container, min_mtime=min_mtime)
    parts: list[str] = []
    for path in paths:
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    text = "\n".join(p for p in parts if p)
    return text or None


def _runsc_strace_paths(directory: Path, container: str, *, min_mtime: float | None) -> list[Path]:
    files = list(_recent_files(directory, min_mtime=min_mtime))
    container_matches = [path for path in files if _path_matches_container(path, container)]
    if container_matches:
        return sorted(container_matches)

    boot_logs = [path for path in files if _looks_like_runsc_boot_log(path)]
    if len(boot_logs) == 1:
        return boot_logs
    return []


def _recent_files(directory: Path, *, min_mtime: float | None) -> list[Path]:
    files: list[Path] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if min_mtime is not None:
            try:
                if path.stat().st_mtime < min_mtime:
                    continue
            except OSError:
                continue
        files.append(path)
    return files


def _path_matches_container(path: Path, container: str) -> bool:
    if not container:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(container)}(?![A-Za-z0-9])")
    return any(pattern.search(part) for part in (path.name, *path.parent.parts))


def _looks_like_runsc_boot_log(path: Path) -> bool:
    name = path.name.lower()
    return ".boot" in name or name.endswith("boot")


def _inspect_fixture(stdout: str) -> tuple[dict[str, Any], str, int | None]:
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {}, redact_text(f"INSPECT_JSON_ERROR:{exc.msg}"), 1
    return {"post_start_inspect": redact_evidence_value(parsed)}, "", None


def _wait_fixture(stdout: str) -> tuple[dict[str, Any], str, int | None]:
    text = stdout.strip()
    if not text:
        return {}, "WAIT_EXIT_CODE_MISSING", None
    try:
        return {"container_exit_code": int(text.splitlines()[-1].strip())}, "", None
    except ValueError:
        return {}, "WAIT_EXIT_CODE_PARSE_ERROR", None


def _cp_fixture(argv: list[str]) -> tuple[dict[str, Any], str, int | None]:
    if not argv:
        return {}, "RUNNER_RESULT_READ_ERROR:missing cp target", 1
    target = Path(argv[-1])
    try:
        raw_text = target.read_text(encoding="utf-8")
    except OSError as exc:
        return {}, redact_text(f"RUNNER_RESULT_READ_ERROR:{type(exc).__name__}:{exc}"), 1

    redacted_text = redact_text(raw_text)
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return {"runner_result_json": redacted_text}, "RUNNER_RESULT_JSON_ERROR:JSONDecodeError", None
    if not isinstance(parsed, Mapping):
        return {"runner_result_json": redacted_text}, "RUNNER_RESULT_JSON_ERROR:root_not_object", None
    return {"runner_result": redact_evidence_value(parsed)}, "", None


def _redact_assignment_match(match: re.Match[str]) -> str:
    key = match.group("key")
    if not _is_sensitive_key(key):
        return match.group(0)
    return f"{key}={_REDACTED}"


def _redact_query_match(match: re.Match[str]) -> str:
    if not _is_sensitive_key(match.group("key")):
        return match.group(0)
    return f"{match.group('prefix')}{_REDACTED}"


def _redact_json_match(match: re.Match[str]) -> str:
    if not _is_sensitive_key(match.group("key")):
        return match.group(0)
    return f"{match.group('prefix')}{_REDACTED}{match.group(4)}"


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().replace("-", "_").lower()
    if normalized in _SCHEMA_KEY_ALLOWLIST:
        return False
    return bool(_SENSITIVE_KEY_RE.search(normalized))


def _append_stderr(stderr: str, message: str) -> str:
    clean_message = redact_text(message)
    if not stderr:
        return clean_message
    return f"{stderr}\n{clean_message}"


def _write_step_evidence(
    evidence_dir: Path | None,
    step_name: str,
    argv: list[str],
    result: CommandResult,
) -> str:
    if evidence_dir is None:
        return ""
    try:
        root = Path(evidence_dir)
        root.mkdir(parents=True, exist_ok=True)
        record = {
            "step": step_name,
            "argv": redact_evidence_value(argv),
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "fixtures": result.fixtures,
        }
        _write_json(root / f"docker_{step_name}_result.json", record)
        if step_name == "create":
            _write_json(root / "docker_create_argv.json", redact_evidence_value(argv))
        elif step_name == "inspect" and "post_start_inspect" in result.fixtures:
            _write_json(root / "docker_inspect.json", result.fixtures["post_start_inspect"])
        elif step_name == "logs":
            (root / "docker_logs.txt").write_text(result.stdout, encoding="utf-8")
    except OSError as exc:
        return redact_text(f"EVIDENCE_WRITE_ERROR:{step_name}:{type(exc).__name__}:{exc}")
    return ""


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(redact_evidence_value(payload), sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
    return _to_text(getattr(exc, "stdout", None) or getattr(exc, "output", None))


def _timeout_stderr(exc: subprocess.TimeoutExpired) -> str:
    return _to_text(getattr(exc, "stderr", None))


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
