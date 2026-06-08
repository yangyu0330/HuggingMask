"""Fixture parser for B-2 runsc debug/strace evidence.

The parser is intentionally coarse. It consumes already-collected log text and
normalizes security-relevant events without invoking runsc or reading host logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterable

from sandbox.b2.schemas import SecurityEvents

_SYSCALL_RE = re.compile(
    r"\b(?P<syscall>execve|connect|socket|sendto|recvfrom|sendmsg|recvmsg|openat|open|write|creat|mkdir|rename|unlink|clone3|clone)\s*\(",
)
_QUOTED_RE = re.compile(r'"([^"]*)"')

_NETWORK_SYSCALLS = {"connect", "socket", "sendto", "recvfrom", "sendmsg", "recvmsg"}
_WRITE_SYSCALLS = {"write", "creat", "mkdir", "rename", "unlink"}
_SECRET_PREFIXES = (
    "/run/secrets",
    "/var/run/docker.sock",
    "/root/.aws",
    "/home/.aws",
    "/etc/shadow",
)
_BLOCKED_READ_PREFIXES = ("/sys", "/dev/nvidia")
_ALLOWED_WRITE_PREFIXES = (
    "/tmp",
    "/tmp/huggingmask",
    "/tmp/hf",
    "/tmp/torch",
    "/tmp/cache",
    "/dev/null",
)
_TRUSTED_EXEC_PATHS = {
    "/usr/local/bin/python",
    "/usr/bin/python",
    "/usr/bin/env",
}
_SUSPICIOUS_EXEC_NAMES = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "pip",
    "curl",
    "wget",
    "gcc",
    "g++",
    "cc",
    "make",
    "cmake",
    "python",
    "python3",
}


@dataclass(frozen=True)
class RunscLogParseResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    security_events: SecurityEvents = field(default_factory=SecurityEvents)
    log_complete: bool = True
    # runsc strace 증거가 실제로 존재했는지. 로그 소스 자체가 없으면(LOG_MISSING)
    # False — "syscall을 관측하지 못했다"는 뜻이고, require_runsc_strace 정책이
    # 켜져 있으면 결정 빌더가 이를 clean으로 인증하지 않는다.
    strace_observed: bool = True
    errors: list[str] = field(default_factory=list)

    def decision_builder_kwargs(self) -> dict[str, Any]:
        return {
            "security_events": self.security_events,
            "log_complete": self.log_complete,
            "strace_observed": self.strace_observed,
        }


def parse_runsc_logs(log_texts: str | Iterable[str | None] | None) -> RunscLogParseResult:
    """Parse one or more runsc log fixture strings into SecurityEvents."""

    if log_texts is None:
        return RunscLogParseResult(log_complete=False, strace_observed=False, errors=["LOG_MISSING"])
    if isinstance(log_texts, str):
        chunks: list[str | None] = [log_texts]
    else:
        chunks = list(log_texts)
    if not chunks or all(not chunk for chunk in chunks):
        return RunscLogParseResult(log_complete=False, strace_observed=False, errors=["LOG_MISSING"])

    events: list[dict[str, Any]] = []
    errors: list[str] = []
    log_complete = True
    for index, chunk in enumerate(chunks):
        if not chunk:
            log_complete = False
            errors.append("LOG_MISSING")
            continue
        parsed = parse_runsc_log_text(chunk, source=f"runsc:{index}")
        events.extend(parsed.events)
        if not parsed.log_complete:
            log_complete = False
            errors.extend(parsed.errors or ["LOG_INCOMPLETE"])

    security_events = classify_security_events(events)
    return RunscLogParseResult(
        events=events,
        security_events=security_events,
        log_complete=log_complete,
        errors=_dedupe(errors),
    )


def parse_runsc_log_text(log_text: str | None, *, source: str = "runsc") -> RunscLogParseResult:
    if not log_text:
        return RunscLogParseResult(log_complete=False, strace_observed=False, errors=["LOG_MISSING"])

    events: list[dict[str, Any]] = []
    errors: list[str] = []
    log_complete = True
    for line_number, raw_line in enumerate(log_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if any(marker in lower for marker in ("log incomplete", "truncated", "dropped events", "lost events")):
            log_complete = False
            errors.append("LOG_INCOMPLETE")
        event = _parse_line(line, source=source, line_number=line_number)
        if event is not None:
            events.append(event)

    return RunscLogParseResult(
        events=events,
        security_events=classify_security_events(events),
        log_complete=log_complete,
        errors=_dedupe(errors),
    )


def classify_security_events(
    events: Iterable[dict[str, Any]],
    *,
    trusted_exec_paths: Iterable[str] | None = None,
    allowed_write_prefixes: Iterable[str] | None = None,
) -> SecurityEvents:
    trusted_execs = set(trusted_exec_paths or _TRUSTED_EXEC_PATHS)
    allowed_writes = tuple(allowed_write_prefixes or _ALLOWED_WRITE_PREFIXES)
    security = SecurityEvents()

    for event in events:
        event_type = str(event.get("event_type") or "")
        path = str(event.get("path") or "")
        if event_type in {"connect", "socket", "dns", "sendto", "recvfrom", "sendmsg", "recvmsg"}:
            security.network_events.append(event)
            continue
        if event_type == "execve" and _is_unexpected_execve(event, trusted_execs):
            security.unexpected_execve.append(event)
            continue
        if event_type == "write" and path and _is_blocked_write_path(path, allowed_writes):
            security.blocked_writes.append(event)
            continue
        if path and _is_secret_path(path):
            security.secret_path_access.append(event)
            continue
        if path and _is_blocked_read_path(path):
            security.blocked_reads.append(event)
            continue
        if event_type in {"clone", "clone3"} or path in {"/proc/cpuinfo", "/proc/meminfo"}:
            review_event = dict(event)
            review_event.setdefault("severity", "MEDIUM")
            security.review_events.append(review_event)

    return security


def _parse_line(line: str, *, source: str, line_number: int) -> dict[str, Any] | None:
    match = _SYSCALL_RE.search(line)
    if not match:
        return None
    syscall = match.group("syscall")
    event_type = _event_type_for_syscall(syscall, line)
    quoted = _QUOTED_RE.findall(line)
    event: dict[str, Any] = {
        "event_type": event_type,
        "syscall": syscall,
        "raw": line[:500],
        "source": source,
        "line_number": line_number,
    }
    pid = _extract_pid(line)
    if pid is not None:
        event["pid"] = pid
    family = _extract_family(line)
    if family is not None:
        event["family"] = family
    path = _extract_path(syscall, quoted)
    if path is not None:
        event["path"] = path
    if syscall == "execve":
        event["argv"] = _extract_exec_argv(quoted)
    return event


def _event_type_for_syscall(syscall: str, line: str) -> str:
    if syscall in {"open", "openat"}:
        quoted = _QUOTED_RE.findall(line)
        path = _extract_path(syscall, quoted)
        if path in {"/etc/resolv.conf", "/etc/hosts"}:
            return "dns"
        if any(flag in line for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
            return "write"
        return "open"
    if syscall in _NETWORK_SYSCALLS:
        if syscall == "socket":
            return "socket" if _extract_family(line) in {"AF_INET", "AF_INET6"} else "socket_local"
        if _extract_family(line) in {"AF_INET", "AF_INET6"} or syscall != "socket":
            return syscall
    if syscall in _WRITE_SYSCALLS:
        return "write"
    return syscall


def _extract_path(syscall: str, quoted: list[str]) -> str | None:
    if not quoted:
        return None
    if syscall == "execve":
        return quoted[0]
    if syscall == "write":
        return None
    for value in quoted:
        if value.startswith("/"):
            return value
    return quoted[0] if quoted[0] else None


def _extract_exec_argv(quoted: list[str]) -> list[str]:
    if not quoted:
        return []
    return quoted[:8]


def _extract_family(line: str) -> str | None:
    if "AF_INET6" in line:
        return "AF_INET6"
    if "AF_INET" in line:
        return "AF_INET"
    if "AF_UNIX" in line:
        return "AF_UNIX"
    return None


def _extract_pid(line: str) -> int | None:
    match = re.search(r"\b(?:pid=|pid\s+)(\d+)\b", line)
    if match:
        return int(match.group(1))
    prefix = re.match(r"^\D*(\d+)\s+", line)
    if prefix:
        return int(prefix.group(1))
    return None


def _is_unexpected_execve(event: dict[str, Any], trusted_execs: set[str]) -> bool:
    path = str(event.get("path") or "")
    if path in trusted_execs:
        return False
    name = PurePosixPath(path).name
    return name in _SUSPICIOUS_EXEC_NAMES or bool(path)


def _is_blocked_write_path(path: str, allowed_prefixes: tuple[str, ...]) -> bool:
    if not path:
        return True
    if path == "/sandbox/input" or path.startswith("/sandbox/input/"):
        return True
    return not any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in allowed_prefixes)


def _is_secret_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in _SECRET_PREFIXES)


def _is_blocked_read_path(path: str) -> bool:
    if _is_secret_path(path):
        return True
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in _BLOCKED_READ_PREFIXES)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
