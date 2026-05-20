from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.runsc_log_parser import parse_runsc_log_text, parse_runsc_logs


def _clean_runner_result() -> dict:
    return {
        "schema_version": "1.0",
        "request_id": "req-b2",
        "nonce": "nonce-123",
        "manifest_verified": True,
        "import_status": "success",
        "instantiate_status": "success",
        "forward_status": "success",
    }


def test_runsc_fixture_classifies_hard_security_events() -> None:
    log_text = """
123 execve("/bin/sh", ["sh", "-c", "curl http://example.invalid"], 0x7ffd) = 0
124 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
125 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 EACCES
126 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_WRONLY|O_CREAT, 0644) = -1 EROFS
127 openat(AT_FDCWD, "/run/secrets/token", O_RDONLY|O_CLOEXEC) = -1 EACCES
128 openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY|O_CLOEXEC) = 3
129 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_THREAD) = 321
"""

    result = parse_runsc_log_text(log_text)

    assert result.log_complete is True
    assert result.errors == []
    assert any(event["syscall"] == "execve" for event in result.events)
    assert result.security_events.unexpected_execve[0]["path"] == "/bin/sh"
    assert {event["syscall"] for event in result.security_events.network_events} >= {"socket", "connect", "openat"}
    assert result.security_events.blocked_writes[0]["path"] == "/sandbox/input/modeling_demo.py"
    assert result.security_events.secret_path_access[0]["path"] == "/run/secrets/token"
    assert result.security_events.review_events[0]["syscall"] == "clone"


def test_runsc_parser_security_events_feed_decision_builder() -> None:
    result = parse_runsc_logs(
        """
42 socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) = 3
43 sendto(3, "query", 5, 0, {sa_family=AF_INET6}, 28) = -1 EACCES
"""
    )

    check = build_sandbox_check_from_runner_result(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        runner_result=_clean_runner_result(),
        expected_nonce="nonce-123",
        security_events=result.security_events,
        log_complete=result.log_complete,
    )

    assert result.security_events.network_events
    assert check["decision"] == "BLOCKED_SECURITY_EVENT"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_SECURITY_EVENT"


def test_log_missing_and_incomplete_are_preserved_for_log_incomplete_decision() -> None:
    missing = parse_runsc_logs(None)
    incomplete = parse_runsc_logs("runsc: dropped events; log incomplete")

    assert missing.log_complete is False
    assert missing.errors == ["LOG_MISSING"]
    assert incomplete.log_complete is False
    assert incomplete.errors == ["LOG_INCOMPLETE"]

    check = build_sandbox_check_from_runner_result(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        runner_result=_clean_runner_result(),
        expected_nonce="nonce-123",
        security_events=missing.security_events,
        log_complete=missing.log_complete,
    )

    assert check["decision"] == "LOG_INCOMPLETE"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_LOG_INCOMPLETE"


def test_allowed_reads_and_writes_do_not_create_hard_events() -> None:
    result = parse_runsc_logs(
        """
1 openat(AT_FDCWD, "/sandbox/input/modeling_demo.py", O_RDONLY|O_CLOEXEC) = 3
2 openat(AT_FDCWD, "/usr/local/lib/python3.13/os.py", O_RDONLY|O_CLOEXEC) = 4
3 openat(AT_FDCWD, "/tmp/huggingmask/runner_result.json", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 5
4 openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY|O_CLOEXEC) = 6
5 write(1, "runner ready\\n", 13) = 13
"""
    )

    assert result.security_events.network_events == []
    assert result.security_events.unexpected_execve == []
    assert result.security_events.blocked_writes == []
    assert result.security_events.secret_path_access == []
    assert result.security_events.blocked_reads == []
    assert result.security_events.review_events[0]["path"] == "/proc/cpuinfo"
