"""B-2 runsc strace 캡처 배선(#55 companion) 단위 테스트.

검증 범위(정직): 호스트측 로직만 — runsc debug-log 디렉토리에서 컨테이너 strace를
수집해 신뢰 ``runsc_logs`` 소스로 포장하고, 그것이 #55 게이트에서 strace 관측으로
인정되는지. **runsc가 실제 strace를 그 경로에 쓰는지는 Linux+gVisor 호스트 필요(미검증).**
"""
import os
import subprocess
import time

from sandbox.b2.real_command_runner import (
    _container_from_logs_argv,
    _logs_fixtures,
    _read_runsc_strace,
)


def _completed(stdout: str = "", rc: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr="")


def test_container_from_logs_argv():
    assert _container_from_logs_argv(["docker", "logs", "huggingmask-b2-req-job-0"]) == "huggingmask-b2-req-job-0"
    assert _container_from_logs_argv(["docker", "logs", "--tail", "100", "cName"]) == "cName"
    assert _container_from_logs_argv(["docker", "logs"]) == ""


def test_read_runsc_strace_collects_container_files(tmp_path):
    sub = tmp_path / "cabc"
    sub.mkdir()
    (sub / "boot.log").write_text('1 openat(AT_FDCWD, "/x") = 3\n', encoding="utf-8")
    out = _read_runsc_strace(tmp_path, "cabc")
    assert out is not None and "openat" in out


def test_read_runsc_strace_collects_single_recent_boot_log_without_container_name(tmp_path):
    (tmp_path / "runsc.log.20260609-010203.000000.boot.txt").write_text(
        '1 openat(AT_FDCWD, "/x") = 3\n',
        encoding="utf-8",
    )

    out = _read_runsc_strace(tmp_path, "cabc", min_mtime=time.time() - 60)

    assert out is not None and "openat" in out


def test_read_runsc_strace_ignores_stale_boot_logs(tmp_path):
    boot = tmp_path / "runsc.log.20260609-010203.000000.boot.txt"
    boot.write_text('1 openat(AT_FDCWD, "/stale") = 3\n', encoding="utf-8")
    stale_mtime = time.time() - 3600
    os.utime(boot, (stale_mtime, stale_mtime))

    assert _read_runsc_strace(tmp_path, "cabc", min_mtime=time.time() - 60) is None


def test_read_runsc_strace_fails_closed_for_ambiguous_generic_boot_logs(tmp_path):
    (tmp_path / "runsc.log.20260609-010203.000000.boot.txt").write_text(
        '1 openat(AT_FDCWD, "/a") = 3\n',
        encoding="utf-8",
    )
    (tmp_path / "runsc.log.20260609-010204.000000.boot.txt").write_text(
        '2 openat(AT_FDCWD, "/b") = 3\n',
        encoding="utf-8",
    )

    assert _read_runsc_strace(tmp_path, "cabc", min_mtime=time.time() - 60) is None


def test_read_runsc_strace_prefers_container_specific_logs_when_boot_logs_are_ambiguous(tmp_path):
    (tmp_path / "runsc.log.20260609-010203.000000.boot.txt").write_text(
        '1 openat(AT_FDCWD, "/generic") = 3\n',
        encoding="utf-8",
    )
    specific = tmp_path / "runsc.log.cabc.boot.txt"
    specific.write_text('2 openat(AT_FDCWD, "/specific") = 3\n', encoding="utf-8")

    out = _read_runsc_strace(tmp_path, "cabc", min_mtime=time.time() - 60)

    assert out is not None
    assert "/specific" in out
    assert "/generic" not in out


def test_read_runsc_strace_none_when_no_match(tmp_path):
    (tmp_path / "other.log").write_text("unrelated noise", encoding="utf-8")
    assert _read_runsc_strace(tmp_path, "cabc") is None
    assert _read_runsc_strace(tmp_path / "missing", "cabc") is None


def test_logs_fixtures_packages_runsc_logs_when_strace_present(tmp_path):
    sub = tmp_path / "cZ"
    sub.mkdir()
    (sub / "strace.log").write_text('42 connect(AF_INET, ...) = -1\n', encoding="utf-8")
    fx, err, code = _logs_fixtures(["docker", "logs", "cZ"], _completed("container stdout"), tmp_path)
    assert "runsc_logs" in fx and "connect" in fx["runsc_logs"]
    # docker logs stdout은 보조 증거로 남되 신뢰 strace는 아님
    assert fx.get("logs") == "container stdout"
    assert err == "" and code is None


def test_logs_fixtures_no_runsc_logs_without_strace(tmp_path):
    # strace 디렉토리 설정됐지만 컨테이너 파일 없음 → runsc_logs 미포장(fail-closed)
    fx, _, _ = _logs_fixtures(["docker", "logs", "cZ"], _completed("stdout only"), tmp_path)
    assert "runsc_logs" not in fx
    # runsc_strace_log_dir 미설정도 동일(기존 동작)
    fx2, _, _ = _logs_fixtures(["docker", "logs", "cZ"], _completed("stdout only"), None)
    assert "runsc_logs" not in fx2


def test_captured_runsc_logs_are_trusted_and_observed():
    # 캡처된 runsc_logs가 #55 게이트에서 신뢰 strace로 인정되고 관측됨(end-to-end 배선).
    from sandbox.b2.host_runner_executor import CommandResult, _has_trusted_runsc_source
    from sandbox.b2.runsc_log_parser import parse_runsc_logs

    fx = {"runsc_logs": '1 openat(AT_FDCWD, "/x") = 3\n', "logs": "stdout noise"}
    results = {"logs": CommandResult(fixtures=fx)}
    assert _has_trusted_runsc_source(results) is True
    assert parse_runsc_logs(fx["runsc_logs"]).strace_observed is True
