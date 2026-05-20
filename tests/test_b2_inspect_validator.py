from __future__ import annotations

import copy

import pytest

from sandbox.b2.decision_builder import build_sandbox_check_from_runner_result
from sandbox.b2.inspect_validator import validate_docker_inspect
from sandbox.b2.schemas import ManifestEvidence, RuntimeEvidence


IMAGE_REF = "huggingmask/b2-runner@sha256:" + "1" * 64


def _inspect_fixture() -> dict:
    return {
        "Id": "container-123",
        "Path": "/usr/bin/env",
        "Args": [
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONNOUSERSITE=1",
            "PYTHONDONTWRITEBYTECODE=1",
            "HUGGINGMASK_REQUEST_ID=req-b2",
            "HUGGINGMASK_JOB_ID=job-b2",
            "HUGGINGMASK_NONCE=nonce-123",
            "/usr/local/bin/python",
            "-I",
            "-S",
            "/app/huggingmask_runner/b2_entrypoint.py",
            "--manifest",
            "/sandbox/input/b2_input_manifest.json",
            "--nonce",
            "nonce-123",
        ],
        "Config": {
            "Image": IMAGE_REF,
            "User": "1000:1000",
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        },
        "HostConfig": {
            "Runtime": "runsc-b2-debug",
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": 128,
            "Memory": 2 * 1024 * 1024 * 1024,
            "NanoCpus": 1_500_000_000,
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/jobs/job-b2/input",
                "Destination": "/sandbox/input",
                "Mode": "ro",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": "/jobs/job-b2/evidence",
                "Destination": "/tmp/huggingmask",
                "Mode": "rw",
                "RW": True,
            },
        ],
    }


def _validate(payload: dict):
    return validate_docker_inspect(
        [payload],
        expected_docker_runtime="runsc-b2-debug",
        expected_image_ref=IMAGE_REF,
        expected_input_source="/jobs/job-b2/input",
        expected_output_source="/jobs/job-b2/evidence",
        expected_pids_limit=128,
        expected_memory_limit="2g",
        expected_cpu_limit="1.5",
    )


def test_valid_inspect_fixture_normalizes_runtime_evidence() -> None:
    ok, evidence, errors = _validate(_inspect_fixture())

    assert ok is True
    assert errors == []
    assert isinstance(evidence, RuntimeEvidence)
    assert evidence.runtime == "runsc-b2-debug"
    assert evidence.image_ref == IMAGE_REF
    assert evidence.network_mode == "none"
    assert evidence.rootfs_readonly is True
    assert evidence.cap_drop_all is True
    assert evidence.no_new_privileges is True
    assert evidence.non_root_user is True
    assert evidence.pids_limit == 128
    assert evidence.memory_limit == 2 * 1024 * 1024 * 1024
    assert evidence.cpu_limit == 1_500_000_000
    assert evidence.env_allowlist_ok is True
    assert evidence.mounts_ok is True


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (lambda payload: payload["HostConfig"].__setitem__("Runtime", "runc"), "RUNTIME_MISMATCH"),
        (lambda payload: payload["HostConfig"].__setitem__("NetworkMode", "bridge"), "NETWORK_NOT_NONE"),
        (lambda payload: payload["HostConfig"].__setitem__("ReadonlyRootfs", False), "ROOTFS_NOT_READ_ONLY"),
        (lambda payload: payload["HostConfig"].__setitem__("CapAdd", ["NET_ADMIN"]), "CAP_ADD_PRESENT"),
        (lambda payload: payload["HostConfig"].__setitem__("CapDrop", []), "CAP_DROP_ALL_MISSING"),
        (lambda payload: payload["HostConfig"].__setitem__("SecurityOpt", []), "NO_NEW_PRIVILEGES_MISSING"),
        (lambda payload: payload["Config"].__setitem__("User", "0:0"), "ROOT_USER"),
        (lambda payload: payload["HostConfig"].__setitem__("PidsLimit", 1024), "PIDS_LIMIT_MISMATCH"),
        (lambda payload: payload["HostConfig"].__setitem__("Memory", 1024), "MEMORY_LIMIT_MISMATCH"),
        (lambda payload: payload["HostConfig"].__setitem__("NanoCpus", 1_000_000_000), "CPU_LIMIT_MISMATCH"),
        (lambda payload: payload["Mounts"][0].__setitem__("RW", True), "INPUT_MOUNT_NOT_READ_ONLY"),
        (lambda payload: payload["Mounts"][0].__setitem__("Source", "/repo"), "INPUT_MOUNT_SOURCE_MISMATCH"),
        (lambda payload: payload["Mounts"][1].__setitem__("RW", False), "OUTPUT_MOUNT_NOT_WRITABLE"),
        (lambda payload: payload["Mounts"][1].__setitem__("Source", "/repo/output"), "OUTPUT_MOUNT_SOURCE_MISMATCH"),
        (lambda payload: payload["Mounts"].append({"Type": "bind", "Source": "/repo", "Destination": "/workspace", "RW": False}), "UNEXPECTED_BIND_MOUNT"),
        (lambda payload: payload["Config"].__setitem__("Env", ["HF_TOKEN=secret"]), "FORBIDDEN_ENV"),
        (lambda payload: payload["Args"].insert(7, "PYTHONPATH=/sandbox/input"), "FORBIDDEN_ENV"),
        (lambda payload: payload.__setitem__("Path", "/bin/sh"), "ENTRYPOINT_MISMATCH"),
        (lambda payload: payload["Args"].remove("-S"), "PYTHON_NO_SITE_MISSING"),
        (lambda payload: payload["Args"].insert(10, "-c"), "UNEXPECTED_PRE_RUNNER_ARG"),
    ],
)
def test_inspect_drift_is_reported_as_fail_evidence(mutator, expected_error: str) -> None:
    payload = copy.deepcopy(_inspect_fixture())
    mutator(payload)

    ok, evidence, errors = _validate(payload)

    assert ok is False
    assert expected_error in errors
    assert isinstance(evidence, RuntimeEvidence)


def test_input_output_mount_overlap_is_reported() -> None:
    payload = _inspect_fixture()
    payload["Mounts"][1]["Source"] = "/jobs/job-b2/input/output"

    ok, evidence, errors = _validate(payload)

    assert ok is False
    assert evidence.mounts_ok is False
    assert "INPUT_OUTPUT_MOUNT_OVERLAP" in errors


def test_inspect_evidence_can_feed_decision_builder_runtime_drift() -> None:
    payload = _inspect_fixture()
    payload["HostConfig"]["Runtime"] = "runc"
    ok, evidence, errors = _validate(payload)

    check = build_sandbox_check_from_runner_result(
        request_id="req-b2",
        job_id="job-b2",
        artifact_id="sha256:" + "a" * 64,
        repo_path="modeling_demo.py",
        runner_result={
            "schema_version": "1.0",
            "request_id": "req-b2",
            "nonce": "nonce-123",
            "manifest_verified": True,
            "import_status": "success",
            "instantiate_status": "success",
            "forward_status": "success",
        },
        expected_nonce="nonce-123",
        runtime_evidence=evidence,
        manifest_evidence=ManifestEvidence(host_manifest_sha256="2" * 64),
        post_start_runtime_errors=errors,
    )

    assert ok is False
    assert check["decision"] == "BLOCKED_RUNTIME_INVALID"
    assert check["policy_gate"]["reason_code"] == "SANDBOX_RUNTIME_DRIFT_AFTER_START"
    assert check["runtime_evidence"]["runtime"] == "runc"
