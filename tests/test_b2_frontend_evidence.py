import json
from pathlib import Path

from fastapi.testclient import TestClient

from proxy.app import main as proxy_main


def test_b2_sandbox_frontend_page_is_served() -> None:
    with TestClient(proxy_main.app) as client:
        response = client.get("/sandbox/b2")

    assert response.status_code == 200
    assert "B-2 Sandbox Evidence" in response.text
    assert "/internal/v1/sandbox/b2/latest" in response.text


def test_latest_b2_evidence_returns_unavailable_when_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(proxy_main, "_B2_EVIDENCE_ROOT", tmp_path / "missing")

    with TestClient(proxy_main.app) as client:
        response = client.get("/internal/v1/sandbox/b2/latest")

    assert response.status_code == 200
    assert response.json()["available"] is False


def test_latest_b2_evidence_projects_selected_fields(monkeypatch, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "20260521_014508_req-b2-demo"
    evidence_dir.mkdir()
    _write_json(
        evidence_dir / "summary.json",
        {
            "repo_path": "modeling_b2_demo.py",
            "docker_runtime": "runsc",
            "runtime_verified": True,
            "forward_status": "success",
            "decision": "B2_POLICY_REVIEW_REQUIRED",
            "deployable": False,
        },
    )
    _write_json(
        evidence_dir / "sandbox_check.json",
        {
            "runtime_evidence": {
                "runtime": "runsc",
                "network_mode": "none",
                "rootfs_readonly": True,
                "cap_drop_all": True,
                "no_new_privileges": True,
                "mounts_ok": True,
            }
        },
    )
    _write_json(
        evidence_dir / "docker_inspect.json",
        [
            {
                "Config": {"User": "1000:1000"},
                "HostConfig": {
                    "Runtime": "runsc",
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                },
                "Mounts": [
                    {"Destination": "/sandbox/input", "Mode": "ro", "RW": False},
                    {"Destination": "/tmp/huggingmask", "Mode": "rw", "RW": True},
                ],
            }
        ],
    )
    _write_json(
        evidence_dir / "runner_result.json",
        {
            "manifest_verified": True,
            "import_status": "success",
            "instantiate_status": "success",
            "forward_status": "success",
            "exception_class": None,
            "exception_message": None,
        },
    )
    monkeypatch.setattr(proxy_main, "_B2_EVIDENCE_ROOT", tmp_path)

    with TestClient(proxy_main.app) as client:
        response = client.get("/internal/v1/sandbox/b2/latest")

    payload = response.json()
    assert payload["available"] is True
    assert payload["summary"]["docker_runtime"] == "runsc"
    assert payload["summary"]["runtime_verified"] is True
    assert payload["summary"]["decision"] == "B2_POLICY_REVIEW_REQUIRED"
    assert payload["summary"]["deployable"] is False
    assert payload["runtime_evidence"]["network_mode"] == "none"
    assert payload["docker_inspect"]["runtime"] == "runsc"
    assert payload["docker_inspect"]["mounts"][0]["destination"] == "/sandbox/input"
    assert payload["runner_result"]["forward_status"] == "success"


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
