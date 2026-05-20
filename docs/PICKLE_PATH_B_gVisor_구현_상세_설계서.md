# HuggingMask PICKLE_PATH_B gVisor Host Evidence 설계서

문서 버전: v1.1  
작성일: 2026-05-20  
대상 PR: #24 `[CORE][fix] weight validator 보안 피드백 반영`  
대상 범위: `PICKLE_PATH_B`의 Docker/runsc(gVisor) 실행 검증과 host-side evidence

## 0. 문서 구조

gVisor 공통 운영 기준은 `docs/gVisor_공통_운영_원칙.md`를 따른다.

이 문서는 PR #24의 weight validator 구현을 전제로 하며, 공통 Docker/runsc 원칙 중 `PICKLE_PATH_B`에서 추가로 확인해야 하는 host evidence만 다룬다.

| 문서 | 역할 |
|---|---|
| `docs/gVisor_공통_운영_원칙.md` | Docker/runsc 실행, inspect, runsc log, evidence, infra error 공통 기준 |
| `docs/B-2_gVisor_구현_상세_설계서.md` | Python 코드 B-2 sandbox 전용 설계 |
| `docs/PICKLE_PATH_B_gVisor_구현_상세_설계서.md` | weight/pickle Path B gVisor host evidence 보강 |

## 1. 목적

이 문서는 weight/pickle 검증 전체를 다시 설계하지 않는다.

PR #24에서 이미 처리한 아래 항목은 이 문서의 범위 밖이다.

- Path A opcode/YARA/modelscan 정책
- `torch.load(weights_only=False)` 제거
- `pickle.load` fallback 제거
- `torch.load(..., weights_only=True)` 사용
- nonce/prefix 기반 sandbox stdout 파싱
- Path A/B tensor key, shape, dtype, hash diff
- 원본 pickle release 금지
- Path A 변환 safetensors만 release 대상으로 삼는 정책
- cache HMAC, atomic write, file lock

이 문서가 설계하는 것은 #24 본문에 남은 확인 요청인 다음 한 가지다.

```text
PICKLE_PATH_B sandbox가 정말 gVisor 정책으로 실행됐는지
container 내부 stdout이 아니라 host evidence로 검증한다.
```

## 2. 현재 #24 기준 확인 결과

#24 diff 기준으로 확인한 현재 상태:

- `analyzer/validators/weight/sandbox/docker_runner.py`
  - 기본 runtime이 `runc`에서 `runsc`로 변경됨
  - Docker command에 `--runtime <runtime>` 추가
  - `HM_SANDBOX_NONCE` env를 넘김
  - stdout은 `HM_SANDBOX_RESULT:<nonce>:` prefix가 있는 JSON만 파싱
- `analyzer/validators/weight/sandbox/load_and_extract.py`
  - unsafe `pickle.load` fallback 제거
  - `torch.load(..., weights_only=True, map_location="cpu")` 사용
- `analyzer/validators/weight/diff/checker.py`
  - Path B에만 있는 tensor key 탐지
  - shape/dtype/hash mismatch 탐지
  - mismatch 시 `PICKLE_PATH_AB_MISMATCH`

따라서 남은 gVisor 설계 gap은 아래다.

- Docker runtime이 실제로 `runsc`였는지 host inspect로 검증하지 않음
- network, mount, read-only rootfs, capability, user, env 제한을 inspect로 검증하지 않음
- runsc debug/strace log를 evidence로 수집하지 않음
- Docker stdout 결과와 host runtime evidence가 분리되어 있지 않음
- gVisor infra error와 pickle artifact block이 reason code에서 충분히 분리되어 있지 않음

## 3. 설계 원칙

- sandbox stdout은 기능 결과일 뿐이다. 최종 Path B security evidence는 host가 수집한다.
- `--runtime runsc`를 command에 넣는 것만으로 충분하지 않다. Docker inspect 결과가 정책과 일치해야 한다.
- runsc log가 필요한 policy에서 log가 없으면 clean으로 보지 않는다.
- gVisor infra 실패는 artifact 악성 증거가 아니므로 기본 `ERROR` 또는 `PENDING_REVIEW`로 구분한다.
- sandbox 내부 loader 정책은 #24 구현을 따른다. 이 문서는 loader 내부를 다시 설계하지 않는다.
- service/proxy는 Docker/runsc를 직접 호출하지 않는다. weight sandbox runner 내부 책임으로 둔다.

## 4. 구현 위치

PR #24 구조를 유지한다.

```text
analyzer/validators/weight/sandbox/
  docker_runner.py        # host-side Docker/runsc 실행 + evidence 수집
  load_and_extract.py     # container 내부 weights_only loader, #24 구현 유지
```

추가 또는 분리 권장 파일:

```text
analyzer/validators/weight/sandbox/
  inspect_validator.py    # Docker inspect 정책 검증
  runsc_log_parser.py     # runsc debug/strace log 요약
  evidence.py             # evidence path와 result shape helper
```

작게 시작하려면 `docker_runner.py` 안에 helper로 먼저 넣고, 테스트가 커지면 위 파일로 분리한다.

## 5. Docker 실행 방식

현재 #24의 `docker run` 방식은 stdout 파싱에는 충분하지만, start 전 inspect 검증이 어렵다. gVisor evidence를 명확히 남기려면 아래 순서로 바꾼다.

```text
docker create
  -> docker inspect pre-start
  -> inspect policy 검증
  -> docker start
  -> docker wait/logs
  -> docker inspect post-run
  -> runsc log 수집
  -> sandbox stdout nonce JSON 파싱
  -> host evidence와 sandbox result 병합
  -> docker rm
```

초기 구현에서 `docker run`을 유지해야 한다면 최소한 실행 후 `docker inspect <container>`가 가능하도록 `--rm`을 쓰지 않고, wait/logs/inspect/rm을 직접 수행한다.

## 6. 필수 Docker 정책

Path B command는 최소한 아래 정책을 가져야 한다.

```text
--runtime <runtime>              # 기본 runsc, 정책으로 주입 가능
--network none
--read-only
--cap-drop ALL
--security-opt no-new-privileges
--pids-limit <limit>
--memory <limit>
--cpus <limit>
-v <host_pickle>:/input/model.pkl:ro
-e HM_SANDBOX_NONCE=<nonce>
```

추가 권장:

```text
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m
--user 1000:1000
--pull never
```

금지:

- `--privileged`
- `--network host`, bridge network, user-defined network
- Docker socket mount
- host repo root mount
- writable `/input`
- `--cap-add`
- `PYTHONPATH=/input`
- cloud/HF token env 전달

## 7. Docker Inspect 검증

`inspect_validator.py`는 Docker inspect JSON에서 아래를 확인한다.

| 항목 | 요구 조건 |
|---|---|
| runtime | `HostConfig.Runtime == expected_runtime` |
| network | `HostConfig.NetworkMode == "none"` |
| readonly rootfs | `HostConfig.ReadonlyRootfs == true` |
| privileged | `HostConfig.Privileged == false` |
| cap add | 비어 있어야 함 |
| cap drop | `ALL` 포함 |
| no new privileges | `SecurityOpt`에 `no-new-privileges` 포함 |
| binds/mounts | `/input/model.pkl` read-only만 허용 |
| env | allowlist만 허용 |
| user | root 금지 권장 |
| resource | memory, pids, cpu limit 존재 |

함수 초안:

```python
def validate_weight_sandbox_inspect(
    inspect_doc: dict,
    *,
    expected_runtime: str,
    expected_input_target: str = "/input/model.pkl",
) -> dict:
    """
    Returns:
      {
        "ok": bool,
        "violations": [{"field": "...", "expected": "...", "actual": "..."}],
        "runtime": "...",
        "network_disabled": bool,
        "read_only_fs": bool
      }
    """
```

pre-start inspect가 실패하면 untrusted code가 아직 실행되지 않았으므로 `PICKLE_PATH_B_INFRA_ERROR`다. post-run inspect에서 drift가 확인되면 `PICKLE_PATH_B_RUNTIME_POLICY_VIOLATION`이다.

## 8. runsc Log Evidence

운영 환경에서는 Path B용 Docker runtime을 별도 이름으로 등록하는 것을 권장한다.

```json
{
  "runtimes": {
    "runsc-weight": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--debug",
        "--strace",
        "--debug-log=/var/log/huggingmask/runsc/weight.%ID%.%COMMAND%.log"
      ]
    }
  }
}
```

정책:

- 개발 기본값은 `runsc`여도 된다.
- evidence가 필요한 운영/보안 테스트는 `runsc-weight`처럼 log-enabled runtime을 사용한다.
- `runtime` 이름은 CLI/env/policy에서 주입하고 하드코딩하지 않는다.
- runsc log directory는 host root만 write 가능해야 한다.
- log가 필요한 policy에서 log 파일을 찾지 못하면 `PICKLE_PATH_B_LOG_INCOMPLETE`다.

`runsc_log_parser.py`는 처음에는 coarse summary만 만든다.

```python
def parse_runsc_logs(paths: list[Path]) -> dict:
    return {
        "log_complete": bool,
        "log_paths": [str],
        "hard_events": [dict],
        "review_events": [dict],
    }
```

초기 hard event:

- network connect/socket 시도
- child process exec
- `/input` write 시도
- `/output` 밖 write 시도
- mount/ptrace/setuid/setgid

초기 review event:

- log incomplete
- timeout
- OOM
- 반복적인 denied file access

## 9. Path B Result Shape

#24의 기존 result dict를 깨지 않기 위해 top-level key를 최소 추가한다.

성공 예:

```json
{
  "status": "PASS",
  "reason_code": "PICKLE_PATH_B_LOAD_OK",
  "reason": "sandbox loaded weights_only artifact and extracted tensor report",
  "runtime": "runsc",
  "tensors": {},
  "gvisor_evidence": {
    "inspect_ok": true,
    "pre_start_inspect_ref": "evidence/sandbox/.../inspect_pre.json",
    "post_run_inspect_ref": "evidence/sandbox/.../inspect_post.json",
    "runtime": "runsc",
    "network_disabled": true,
    "read_only_fs": true,
    "runsc_log_complete": true,
    "runsc_logs_ref": "evidence/sandbox/.../runsc/",
    "hard_events": [],
    "review_events": []
  }
}
```

infra 실패 예:

```json
{
  "status": "ERROR",
  "reason_code": "PICKLE_PATH_B_INFRA_ERROR",
  "reason": "Docker inspect failed before untrusted code started",
  "runtime": "runsc",
  "gvisor_evidence": {
    "inspect_ok": false,
    "violations": []
  }
}
```

runtime policy 위반 예:

```json
{
  "status": "BLOCK",
  "reason_code": "PICKLE_PATH_B_RUNTIME_POLICY_VIOLATION",
  "reason": "container runtime policy drift detected",
  "runtime": "runsc",
  "gvisor_evidence": {
    "inspect_ok": false,
    "violations": [
      {
        "field": "HostConfig.NetworkMode",
        "expected": "none",
        "actual": "bridge"
      }
    ]
  }
}
```

## 10. Reason Code 정리

기존 #24 reason code를 유지한다. gVisor evidence용으로 아래만 추가한다.

| code | 의미 |
|---|---|
| `PICKLE_PATH_B_INFRA_ERROR` | Docker/runsc/image/inspect가 실행 전 실패 |
| `PICKLE_PATH_B_RUNTIME_POLICY_VIOLATION` | inspect 기준 runtime/network/mount/env/cap 정책 위반 |
| `PICKLE_PATH_B_LOG_INCOMPLETE` | runsc log 필요 정책에서 log 누락 |
| `PICKLE_PATH_B_SECURITY_EVENT` | runsc/event parser가 hard event 탐지 |

`PICKLE_PATH_B_EXECUTION_FAILED`는 container 내부 loader 실패나 non-zero exit에 사용한다. Docker/gVisor 준비 실패와 섞지 않는다.

## 11. 테스트 계획

#24 테스트에 추가할 gVisor 전용 테스트:

| 테스트 | 목적 |
|---|---|
| `test_docker_runner_uses_create_start_inspect_flow` | `docker create -> inspect -> start -> wait -> logs -> inspect -> rm` 순서 고정 |
| `test_inspect_rejects_non_runsc_runtime` | runtime이 `runc`이면 위반 |
| `test_inspect_rejects_network_enabled` | network가 `none`이 아니면 위반 |
| `test_inspect_rejects_writable_input_mount` | `/input/model.pkl`이 writable이면 위반 |
| `test_inspect_rejects_privileged_or_cap_add` | privileged/cap-add 차단 |
| `test_runsc_log_missing_is_not_clean` | log required인데 없으면 `PICKLE_PATH_B_LOG_INCOMPLETE` |
| `test_infra_error_is_not_artifact_block` | pre-start inspect 실패는 infra error로 분리 |
| `test_gvisor_evidence_attached_to_path_b_result` | result에 `gvisor_evidence`가 붙음 |

Docker 없는 Windows 개발 환경에서는 command/inspect parser unit test만 실행한다. 실제 runsc E2E는 Linux Docker 환경에서 별도 marker로 둔다.

```python
@pytest.mark.gvisor
def test_pickle_path_b_gvisor_e2e(...):
    ...
```

## 12. 구현 순서

1. `docker_runner.py`를 `docker run` 직접 호출에서 create/start/wait/logs/inspect/rm 흐름으로 변경
2. `inspect_validator.py` 추가
3. `gvisor_evidence` result shape 추가
4. Docker 없는 단위 테스트 추가
5. runsc log path 정책과 parser skeleton 추가
6. Linux Docker gVisor E2E 테스트 추가

## 13. 완료 기준

- Path B command에 `--runtime runsc`가 들어가는 것만 테스트하지 않고, inspect 결과도 검증한다.
- network disabled, read-only rootfs, read-only input mount, cap drop, no-new-privileges가 inspect로 확인된다.
- sandbox stdout JSON이 PASS여도 inspect 위반이면 `BLOCK` 또는 `ERROR`로 뒤집힌다.
- runsc log required policy에서 log가 없으면 clean 처리하지 않는다.
- Docker/gVisor infra 실패와 artifact 악성 판정을 reason code로 분리한다.
- #24의 `weights_only=True`, nonce stdout, A/B diff 정책은 그대로 유지한다.
