# HuggingMask gVisor 공통 운영 원칙

문서 버전: v1.0
작성일: 2026-05-20
대상 범위: HuggingMask의 Docker/runsc 기반 sandbox 공통 정책

## 1. 목적

이 문서는 Python 코드 샌드박스와 weight/pickle 샌드박스가 공유하는 gVisor 운영 기준만 정의한다.

샌드박스별 입력 manifest, entrypoint, 판정 의미, release 정책은 전용 문서에서 다룬다.

| 문서 | 책임 |
|---|---|
| `docs/gVisor_공통_운영_원칙.md` | Docker/runsc 실행, inspect, log, evidence, infra error 공통 기준 |
| `docs/B-2_gVisor_구현_상세_설계서.md` | 파일/config -> Python 코드 B-2 sandbox 전용 설계 |
| `docs/PICKLE_PATH_B_gVisor_구현_상세_설계서.md` | weight/pickle Path B의 gVisor host evidence 보강 설계 |

## 2. 공통 원칙

- gVisor는 단독 승인 장치가 아니다. 각 validator의 정책 결정을 보조하는 host-side evidence 수집 장치다.
- container 내부 stdout/stderr/JSON은 단독 보안 판정 근거가 아니다.
- 최종 보안 판정에는 host가 수집한 Docker inspect, runsc log, manifest hash, output artifact hash를 함께 사용한다.
- proxy는 Docker/runsc를 직접 호출하지 않는다.
- service는 runner를 주입하거나 validator에 위임한다. sandbox 실행 세부는 sandbox/validator 모듈 책임이다.
- sandbox infra 실패와 artifact 악성 판정은 reason code와 status에서 분리한다.
- `--runtime runsc`를 command에 넣는 것만으로 충분하지 않다. Docker inspect로 실제 runtime과 제한 정책을 확인해야 한다.
- container 내부 `dmesg`, stdout/stderr, runner JSON은 공격자가 흉내 낼 수 있으므로 runtime 증명이나 최종 보안 판정의 단독 근거로 쓰지 않는다.

## 3. 공통 실행 흐름

권장 host runner 흐름:

```text
prepare sanitized input
  -> write canonical manifest
  -> docker create
  -> docker inspect pre-start
  -> inspect policy validation
  -> docker start
  -> docker wait/logs
  -> docker inspect post-run
  -> runsc log discovery/copy
  -> parse runner output
  -> build host evidence decision
  -> docker rm
```

`docker run --rm` 단일 호출은 초기 smoke test에는 쓸 수 있지만, host evidence가 필요한 구현에서는 피한다. 실행 후 inspect와 log 수집이 어려워지기 때문이다.

## 4. Docker/runsc 정책

공통 필수 정책:

```text
--runtime <policy_runtime>
--network none
--read-only
--cap-drop ALL
--security-opt no-new-privileges
--pids-limit <limit>
--memory <limit>
--cpus <limit>
--pull never
```

권장 정책:

```text
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=<limit>
--tmpfs /run:rw,noexec,nosuid,nodev,size=<limit>
--user 1000:1000
```

금지:

- `--privileged`
- `--network host`, bridge network, user-defined network
- Docker socket mount
- host repo root mount
- writable input mount
- `--cap-add`
- `PYTHONPATH`로 untrusted input path 주입
- cloud/Hugging Face/token/proxy credential env 전달
- digest 없이 mutable image tag만 사용하는 운영 배포

## 5. Docker Inspect 공통 검증

inspect validator는 최소한 아래 항목을 검증한다.

| 항목 | 요구 조건 |
|---|---|
| runtime | policy에서 지정한 Docker runtime과 일치 |
| network | `none` |
| readonly rootfs | true |
| privileged | false |
| cap add | 비어 있어야 함 |
| cap drop | `ALL` 포함 |
| no new privileges | `SecurityOpt`에 포함 |
| bind mounts | 전용 문서에서 허용한 mount만 존재 |
| input mount | read-only |
| env | allowlist만 존재 |
| user | non-root 권장 |
| resource limits | memory, pids, cpu limit 존재 |
| image | 운영에서는 digest-pinned |

검증 방식 구분:

- `--runtime`, network mode, read-only rootfs, bind mount, capability, `no-new-privileges`, resource limit은 `docker inspect`의 `HostConfig`, `Config`, `Mounts`, `NetworkSettings`로 검증한다.
- `--pull never`는 container inspect 결과로 증명되는 runtime 속성이 아니다. host runner의 command/API construction과 image resolution audit로 검증한다.
- image 신뢰는 mutable tag 문자열이 아니라 local image ID 또는 digest allowlist로 검증한다.
- read-only rootfs와 bind mount read-only는 별도 조건이다. rootfs가 read-only여도 input bind mount가 writable이면 정책 위반이다.

검증 시점:

- pre-start inspect: untrusted code 실행 전 정책 위반 차단
- post-run inspect: 실행 중 drift 또는 예상 밖 설정 확인

pre-start inspect 실패는 artifact 악성 증거가 아니다. 기본적으로 infra error로 분류한다.

post-run inspect에서 정책 위반 drift가 확인되면 runtime policy violation으로 분류한다.

## 6. runsc Log 공통 기준

운영에서는 evidence용 runsc runtime을 별도 이름으로 등록하는 것을 권장한다.

예:

```json
{
  "runtimes": {
    "runsc-huggingmask": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--debug",
        "--strace",
        "--debug-log=/var/log/huggingmask/runsc/%ID%.%COMMAND%.log"
      ]
    }
  }
}
```

공통 규칙:

- runtime 이름은 policy/env/CLI에서 주입한다.
- 코드에 `runsc` 또는 `runsc-huggingmask`를 고정하지 않는다.
- runsc log directory는 host root만 write 가능해야 한다.
- host runner는 Docker container id와 runsc log 파일을 매핑한다.
- log가 필요한 policy에서 log를 찾지 못하면 clean으로 처리하지 않는다.
- runsc log parser는 hard event, review event, allowed event를 분리한다.

공통 hard event 후보:

- network connect/socket 시도
- child process exec
- input mount write 시도
- 허용 output/tmp 밖 write 시도
- mount/ptrace/setuid/setgid
- untrusted input path에서 shared object load

전용 문서는 각 샌드박스의 정상 파일 접근과 정상 runtime event를 별도로 allowlist한다.

## 7. Evidence 저장

권장 evidence layout:

```text
evidence/sandbox/<YYYYMMDD>_<request_id>/
  manifest/
  docker/
    inspect_pre.json
    inspect_post.json
    stdout.txt
    stderr.txt
  runsc/
  runner/
    result.json
  decision/
    sandbox_check.json
```

경로 규칙:

- request/job 단위로 격리한다.
- untrusted input 원본 전체를 evidence에 복사하지 않는다. hash, size, repo_path, manifest만 보존한다.
- stdout/stderr는 보존하되 단독 판정 근거로 쓰지 않는다.
- evidence path는 result detail에 relative 또는 controlled absolute path로 기록한다.

## 8. Status와 Reason 분리

공통 분류:

| 상황 | 의미 | 기본 처리 |
|---|---|---|
| Docker/runsc/image 준비 실패 | sandbox infra 문제 | `ERROR` 또는 `PENDING_REVIEW` |
| pre-start inspect 실패 | 실행 전 정책 검증 실패 | infra error |
| post-run inspect drift | 제한 정책 위반 | runtime policy violation |
| runsc log incomplete | evidence 불충분 | review/error, clean 금지 |
| hard security event | artifact 실행 중 위험 행동 관찰 | `BLOCK` |
| runner functional failure | 로드/실행/변환 실패 | 전용 문서 기준 |
| runner clean + host evidence clean | 관찰상 clean | 전용 문서 기준 |

같은 Docker 실패라도 artifact가 악성이라서 막힌 것인지, gVisor 환경이 준비되지 않은 것인지 구분해야 한다.

## 9. 전용 문서에서 반드시 정할 것

각 샌드박스 전용 문서는 아래를 반드시 별도로 정의한다.

- 어떤 artifact가 sandbox 대상인지
- input manifest shape
- input mount에 들어갈 파일 집합
- trusted entrypoint가 하는 일
- untrusted repo/code import 허용 여부
- runner output shape
- host evidence가 result detail에 붙는 위치
- clean 결과가 `PASS`인지, `PENDING_REVIEW`인지
- release artifact가 있는지
- sandbox not configured fallback 정책
- 전용 reason code
- 전용 테스트 matrix

## 10. 현재 전용 차이

| 항목 | Python 코드 B-2 | weight/pickle Path B |
|---|---|---|
| 대상 | `modeling_*.py` 등 Python code | pickle/PyTorch weight artifact |
| input | primary Python + dependency closure + support files | #24의 Path B pickle input |
| untrusted code import | 제한적으로 관찰 대상 import | repo Python code import 금지 |
| runner output 의미 | 코드 실행 행동 evidence | weights_only loader 기능 결과 |
| clean 결과 | 단독 `PASS` 아님 | #24 Path A/A-B diff 정책과 결합 |
| result detail | `sandbox_check` | `path_b.gvisor_evidence` |
| release artifact | 없음 | #24 정책상 Path A 변환 safetensors |

이 차이 때문에 공통 문서 하나로 통합하지 않는다. 공통 문서는 host runtime 기준만 제공하고, 판정 의미는 전용 문서에 둔다.
