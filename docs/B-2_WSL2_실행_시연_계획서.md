# HuggingMask B-2 로컬 Linux Docker/runsc 실행 시연 계획서

문서 버전: v0.2
작성일: 2026-05-20
수정일: 2026-05-21
대상 환경: Windows 개발 PC + Docker Desktop `desktop-linux` Linux daemon + `runsc`
선택 환경: WSL2 Ubuntu Docker Engine + `runsc`
목표 범위: 캡스톤 시연용 로컬 PoC

## 1. 목표

Windows 개발 PC에서 접근 가능한 Linux Docker daemon에 `runsc` runtime을 등록하고, HuggingMask B-2 sandbox를 실제 Docker/runsc(gVisor)로 실행한 뒤 실행 결과를 `sandbox_check`와 evidence 파일로 남긴다.

이 문서의 목표는 배포 설계가 아니라, 현재 fixture 기반 B-2 runner를 실제 실행 가능한 시연 PoC로 확장하기 위한 구현 기준을 고정하는 것이다.

최종 시연에서 보여줄 메시지는 다음이다.

```text
명확히 위험한 custom code는 실행 전에 BLOCK한다.
B-2 대상 custom model code는 바로 승인하지 않고 runsc/gVisor sandbox에서 제한 실행한다.
Docker inspect와 runner_result evidence를 남긴다.
sandbox 실행이 clean이어도 자동 PASS가 아니라 security review evidence로 남긴다.
```

### 1.1 환경 선택 이유

이번 PoC의 primary acceptance 환경은 Docker Desktop의 `desktop-linux` Linux daemon이다.

선택 이유:

- 프로젝트의 보안 acceptance 기준은 배포판 이름이 아니라 Docker daemon이 실제 `runsc` runtime으로 컨테이너를 실행했는지다.
- `docker inspect` evidence에서 `Runtime=runsc`, `network=none`, read-only rootfs, cap drop, no-new-privileges, bind mount 정책을 확인할 수 있으면 B-2 sandbox evidence 요구를 충족한다.
- 현재 개발 PC에는 별도 WSL2 Ubuntu 배포판이 없지만, Docker Desktop의 `desktop-linux` daemon은 Linux container daemon이며 `runsc` 등록과 `hello-world` smoke test가 완료됐다.
- WSL2 Ubuntu를 새로 설치하는 작업은 보안 기능을 더 증명하기보다 시연 환경 라벨을 맞추는 작업에 가깝다.

따라서 이 문서는 `desktop-linux + runsc`를 로컬 PoC의 기준 환경으로 채택한다. WSL2 Ubuntu는 같은 절차를 재현할 수 있는 선택 환경으로 남긴다.

## 2. 현재 상태

이미 구현된 범위:

- B-2 대상 판정: `_requires_b2_sandbox()`
- snapshot 기반 source resolver
- B-2 input manifest 생성과 hash 검증
- Docker/runsc command plan 생성
- Docker inspect fixture validator
- runsc log fixture parser
- in-container trusted entrypoint
- fixture 기반 `B2HostRunner`
- `sandbox_check` decision builder
- opt-in `RealDockerCommandRunner`
- B-2 demo Docker image skeleton
- 로컬 Linux Docker daemon 실행용 demo script contract
- local evidence 저장 contract
- Docker Desktop `desktop-linux` daemon에 `runsc` runtime 등록
- `runsc` smoke test: `docker run --runtime=runsc --rm hello-world` 성공
- B-2 runsc demo acceptance evidence 생성

아직 없는 범위:

- 별도 WSL2 Ubuntu 배포판에서의 중복 acceptance evidence
- Linux 전용 e2e 테스트

2026-05-21 구현 진행 상태:

- `/phase-0`: 문서 초안 추가.
- `/phase-1`: `sandbox/b2/real_command_runner.py` 추가, subprocess shell=False, timeout, inspect/logs/cp fixture parsing, secret redaction, evidence 파일 저장 unit test 통과.
- `/phase-2`: `sandbox/image/b2/Dockerfile`, `requirements.txt` 추가. Docker Desktop Linux engine 기준 image build 검증 완료.
- `/phase-3` ~ `/phase-5`: `scripts/demo_b2_run.py` 추가, demo snapshot 생성, `B2HostRunner` 연결, `summary.json`, `sandbox_check.json`, `b2_input_manifest.json`, `runner_result.json`, `host_runner_output.json` 저장 contract test 통과.
- `/phase-6`: Docker Desktop `desktop-linux` daemon 기준 `runsc` smoke test와 B-2 demo acceptance 완료. acceptance evidence는 `evidence/sandbox/20260520_094857_req-b2-demo`.
- `/phase-7`: entrypoint deterministic forward contract 추가. `runsc` acceptance에서 `forward_status=success`, `decision=B2_POLICY_REVIEW_REQUIRED`, `deployable=false` 확인.
- `/phase-8`: B-2 명시 테스트 125개 통과. Linux 전용 e2e pytest는 아직 별도 구현하지 않음.

현재 구조는 버리는 코드가 아니다. `FakeCommandRunner` 자리에 실제 Docker command runner를 꽂는 방식으로 확장한다.

```text
현재:
  B2HostRunner -> FakeCommandRunner -> fixture inspect/log/result

시연 목표:
  B2HostRunner -> RealDockerCommandRunner -> real docker/runsc inspect/log/result
```

## 3. 시연 범위

### 포함

- 로컬 Linux Docker daemon에서 실제 `docker create/start/wait/inspect/logs/cp/rm` 실행
- Docker runtime이 `runsc`였는지 host-side `docker inspect`로 확인
- B-2 input manifest와 staged input hash 재검증
- `runner_result.json` 수집
- `sandbox_check` 생성
- `evidence/sandbox/...`에 evidence 저장
- 발표용 demo script 제공

### 제외

- AWS 배포
- ECS/EKS/Fargate/Lambda
- 운영용 queue/DB/review UI
- 대형 모델 처리
- GPU inference
- Hugging Face token이 필요한 private model
- sandbox clean 결과의 자동 승인

## 4. 구현 대상 파일

추가할 파일:

```text
sandbox/b2/real_command_runner.py
sandbox/image/b2/Dockerfile
sandbox/image/b2/requirements.txt
scripts/demo_b2_run.py
tests/test_b2_real_command_runner.py
tests/test_b2_demo_script_contract.py
```

수정 가능성이 있는 파일:

```text
sandbox/b2/entrypoint.py
sandbox/b2/host_runner_executor.py
sandbox/b2/host_runner.py
sandbox/b2/schemas.py
.gitignore
```

수정 원칙:

- 기존 fixture unit test는 유지한다.
- 실제 Docker/runsc e2e는 기본 pytest에서 돌리지 않는다.
- 실제 실행 테스트는 Linux + 명시적 환경변수에서만 활성화한다.

## 5. 전체 실행 흐름

```text
scripts/demo_b2_run.py
  -> demo snapshot 생성 또는 입력 snapshot 로드
  -> ArtifactRef / ValidationJobRequest 생성
  -> SnapshotSourceResolver 생성
  -> B2HostRunner 구성
  -> RealDockerCommandRunner 주입
  -> run_validation_job() 호출
  -> B-2 대상이면 run_b2_sandbox_pipeline() 실행
  -> Docker/runsc 컨테이너 실제 실행
  -> docker inspect/logs/cp 결과 수집
  -> build_sandbox_check_from_runner_result()
  -> console summary 출력
  -> evidence/sandbox/<timestamp>_<request_id>/ 저장
```

## 6. RealDockerCommandRunner 설계

파일: `sandbox/b2/real_command_runner.py`

역할:

- `CommandRunner` protocol을 실제 Docker 실행으로 구현한다.
- `B2HostRunner`가 넘기는 lifecycle step을 그대로 실행한다.
- shell을 사용하지 않고 argv list를 그대로 실행한다.
- 각 step의 stdout/stderr/exit code를 `CommandResult`로 반환한다.
- `inspect` step의 stdout JSON을 파싱해 fixture key로 넣는다.
- `logs` step의 stdout을 log evidence로 넣는다.

필수 동작:

```text
create:
  docker create ... 실행
  stdout/stderr/exit_code 저장

start:
  docker start <container> 실행

wait:
  docker wait <container> 실행
  컨테이너 exit code 저장

inspect:
  docker inspect <container> 실행
  JSON parse 후 fixtures["post_start_inspect"]에 저장

logs:
  docker logs <container> 실행
  stdout을 CommandResult.stdout에 그대로 저장
  필요하면 fixtures["logs"] 또는 fixtures["runsc_logs"]에도 같은 내용을 저장

cp:
  docker cp <container>:/tmp/huggingmask/runner_result.json <host path> 실행
  복사된 JSON을 읽어 fixtures["runner_result"]에 저장

rm:
  docker rm -f <container> 실행
  cleanup 실패는 기록하되 원래 실패 원인을 덮지 않음
```

구현 제약:

- `subprocess.run(..., shell=False)`만 사용한다.
- timeout을 step별로 둔다.
- stderr는 evidence에 남기되 secret redaction을 적용한다.
- `create/start` 실패는 `runtime_setup_errors`로 분류되어야 한다.
- `wait/inspect/logs/cp` 실패는 `post_start_runtime_errors` 또는 diagnostics failure로 분류되어야 한다.

권장 timeout:

```text
create: 30초
start: 30초
wait: 60초
inspect: 15초
logs: 15초
cp: 15초
rm: 15초
```

## 7. Docker image 설계

파일: `sandbox/image/b2/Dockerfile`

역할:

- 검사 대상 모델 코드를 image 안에 넣지 않는다.
- image에는 trusted runner만 넣는다.
- 입력 repo snapshot은 실행 시 `/sandbox/input:ro`로 bind mount한다.
- 출력은 `/tmp/huggingmask:rw`에만 쓴다.

초기 Dockerfile 기준:

```Dockerfile
FROM python:3.12-slim

RUN useradd -u 1000 -m sandboxuser

WORKDIR /app/huggingmask_runner

COPY sandbox/b2/entrypoint.py /app/huggingmask_runner/b2_entrypoint.py
COPY sandbox/image/b2/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

USER 1000:1000
ENTRYPOINT ["/usr/bin/env"]
```

초기 `requirements.txt`는 비워 두거나 최소 dependency만 둔다. B-2 demo target이 `torch` 없이 import/instantiate 가능하도록 만들면 image가 작아지고 시연 안정성이 올라간다.

운영 전환 시에는 tag가 아니라 digest 기반 `image_ref`를 사용한다.

## 7.1 Demo target 기준

초기 demo target은 외부 ML dependency 없이 B-2 대상이 되도록 만든다. 현재 B-2 대상 판정은 `_requires_b2_sandbox()`를 통과해야 하므로 단순히 `modeling_*.py` 파일만 있는 것으로는 부족하다.

권장 demo target:

```python
class DemoModel:
    def custom_activation(self, x):
        return x

    def forward(self, x):
        return self.custom_activation(x)
```

이 형태를 쓰는 이유:

- 파일명이 `modeling_b2_demo.py`이면 role이 `MODELING`으로 분류된다.
- `self.custom_activation`은 현재 whitelist에 없는 API ref라서 `pending_api_refs`가 생긴다.
- 명확한 위험 API, 동적 import, 난독화 패턴이 없다.
- 외부 package가 필요 없어 B-2 image를 작게 유지할 수 있다.
- entrypoint가 나중에 deterministic forward를 실행해도 간단한 입력으로 성공시킬 수 있다.

기대되는 정적 판정:

```text
route: CODE_SANDBOX_RUNTIME
grade: B-2
status: PENDING_REVIEW
review_action: SECURITY_OWNER_GATE
pending_api_refs: ["self.custom_activation"]
```

이 demo target은 실제 악성 코드가 아니다. 목적은 B-2 경로와 runsc evidence 수집을 안정적으로 보여주는 것이다.

## 8. Demo script 설계

파일: `scripts/demo_b2_run.py`

역할:

- 선택한 Linux Docker daemon에서 한 번의 명령으로 B-2 실제 실행을 보여준다.
- 작은 demo snapshot을 임시 디렉터리에 만든다.
- B-2 대상 Python artifact를 구성한다.
- 실제 `B2HostRunner + RealDockerCommandRunner`를 연결한다.
- 결과 summary와 evidence 파일을 남긴다.

초기 실행 예:

```bash
python scripts/demo_b2_run.py \
  --image-ref huggingmask-b2-sandbox:local \
  --docker-runtime runsc \
  --evidence-dir evidence/sandbox
```

출력 예:

```text
HuggingMask B-2 runsc demo
repo_path: modeling_b2_demo.py
grade: B-2
route: CODE_SANDBOX_RUNTIME
docker_runtime: runsc
runtime_verified: true
decision: B2_POLICY_REVIEW_REQUIRED
deployable: false
evidence_dir: evidence/sandbox/20260520_req-b2-demo
```

주의:

현재 `sandbox/b2/entrypoint.py`는 import와 instantiate 후 대상 인스턴스에 `forward`가 있으면 deterministic forward contract를 시도한다. 지원 범위는 필수 positional 인자가 0개 또는 1개인 `forward`이며, 1개인 경우 `None`을 입력으로 전달한다. 그 외 시그니처는 기존처럼 `skipped_schema_unknown`으로 남긴다.

manifest의 `target_class`는 config-linked 결과가 제공하면 그 값을 우선하고, 직접 Python artifact에서는 AST에 단일 class와 해당 class의 `forward`가 확인될 때만 채운다. 다중 class 또는 불명확한 경우에는 filename/class heuristic으로 추정하지 않는다.

이 demo target은 `forward(self, x)`가 `None` 입력을 그대로 반환하므로 runsc runtime이 준비된 환경에서는 clean observation을 만들 수 있다. 단, 이 결과도 자동 PASS가 아니라 `B2_POLICY_REVIEW_REQUIRED` review evidence로 남겨야 한다.

## 9. Evidence 저장 구조

기본 경로:

```text
evidence/sandbox/<YYYYMMDD_HHMMSS>_<request_id>/
```

필수 파일:

```text
summary.json
sandbox_check.json
b2_input_manifest.json
docker_create_argv.json
docker_inspect.json
docker_logs.txt
runner_result.json
host_runner_output.json
```

선택 파일:

```text
runsc_logs.txt
stdout.txt
stderr.txt
demo_snapshot_manifest.json
```

저장 원칙:

- evidence에는 token, credential, local secret path를 저장하지 않는다.
- 대형 모델 파일은 evidence에 복사하지 않는다.
- GitHub에는 기본적으로 raw evidence를 올리지 않는다.
- 발표용으로 필요한 요약 evidence만 별도 markdown 또는 redacted JSON으로 남긴다.

## 10. 로컬 Linux Docker 실행 환경

Primary 환경:

```text
Windows 11
Docker Desktop desktop-linux Linux daemon
Docker context: desktop-linux
gVisor runsc
Python 3.12
```

선택 환경:

```text
WSL2 Ubuntu
Docker Engine 또는 Docker Desktop WSL integration
gVisor runsc
Python 3.12
```

공식 기준:

- gVisor 설치: https://gvisor.dev/docs/user_guide/install/
- gVisor Docker Quick Start: https://gvisor.dev/docs/user_guide/quick_start/docker/
- Docker alternative runtimes: https://docs.docker.com/engine/daemon/alternative-runtimes/
- dockerd runtime 등록 방식: https://docs.docker.com/reference/cli/dockerd/

공식 문서 기준으로 `runsc`는 Docker runtime으로 등록한 뒤 `docker run --runtime=runsc ...` 형태로 실행한다. Docker daemon runtime 등록은 `/etc/docker/daemon.json`, Docker Desktop의 daemon 설정, 또는 `dockerd --add-runtime` 계열 설정으로 가능하다.

사전 확인:

```bash
docker version
docker info | grep -i runtime
docker run --runtime=runsc --rm hello-world
```

`hello-world`가 `runsc`로 성공하지 않으면 HuggingMask B-2 demo도 진행하지 않는다.

Docker Desktop `desktop-linux` 기준 확인:

```powershell
docker context ls
docker info --format '{{json .Runtimes}}'
docker run --runtime=runsc --rm hello-world
python scripts/demo_b2_run.py --image-ref huggingmask-b2-sandbox:local --docker-runtime runsc --evidence-dir evidence/sandbox
```

Docker Desktop 기준으로는 `runsc` binary가 Windows PATH에 있을 필요는 없다. 중요한 조건은 현재 Docker daemon의 runtimes에 `runsc`가 등록되어 있고, `docker run --runtime=runsc --rm hello-world`가 성공하는 것이다.

WSL2 Ubuntu 선택 환경 체크리스트:

```bash
# 1. Linux 배포판과 kernel 확인
uname -a
cat /etc/os-release

# 2. Docker daemon 접근 확인
docker version
docker info

# 3. runsc 설치 확인
which runsc
runsc --version

# 4. Docker runtime 등록 확인
docker info | grep -i -A3 runtimes

# 5. gVisor runtime smoke test
docker run --runtime=runsc --rm hello-world

# 6. gVisor 실행 여부 참고 확인
# 보안 판정 근거로 쓰지는 않고, 설치 smoke check로만 사용한다.
docker run --runtime=runsc --rm ubuntu dmesg | head
```

WSL2 Ubuntu에서 설치/등록이 필요한 경우의 기본 흐름:

```bash
# gVisor apt repository 방식 예시. 최신 명령은 공식 문서를 우선한다.
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update
sudo apt-get install -y runsc

# Docker runtime 등록
sudo runsc install
sudo systemctl restart docker || sudo service docker restart

# 최종 확인
docker run --runtime=runsc --rm hello-world
```

주의:

- `dmesg` 출력은 gVisor quick start의 편의 확인 수단일 뿐이다. 보안 판정 evidence는 host-side `docker inspect`와 runner diagnostics를 기준으로 한다.
- Docker Desktop `desktop-linux`, Docker Desktop WSL integration, WSL 내부 Docker Engine 중 하나를 선택한다. 여러 daemon 설정이 섞이면 `docker context`, daemon runtime 등록 위치, evidence 해석이 어긋날 수 있다.
- Docker daemon 접근 권한이 없으면 demo script는 실패해야 한다. 권한 문제를 우회하기 위해 sandbox worker에 cloud token이나 host secret을 넣지 않는다.

최종 기준은 선택한 Linux Docker daemon에서 다음이 보여야 한다.

```text
docker CLI가 사용 가능하다.
docker daemon이 접근 가능하다.
runsc runtime이 docker info에 등록되어 있다.
docker run --runtime=runsc --rm hello-world가 성공한다.
```

## 11. 성공 기준

### 최소 성공 기준

아래가 모두 만족되면 B-2 실제 실행 PoC로 인정한다.

- 선택한 Linux Docker daemon에서 demo script 실행
- 실제 Docker lifecycle 실행
- `docker inspect` evidence 저장
- inspect 결과에서 runtime이 `runsc`
- `runner_result.json` 생성
- `sandbox_check.json` 생성
- `deployable=false`
- 결과가 `PASS`로 자동 승격되지 않음

### 발표 목표 기준

아래가 모두 만족되면 캡스톤 발표용 B-2 시연 기준으로 본다.

- B-2 대상 artifact가 `_requires_b2_sandbox()`를 통과
- `CODE_SANDBOX_RUNTIME` route 결과에 `sandbox_check` 부착
- runtime evidence에 `runsc`, `network=none`, read-only rootfs, cap drop 확인
- manifest/input hash error 없음
- hard security event 없음
- runner diagnostics valid
- decision이 `B2_POLICY_REVIEW_REQUIRED`
- `deployable=false`
- evidence directory를 발표 중 열어 확인 가능

## 12. 테스트 계획

기본 unit test:

```bash
python -m pytest tests/test_b2_host_runner_command.py -q
python -m pytest tests/test_b2_host_runner_executor.py -q
python -m pytest tests/test_b2_decision_builder.py -q
python -m pytest tests/test_b2_orchestrator_pipeline.py -q
```

신규 unit test:

```bash
python -m pytest tests/test_b2_real_command_runner.py -q
python -m pytest tests/test_b2_demo_script_contract.py -q
```

Linux 전용 e2e:

```bash
RUN_B2_RUNSC_E2E=1 python -m pytest tests/test_b2_runsc_e2e.py -q
```

e2e skip 조건:

- OS가 Linux가 아님
- `RUN_B2_RUNSC_E2E=1`이 없음
- Docker CLI 없음
- runsc runtime 미등록
- B-2 image 없음

## 13. Phase 작업 순서

각 phase는 `/phase-N` 형식으로 추적한다. 2026-05-21 기준 `/phase-0`부터 `/phase-7`까지 로컬 PoC 기준으로 완료했고, `/phase-8`은 회귀 테스트와 발표 리허설, Linux 전용 e2e 후속 작업으로 둔다.

### /phase-0 - 문서와 범위 고정

- 이 문서를 기준으로 구현 범위를 고정한다.
- 기존 B-2 상세 설계서와 충돌하지 않는다.
- 별도 runbook 파일을 만들지 않고 이 문서 안에 실행 절차를 계속 보강한다.

완료 기준:

- `docs/B-2_WSL2_실행_시연_계획서.md` 추가
- 공식 gVisor/Docker 문서 링크와 로컬 Linux Docker daemon 사전 확인 절차 반영

### /phase-1 - RealDockerCommandRunner 구현

- `sandbox/b2/real_command_runner.py` 추가
- subprocess 기반 실제 Docker 실행
- inspect/result parsing unit test 추가

완료 기준:

- fake subprocess 또는 monkeypatch 기반 unit test 통과
- 기존 fixture runner test 영향 없음

### /phase-2 - B-2 Docker image 추가

- `sandbox/image/b2/Dockerfile` 추가
- `sandbox/image/b2/requirements.txt` 추가
- image build 명령 문서화

완료 기준:

- 선택한 Linux Docker daemon에서 image build 성공
- trusted entrypoint가 container 내부에 존재

### /phase-3 - demo target과 snapshot 생성

- `scripts/demo_b2_run.py` 추가
- demo snapshot 생성
- `modeling_b2_demo.py`가 정적 분석에서 B-2 sandbox 대상이 되도록 구성

완료 기준:

- demo target 정적 결과가 `CODE_SANDBOX_RUNTIME`, `B-2`, `PENDING_REVIEW`
- `pending_api_refs`에 `self.custom_activation` 포함

### /phase-4 - demo script와 B2HostRunner 연결

- `scripts/demo_b2_run.py`에서 `run_validation_job()` 호출
- `B2HostRunner + RealDockerCommandRunner` 연결

완료 기준:

- 선택한 Linux Docker daemon에서 demo script가 실제 container를 생성하고 정리
- `sandbox_check.json` 저장
- B-2 대상 artifact result에 `details["sandbox_check"]` 부착

### /phase-5 - evidence 저장

- `summary.json`
- `sandbox_check.json`
- `b2_input_manifest.json`
- `docker_inspect.json`
- `docker_logs.txt`
- `runner_result.json`
- `host_runner_output.json`

완료 기준:

- `evidence/sandbox/<timestamp>_<request_id>/` 생성
- 필수 evidence 파일 저장
- token, credential, large model file 저장 없음

### /phase-6 - runsc 실제 시연

- 선택한 Linux Docker daemon에서 Docker/runsc 사전 확인
- B-2 image build
- demo script 실행
- 결과와 evidence 확인

완료 기준:

- `docker run --runtime=runsc --rm hello-world` 성공
- `docker inspect`에서 runtime이 `runsc`
- `runner_result.json` 생성
- `sandbox_check.deployable=false`
- decision이 자동 PASS로 승격되지 않음

2026-05-21 기준 acceptance evidence:

```text
evidence/sandbox/20260520_094857_req-b2-demo
```

확인된 값:

```text
docker_runtime=runsc
runtime_verified=true
decision=B2_POLICY_REVIEW_REQUIRED
forward_status=success
deployable=false
```

상태:

- Docker Desktop `desktop-linux` daemon 기준 완료.
- 별도 WSL2 Ubuntu 배포판 기준 evidence는 선택 재현 작업으로 남김.

### /phase-7 - forward clean path 정리

- entrypoint의 `forward_status=skipped_schema_unknown` 문제를 demo target 기준으로 해결한다.
- 필수 positional 인자 0개 또는 1개인 `forward`에 한해 deterministic input으로 제한 실행한다.

완료 기준:

- runsc runtime 준비 환경의 최종 발표 script에서 `B2_POLICY_REVIEW_REQUIRED` 생성

2026-05-21 상태:

- 완료. `forward_status=success`와 `B2_POLICY_REVIEW_REQUIRED`를 runsc acceptance evidence에서 확인.

### /phase-8 - 회귀 테스트와 발표 리허설

- 기존 fixture 기반 B-2 tests 유지
- 신규 real command runner unit test 통과
- Linux 전용 e2e는 명시적 환경변수에서만 실행
- 발표용 명령과 evidence 확인 절차 리허설

완료 기준:

- 기본 pytest에서 Docker/runsc 없는 환경이 깨지지 않음
- B-2 명시 테스트 통과
- Linux 전용 `RUN_B2_RUNSC_E2E=1` e2e는 후속 구현
- 발표 중 열 evidence 경로 확정

## 14. 발표 시나리오

권장 순서:

```text
1. 안전한 모델/config는 일반 검증에서 통과 또는 안전 경로로 처리
2. eval/subprocess 같은 명확한 위험 코드는 실행 전 BLOCK
3. auto_map custom code trigger는 config 단계에서 감지
4. B-2 대상 코드는 runsc sandbox에서 실제 제한 실행
5. docker inspect와 runner_result evidence 확인
6. sandbox clean이어도 자동 PASS가 아니라 review evidence로 남는 점 설명
```

B-2 발표 멘트:

```text
이 파일은 정적 분석만으로 자동 승인하지 않습니다.
HuggingMask는 B-2로 분류한 뒤 로컬 Linux Docker daemon의 Docker/runsc 기반 gVisor sandbox에서 제한 실행합니다.
실행 후 Docker inspect로 runsc runtime, network none, read-only rootfs를 확인합니다.
runner_result와 sandbox_check를 evidence로 저장합니다.
다만 B-2 clean 결과는 자동 PASS가 아니라 보안 리뷰 evidence입니다.
```

현재 발표 기준 환경은 Docker Desktop `desktop-linux` daemon이다. 별도 WSL2 Ubuntu 배포판에서 같은 명령을 재현할 수 있지만, 현재 acceptance evidence는 `desktop-linux + runsc` 기준으로 설명한다.

## 15. 리스크와 대응

| 리스크 | 대응 |
|---|---|
| 선택한 Linux Docker daemon에 runsc 등록 실패 | `docker run --runtime=runsc --rm hello-world`가 성공할 때까지 HuggingMask demo를 acceptance로 보지 않음 |
| Docker Desktop daemon과 WSL 내부 Docker Engine 설정 혼동 | 하나만 선택하도록 문서화하고 `docker context ls`, `docker info` runtime을 evidence에 남김 |
| Docker logs가 runsc syscall log가 아님 | 1차는 docker logs evidence로 저장하고, runsc debug/strace log 수집은 별도 step으로 분리 |
| entrypoint가 forward를 실행하지 않아 clean decision이 안 나옴 | deterministic forward contract를 별도 구현 |
| demo image가 너무 커짐 | torch 없는 demo target으로 시작 |
| evidence에 민감 정보 저장 | env/token redaction과 `.gitignore` 추가 |
| container cleanup 실패 | `rm` step은 finally에서 항상 실행하고 evidence에 cleanup error 기록 |

## 16. GitHub 업로드 기준

GitHub에 올릴 수 있는 것:

```text
sandbox/b2/real_command_runner.py
sandbox/image/b2/Dockerfile
sandbox/image/b2/requirements.txt
scripts/demo_b2_run.py
docs/B-2_WSL2_실행_시연_계획서.md
tests/test_b2_*.py
```

GitHub에 올리지 않는 것:

```text
.env
HF token
AWS credential
demo_snapshots/
hf_cache/
raw evidence logs
large model files
*.safetensors
*.bin
*.pt
*.pth
```

필요한 `.gitignore` 후보:

```gitignore
demo_snapshots/
hf_cache/
.huggingface/
evidence/sandbox/
*.safetensors
*.bin
*.pt
*.pth
```

## 17. 최종 정의

이 계획의 완료 상태는 다음 한 문장으로 설명할 수 있어야 한다.

```text
HuggingMask는 로컬 Linux Docker daemon에서 B-2 대상 custom model code를 실제 Docker/runsc 기반 gVisor sandbox로 실행하고, host-side inspect와 runner diagnostics를 sandbox_check/evidence로 남기는 캡스톤 시연 PoC를 제공한다.
```
