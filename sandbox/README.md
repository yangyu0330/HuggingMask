# Sandbox Module Guide

## B-2 gVisor Phase 0-13 status

Implemented host-side contract so far:

- B-2 sandbox target boundary in the orchestrator.
- Snapshot-only source resolver and verified-only staging.
- `config.json` `auto_map` Python promotion to sibling artifact results.
- B-1 runtime failure separation from B-2 sandbox candidates.
- B-2 input manifest, local import closure, support JSON handling, and canonical manifest hashing.
- Runner-result decision builder where clean sandbox evidence remains policy review, never automatic PASS.
- Optional orchestrator pipeline wiring for direct Python and auto_map sibling Python.
- Docker/runsc command and lifecycle planning as `list[str]` only.
- Docker inspect fixture validator and runsc log fixture parser.
- Trusted in-container B-2 entrypoint contract with manifest/hash verification before import.
- Injectable `B2HostRunner` coordinator using a fake/fixture `CommandRunner`.
- Full fixture end-to-end tests from `run_validation_job()` through `artifact.details.sandbox_check`.
- PR hardening coverage for `python -I -S`, inspect planned host mount source checks, and B-2 schema round-trips.
- Real subprocess-backed Docker lifecycle runner for local Linux Docker daemon demo use, still injected and opt-in.
- Local B-2 demo image and script contract for Docker/runsc evidence collection.

Not implemented yet:

- No real Docker/runsc execution is enabled by default in pytest or normal validation jobs.
- No Linux runsc e2e test is wired yet.
- No production queue/DB/review UI integration is present.

## 담당자
정은미, 양유상, 공통

## 목적
`sandbox`는 가중치 검증 Path B 또는 코드 runtime 검증이 필요할 때 제한 실행 증빙을 제공하는 opt-in 모듈이다. 기본 pytest와 일반 validation job은 실제 Docker/runsc 실행에 의존하지 않는다.

## 입력
- sandbox 실행이 필요한 artifact
- runtime profile
- 네트워크와 파일시스템 제한 정책

## 출력
- 실행 로그
- syscall 또는 runtime anomaly 결과
- validator가 사용할 검증 근거

## 구현 시 주의사항
- sandbox 결과가 있어도 최종 release 판단은 orchestrator에서 한다.
- 네트워크 차단, read-only filesystem, timeout 정책을 기본 전제로 둔다.
- 구현 전까지 정은미/양유상 담당 모듈은 sandbox가 없을 수 있음을 명시적으로 처리해야 한다.
- Docker/runsc 실환경 실행은 로컬 데모 스크립트와 별도 이미지 기준으로 검증한다.

## 관련 테스트
- `tests/test_weight_validator.md`
- `tests/test_code_validator.md`
- `tests/test_validation_flow.md`
- `tests/test_b2_full_fixture_flow.py`
- `tests/test_b2_demo_script_contract.py`

## 상세 설계
- gVisor 공통 운영 원칙: `docs/gVisor_공통_운영_원칙.md`
- 코드 B-2 gVisor 설계: `docs/B-2_gVisor_구현_상세_설계서.md`
- 가중치 pickle Path B gVisor host evidence 설계: `docs/PICKLE_PATH_B_gVisor_구현_상세_설계서.md`
- 가중치 문서는 PR #24의 weight validator 구현을 전제로 하며, Docker inspect와 runsc log 기반 검증만 다룬다.
