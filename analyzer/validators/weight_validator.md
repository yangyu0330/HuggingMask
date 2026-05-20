# Weight Validator Guide

## 담당자
정은미

## 목적
safetensors와 pickle 계열 가중치 파일을 검증한다.

## 입력
- `SAFETENSORS` 또는 `PICKLE`로 분류된 `ArtifactRef`
- opcode 정책 버전
- 파일 hash와 크기 정보

## 출력
- `ArtifactValidationResult`
- route kind: `SAFETENSORS_FAST_PATH`, `PICKLE_PATH_A`, `PICKLE_PATH_B`
- reason entries

## 구현 시 주의사항
- safetensors는 metadata와 hash 기반 fast path를 우선한다.
- pickle 계열은 Path A에서 opcode 기반 정적 검증을 수행한다.
- 위험 opcode가 발견되면 즉시 `BLOCK`으로 반환한다.
- Path B sandbox 검증은 필요 시 후속 단계로 연결하되, release 판단은 안전한 결과만 사용한다.

## 관련 테스트
- `tests/test_weight_validator.md`
- `tests/test_validation_flow.md`

## gVisor 보강 설계
- 공통 Docker/runsc 운영 기준은 `docs/gVisor_공통_운영_원칙.md`를 따른다.
- `PICKLE_PATH_B`의 Docker/runsc host evidence 보강은 `docs/PICKLE_PATH_B_gVisor_구현_상세_설계서.md`를 기준으로 한다.
- Path A/YARA/A-B diff/release/cache 정책은 PR #24 구현을 기준으로 하고, 이 문서는 gVisor inspect와 runsc log evidence만 다룬다.
