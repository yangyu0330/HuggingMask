# Whitelist Module Guide

## 담당자
김민우

## 목적
적응형 화이트리스트 엔진은 코드 검증에서 추출한 API 경로를 허용, 차단, 미등록, pending 상태로 판정한다.

## 입력
- 양유상 코드 검증 경로가 추출한 API 경로 목록
- 초기 allow/block 규칙
- pending API 저장소
- 모델과 job 메타데이터

## 출력
- `WhitelistCheckResponse`
- `PendingApiRecord`
- whitelist version

## 구현 시 주의사항
- 미등록 API는 자동 승인하지 않는다.
- `AUTO_APPROVE`는 추천 분류일 뿐이며, 실제 whitelist 반영은 review 승인 이후로 제한한다.
- 김민우는 코드 등급을 직접 결정하지 않는다. 양유상이 whitelist 응답을 보고 code grade와 status를 결정한다.

## 관련 테스트
- `tests/test_whitelist_engine.md`
- `tests/test_code_validator.md`
- `tests/test_validation_flow.md`
