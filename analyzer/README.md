# Analyzer Module Guide

## 담당자
박용담, 정은미, 양유상

## 목적
`analyzer`는 HuggingMask 검증 파이프라인의 중심 모듈이다. 파일을 분류하고, 공통 JSON 계약을 검증하며, 가중치 검증과 코드 검증 결과를 하나의 `ValidationJobResponse`로 조립한다.

## 입력
- `mock_hf` fixture 또는 실제 모델 저장소에서 수집한 파일 목록
- 파일 경로, 파일명, 확장자, SHA256, 크기 정보
- 정책 버전과 whitelist 버전 정보

## 출력
- `ArtifactRef` 목록
- 파일별 `ArtifactValidationResult`
- 최종 `ValidationJobResponse`

## 구현 시 주의사항
- 박용담은 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 계약, 최종 응답 조립 기준을 맡는다.
- 정은미와 양유상 담당 모듈은 임의의 dict를 반환하지 않고 `schemas.md`에 정의된 공통 계약에 맞춘다.
- 프록시 서버는 이 모듈을 직접 구현하지 않고, 나중에 `orchestrator`를 호출하는 얇은 진입점으로 연결한다.

## 관련 테스트
- `tests/test_file_classifier.md`
- `tests/test_json_schema.md`
- `tests/test_validation_flow.md`
