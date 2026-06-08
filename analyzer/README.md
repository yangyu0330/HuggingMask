# Analyzer Module Guide

## 담당자
박용담, 정은미, 양유상

## 목적
`analyzer`는 HuggingMask 검증 파이프라인의 중심 모듈이다. 파일을 분류하고, 공통 JSON 계약을 검증하며, 가중치/코드/config/전처리 메타데이터 검증 결과를 하나의 `ValidationJobResponse`로 조립한다.

## 입력
- `mock_hf` fixture 또는 실제 모델 저장소에서 수집한 파일 목록
- 파일 경로, 파일명, 확장자, SHA256, 크기 정보
- 정책 버전과 whitelist 버전 정보

## 출력
- `ArtifactRef` 목록
- 파일별 `ArtifactValidationResult`
- 최종 `ValidationJobResponse`
- release 대상 artifact 목록과 generated safetensors 목록

## 구현 시 주의사항
- 박용담은 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 계약, 최종 응답 조립 기준을 맡는다.
- 정은미와 양유상 담당 모듈은 임의의 dict를 반환하지 않고 `schemas.md`에 정의된 공통 계약에 맞춘다.
- 프록시는 검증 로직을 직접 구현하지 않고 이 모듈의 service/orchestrator 경로를 호출한다.
- raw pickle은 자동 release하지 않는다. 안전 schema 변환 결과 또는 safetensors 원본만 release 대상으로 삼는다.
- `training_args.bin` 같은 auxiliary pickle은 release artifact가 아니며, 악성 증거가 없는 경우 단독으로 전체 release를 막지 않는다.
- `tokenizer_config.json`, `preprocessor_config.json`, `processor_config.json`, `tokenizer.json`, `chat_template.jinja` 등 전처리 메타데이터는 semantic inventory를 남긴다.

## 관련 테스트
- `tests/test_file_classifier.md`
- `tests/test_json_schema.md`
- `tests/test_validation_flow.md`
- `tests/test_full_pipeline.py`
- `tests/test_weight_validation.py`
- `tests/test_code_semantic.py`
