# Classifier Guide

## 담당자
박용담

## 목적
모델 저장소의 파일을 검증 가능한 artifact로 분류하고 `ArtifactRef` 생성을 위한 기본 정보를 만든다.

## 입력
- 저장소 기준 상대 경로
- 실제 로컬 파일 경로
- 파일명과 확장자
- 파일 크기와 SHA256

## 출력
- 파일별 `file_kind`
- `ArtifactRef` 생성에 필요한 메타데이터
- 분류 실패 시 reason code

## 구현 시 주의사항
- `.safetensors`는 `SAFETENSORS`로 분류한다.
- `.pkl`, `.pt`, `.bin` 등 pickle 계열은 `PICKLE`로 분류한다.
- `.py`는 `PYTHON`으로 분류한다.
- `config.json`은 `CONFIG_JSON`으로 분류한다.
- `tokenizer_config.json`은 `TOKENIZER_CONFIG_JSON`으로 분류한다.
- 분류가 불명확한 파일은 `OTHER`로 두고 검증 경로에서 안전하게 처리한다.

## 관련 테스트
- `tests/test_file_classifier.md`
- `tests/test_validation_flow.md`
