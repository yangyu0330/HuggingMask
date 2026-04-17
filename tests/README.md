# Tests Guide

## 담당자
공통: 박용담, 정은미, 양유상, 김민우

## 목적
역할별 구현물이 공통 계약에 맞게 동작하는지 fixture 기반으로 검증한다.

## 입력
- `mock_hf` fixture
- analyzer 검증 결과
- whitelist 검증 결과
- proxy health endpoint

## 출력
- pytest 결과
- fixture별 pass/block/pending 판단
- 회귀 여부

## 구현 시 주의사항
- 이번 단계에서는 테스트 설명서만 추가하고 실제 테스트 코드는 변경하지 않는다.
- 기능 구현 후에는 각 담당자가 자기 모듈 테스트를 먼저 추가하고, 마지막에 통합 흐름 테스트를 추가한다.
- 기존 `tests/test_health.py`는 프록시 최소 동작 확인용으로 유지한다.

## 관련 테스트
- `tests/test_health.py`
