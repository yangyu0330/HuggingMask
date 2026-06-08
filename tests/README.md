# Tests Guide

## 담당자
공통: 박용담, 정은미, 양유상, 김민우

## 목적
역할별 구현물이 공통 계약에 맞게 동작하는지 fixture 기반으로 검증하고, 발표 전 회귀 여부를 확인한다.

## 입력
- `mock_hf` fixture
- analyzer 검증 결과
- whitelist 검증 결과
- proxy health endpoint

## 출력
- pytest 결과
- fixture별 pass/block/pending 판단
- 회귀 여부
- Docker/health smoke 결과는 별도 운영 증빙으로 기록

## 구현 시 주의사항
- 기존 `tests/test_health.py`는 프록시 최소 동작 확인용으로 유지한다.
- 기능 변경 시 담당 모듈 테스트와 통합 흐름 테스트를 함께 확인한다.
- 발표 주간에는 `python -m pytest -q` 전체 통과를 기본 기준으로 삼는다.

## 현재 발표 전 기준
- 확인일: 2026-06-08
- 명령: `python -m pytest -q`
- 결과: `700 passed, 1 skipped`

## 관련 테스트
- `tests/test_health.py`
- `tests/test_validation_jobs.py`
- `tests/test_full_pipeline.py`
- `tests/test_weight_validation.py`
- `tests/test_code_semantic.py`
- `tests/test_router_e2e.py`
- `tests/test_dashboard_and_ops.py`
