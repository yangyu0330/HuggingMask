# Whitelist Rules Guide

## 담당자
김민우

## 목적
초기 allow/block 규칙과 namespace 규칙을 관리한다.

## 입력
- 허용 API namespace
- 차단 API 경로
- 정책 버전

## 출력
- whitelist engine이 사용할 규칙 객체
- matched rule 문자열
- whitelist version

## 구현 시 주의사항
- 위험 API는 명시적 block 목록에 둔다.
- `torch.nn.*` 같은 namespace allow는 범위를 좁게 유지한다.
- 규칙 변경 시 whitelist version을 갱신한다.
- 규칙 변경은 캐시 무효화 기준에 포함되어야 한다.

## 관련 테스트
- `tests/test_whitelist_engine.md`
