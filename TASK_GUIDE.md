# TASK GUIDE

HuggingMask 팀의 구현 착수 및 작업 수행 기준 문서입니다.  
현재는 핵심 검증 엔진 제작을 지나 통합 검증 endpoint, 운영 UI, 데모 증빙을 안정화하는 단계입니다.

## 1. 운영 리듬
- 시작 전: 담당 범위와 입력/출력 확인
- 진행 중: 개인 개발 + 짧은 진행 보고
- 종료 전: 테스트 확인, PR 생성, 증빙 자료 정리
- 블로커 발생 시: 같은 날 팀에 공유하고 범위 조정

일일 보고 예시:
```text
[이름] 오늘 완료: ... / 내일 계획: ... / 이슈: ...
```

## 2. 현재 역할 분배
- 박용담: 파일분류, `config.json`, `tokenizer_config.json`, 공통 JSON 스키마/계약, 최종 응답 조립 기준
- 정은미: 가중치검증경로, safetensors 검증, pickle Path A/Path B 검증, 가중치 artifact별 validation result 생성
- 양유상: 코드검증경로, 검증1(`CODE_AST_SCAN`), 검증2(`CODE_RESTRICTED_RUNTIME`), 검증3(`CODE_SANDBOX_RUNTIME`), config가 참조한 `.py` 파일의 코드 검증
- 김민우: 적응형 화이트리스트 엔진, allow/block/unknown/pending 판정, pending API 저장/갱신, adaptive whitelist 정책 문서화, 통합 검증 endpoint와 운영 대시보드 연결

## 3. 작업 단위 규칙
- 기능 전체를 한 번에 하지 말고 작은 단위로 분리
- 한 PR은 한 목적 중심으로 작성
- 모듈 경계를 넘는 수정은 PR 본문에 이유 명시
- 동일 파일 동시 수정은 최대한 피하기

## 4. 작업 시작 체크리스트
- [ ] 현재 `dev` 최신화 완료
- [ ] `feature/*` 브랜치 생성 완료
- [ ] 작업 범위(모듈/파일) 명확화
- [ ] 완료 기준(테스트/동작) 정의

## 5. 작업 수행 체크리스트
- [ ] 코드 직접 읽기 및 흐름 이해
- [ ] 서버/기능 실행 확인
- [ ] 기존 기능 영향 확인
- [ ] 테스트 수행 (`python -m pytest -q`)
- [ ] 불필요 파일/코드 정리

## 6. 작업 종료 체크리스트
- [ ] 커밋 메시지 규칙 준수
- [ ] `feature/*` -> `dev` PR 생성
- [ ] PR 본문 4개 항목 작성
- [ ] 리뷰 요청 완료
- [ ] 증빙 자료 업로드 완료

## 7. 모듈별 기본 책임
- `analyzer`: 박용담/정은미/양유상 담당 검증 흐름의 중심 모듈
- `analyzer/validators`: 정은미/양유상 담당 파일 유형별 검증 경로
- `whitelist`: 김민우 담당 적응형 화이트리스트와 pending API 관리
- `proxy`: FastAPI 진입점. `/health`, `/internal/v1/validation/jobs`, `/internal/v1/validation/full`, whitelist 운영 API, `/dashboard` 제공
- `sandbox`: B-2/C 후보에 대한 격리 실행 증거 수집 및 정책 게이트 담당

## 8. 증빙 자료 운영 규칙
다음 폴더를 작업 단위로 업데이트합니다.
```text
evidence/worklog
evidence/meetings
evidence/tests
evidence/demo
evidence/perf
evidence/budget
```

작업 단위 최소 산출물:
- 회의록
- 테스트 결과
- 주요 결정 기록
- 데모 캡처/로그
- 버그 및 수정 내역

## 9. 지연 시 대응 원칙
- 2일 이상 지연 항목은 월요일 회의에서 즉시 재분배
- 핵심 경로 지연 시 범위 축소 우선순위 적용
- 통합 실패 시 개인 작업보다 통합 안정화 우선

## 10. 최종 목표
각 담당자가 만든 검증 경로를 공통 JSON 계약과 단일 endpoint로 안정적으로 붙이고, 데모/운영 증빙까지 재현 가능한 상태를 만든다.
- 박용담/정은미/양유상/김민우 입출력 계약 일치
- mock fixture 및 local snapshot 기반 검증 가능
- `POST /internal/v1/validation/full`에서 가중치 + 코드 + config + whitelist + 제한 런타임 통합 판정 가능
- 운영 대시보드에서 pending/review/audit/feedback 확인 가능
- `python -m pytest -q` 통과
- 구현 근거와 테스트 결과 증빙
