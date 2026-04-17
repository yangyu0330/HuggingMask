# HuggingMask 증거자료 시스템 가이드 (v1.0)

논문/결과보고서 작성을 쉽게 하기 위해, `evidence/` 폴더의 수집 기준을 고정한 문서입니다.

## 1) 운영 목적
- 개발 진행 증거를 주차별로 누락 없이 남긴다.
- 보고서 본문/부록에 바로 붙일 수 있는 형태로 정리한다.
- 나중에 찾기 쉽도록 파일명/요약 형식을 통일한다.

## 2) 공통 정리 규칙

### 2.1 파일명 규칙
```text
YYYYMMDD_주제_작성자_버전.ext
```

예시:
- `20260408_proxy-healthcheck_YS_v1.png`
- `20260419_ast-risk-test_YS_v2.md`
- `20260502_meeting-minutes_all_v1.md`

### 2.2 문서 상단 메타 정보 (MD 기준)
```md
# 제목
- 날짜: 2026-04-19
- 작성자: 양유상
- 관련 모듈: analyzer/validators/code_validator
- 관련 이슈/PR: #12, #18
- 보고서 사용 위치: 3.2 위험 코드 탐지 실험
```

### 2.3 캡처/로그 저장 원칙
- 캡처에는 반드시 날짜와 화면 맥락(명령어/결과)이 같이 보이게 한다.
- 로그는 원본(`.log`) + 요약(`.md`)를 같이 저장한다.
- 테스트/성능 수치는 표 형태(`.md` 또는 `.csv`)로 남긴다.

## 3) 폴더별 수집 기준

| 폴더 | 반드시 넣을 내용 | 권장 형식 | 최소 개수(주차당) |
|---|---|---|---|
| `worklog` | 작업 단계별 핵심 산출물 요약, 스크린샷, 결정사항 | `.md`, `.png`, `.log` | 요약 1개 + 캡처 3개 |
| `meetings` | 회의록, 참석자, 결정사항, 액션아이템 | `.md`, `.pdf` | 회의당 1개 |
| `tests` | pytest 결과, 수동 테스트표, 실패/수정 내역 | `.md`, `.txt`, `.xml` | 테스트 실행당 1세트 |
| `demo` | 시나리오 입력, 실행 명령, 결과 캡처/영상 | `.md`, `.png`, `.mp4` | 시나리오별 1세트 |
| `perf` | 처리시간, 비교표, 반복 측정 원본 | `.md`, `.csv` | 실험당 1세트 |
| `budget` | 영수증, 사용내역, 정산 요약 | `.jpg`, `.pdf`, `.md` | 지출 건당 1세트 |

## 4) 폴더별 정리 템플릿 + 예시

## 4.1 `worklog`
작업 단계별 대표 요약 파일 1개를 반드시 둡니다.

파일 예시:
`evidence/worklog/20260426_validation_contract_summary_YS_v1.md`

```md
# 구현 단계 요약
- 기간: 2026-04-20 ~ 2026-04-26
- 목표: 인터페이스 기준 확정, 코드 검증+화이트리스트 연동

## 완료 항목
- [x] 인터페이스 정의서 v1.0 확정
- [x] 미등록 API Pending 등록 동작 확인

## 증거 링크
- 테스트 로그: ../tests/20260425_whitelist_pending_test_MW_v1.md
- 회의록: ../meetings/20260422_validation_meeting_all_v1.md
- 데모 캡처: ../demo/20260426_scenario2_pass_YD_v1.png

## 이슈/리스크
- B-2 분류 기준에서 오탐 1건 발생 (다음 주 수정)
```

## 4.2 `meetings`
회의 1회당 1문서 원칙.

파일 예시:
`evidence/meetings/20260422_validation_meeting_all_v1.md`

```md
# 구현 단계 정기회의
- 일시: 2026-04-22 20:00~20:35
- 참석자: 양유상, 박용담, 김민우, 정은미

## 안건
1. 인터페이스 동결 범위 확정
2. Pending API 승인 정책

## 결정사항
- auto_classification은 권고로만 사용
- whitelist 반영은 review_status=APPROVED 이후

## 액션 아이템
- 박용담: 인터페이스 문서 v1.0 확정 (4/23)
- 양유상: AST 탐지 로그 보강 (4/24)
```

## 4.3 `tests`
자동/수동 테스트를 구분해 기록합니다.

파일 예시:
`evidence/tests/20260425_pytest_summary_MW_v1.md`

```md
# 테스트 결과 요약
- 실행일: 2026-04-25
- 환경: Python 3.13, Docker compose

## 자동 테스트(pytest)
- 명령: `python -m pytest -q`
- 결과: 12 passed, 1 skipped
- 원본 로그: `20260425_pytest_raw_MW_v1.txt`

## 수동 테스트
| 항목 | 입력 | 기대결과 | 실제결과 | 판정 |
|---|---|---|---|---|
| /health | GET | 200 | 200 | PASS |
| 악성 pickle | sample_mal.pkl | BLOCK | BLOCK | PASS |
```

## 4.4 `demo`
발표 시나리오별로 입력/명령/결과를 한 문서에 묶습니다.

파일 예시:
`evidence/demo/20260530_demo_scenario03_EM_v1.md`

~~~md
# 데모 시나리오 03 - 악성 pickle 차단
- 목적: 위험 opcode 탐지 시 차단 동작 증명

## 입력
- 파일: `sample_malicious_reduce.pkl`

## 실행 명령
```bash
python run_demo.py --scenario 03
```

## 결과
- status: BLOCK
- reason_code: PICKLE_OPCODE_BLOCKED
- 캡처: `20260530_demo_s03_block_EM_v1.png`
~~~

## 4.5 `perf`
반드시 반복 측정값(최소 3회)과 평균을 같이 남깁니다.

파일 예시:
`evidence/perf/20260518_validation_latency_YD_v1.md`

```md
# 성능 측정 - 검증 지연시간
- 조건: 동일 모델, 정책 fingerprint 고정

| 시나리오 | 1회(ms) | 2회(ms) | 3회(ms) | 평균(ms) |
|---|---:|---:|---:|---:|
| safetensors PASS | 142 | 138 | 145 | 141.7 |
| pickle BLOCK | 421 | 409 | 430 | 420.0 |
```

## 4.6 `budget`
지출 1건당 증빙 세트를 남깁니다.

파일 예시:
`evidence/budget/20260510_meeting_expense_EM_v1.md`

```md
# 회의비 정산 기록
- 일자: 2026-05-10
- 사용처: 팀 회의 식비
- 금액: 38,000원
- 참석자: 4명
- 영수증 파일: `20260510_receipt_EM_v1.jpg`
- 비고: 캡스톤 정산 내역서 반영 완료
```

## 5) 보고서/논문 연결 태그 규칙
문서 하단에 아래 태그를 붙이면 최종 정리할 때 빠르게 필터링할 수 있습니다.

- `[REPORT]` 결과보고서 본문/부록에 사용
- `[PAPER]` 논문 그림/표/실험근거에 사용
- `[DEMO]` 발표 데모 근거에 사용
- `[ADMIN]` 정산/행정 제출용

예시:
```text
태그: [REPORT][PAPER]
```

## 6) 작업 마감 체크리스트 (팀장 확인용)
- [ ] 작업 요약 파일 1개 이상 존재
- [ ] 회의록 1개 이상 존재
- [ ] 테스트 결과(자동/수동) 최신본 존재
- [ ] 데모 캡처 또는 실행 로그 존재
- [ ] 성능/리스크 갱신 여부 확인
- [ ] 필요 시 정산 증빙 첨부 완료

## 7) 권장 인덱스 파일
구현 안정화 단계부터 아래 파일을 추가 운영합니다.

`evidence/evidence_index.md`

구성 예시:
- 작업 단계별 대표 파일 링크
- 보고서용 그림/표 목록
- 논문용 실험 결과 표 목록
- 누락 항목(보완 필요) 목록

---

이 문서 기준으로만 정리하면 보고서/논문 작성 시 자료를 다시 뒤질 필요가 없도록 설계되어 있습니다.
