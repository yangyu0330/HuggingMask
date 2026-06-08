# HuggingMask 프로젝트 — 진행 현황 및 아키텍처 종합

> 비교과 활동 제출용 자료. 외부인이 읽어도 이해되도록 작성.
>
> 기준일: 2026-05-19 / 작성자: 김민우 (캡스톤디자인 팀원)

---

## 1. 프로젝트 한눈에 보기

| 항목 | 내용 |
|---|---|
| 프로젝트명 | **HuggingMask — AI 모델 공급망 보안 검증 프록시** |
| 목적 | HuggingFace 등 외부에서 받은 AI 모델 파일(.bin / .safetensors / .py / config.json)이 안전한지 사전 검증해서 악성 모델 차단 |
| 기간 | 2026-03-29 ~ 진행 중 (2026-05-19 기준 약 7주 차) |
| 팀 구성 | 4명 (캡스톤디자인) |
| 기술 스택 | Python 3.13, FastAPI, SQLAlchemy 2.0, Docker Compose, pytest |
| 코드 규모 | Python 약 **31,000+ 줄** (analyzer 5,435 / whitelist 4,330 / tests 5,944 / proxy 77 + 기타) |
| GitHub | `yangyu0330/HuggingMask` — 머지 PR **17개**, OPEN PR **4개** |
| 실행 | `docker compose up --build` → `http://127.0.0.1:8000/dashboard` |

---

## 2. 왜 이 프로젝트가 필요한가

최근 AI 모델은 코드와 가중치가 함께 배포되는 형태가 늘었다. 특히 HuggingFace 등 공개 저장소에서 모델을 받을 때:

1. **가중치 파일(.bin / .pkl)** 안에 pickle 역직렬화 폭탄이 숨어 있을 수 있다
2. **모델 코드(modeling_*.py / tokenization_*.py)** 가 `os.system` / `subprocess` / `requests.get` 같은 외부 통신·실행 함수를 호출해 토큰·자격증명을 탈취할 수 있다
3. **설정 파일(config.json)** 의 `auto_map` / `trust_remote_code` 같은 키가 임의 코드 실행 진입점이 된다

HuggingMask는 모델을 다운로드받기 전·받는 즉시에 위 3가지 위협을 **검증 파이프라인**으로 막아서, 안전한 모델만 사용자 환경에 도달하게 한다.

---

## 3. 시스템 아키텍처

### 3.1 전체 구조 — 4개 레이어

```
사용자 ──→ [Proxy 8000] ──→ [Analyzer 검증 파이프라인] ──→ [Whitelist 화이트리스트 엔진]
                                  │                              │
                                  ↓                              ↓
                             [Sandbox 격리 실행]            [감사 로그 / 운영 대시보드]
```

| 레이어 | 모듈 | 책임 |
|---|---|---|
| ① Proxy | `proxy/app/main.py` | FastAPI 진입점, health / validation jobs / dashboard 라우팅 |
| ② Analyzer | `analyzer/` | 파일 분류 → 적합한 검증기로 dispatch (orchestrator) |
| ③ Validators | `analyzer/validators/` | 파일 유형별 정적 + 동적 검증 |
| ④ Whitelist | `whitelist/` | API 호출 4-state 판정 + 감사 chain + 운영 UI |

### 3.2 검증 파이프라인 — 모델 파일 4종이 검증되는 흐름

```
HuggingFace 모델 다운로드 요청
   │
   ▼
[1] 파일 분류 (classifier)
   ├── *.bin / *.safetensors  →  가중치 검증
   ├── *.py                    →  코드 검증
   ├── config.json             →  설정 검증
   └── tokenizer_config.json   →  설정 검증
   │
   ▼
[2] 검증 단계 (validators)

  가중치 (정은미)
   ├── pickle opcode 정적 분석 → REDUCE / GLOBAL 등 위험 opcode 탐지
   ├── safetensors 헤더 검증 → 안전 포맷 확인
   ├── YARA 룰 매칭 → 시그니처 기반 악성 패턴 탐지
   └── (위험 시) Docker sandbox에서 격리 로드

  코드 (양유상 + 김민우)
   ├── 검증1 CODE_AST_SCAN (양유상)
   │   └── AST 정적 분석 → eval/exec/os.system 등 즉시 차단
   ├── 검증2 CODE_RESTRICTED_RUNTIME (김민우) ⭐ 본인 양도분
   │   └── multiprocessing + builtins/import/audit hook 9겹 격리 실행
   └── 검증3 CODE_SANDBOX_RUNTIME (양유상)
       └── gVisor 컨테이너 격리 (현재 설계 완료, 구현 진행 중)

  설정 (박용담)
   ├── config.json AST 검증
   ├── tokenizer_config.json 라우팅
   └── 전처리 파일 AST 검증 (preprocessing_validator) — 5/17 추가

[3] API 호출 → 화이트리스트 판정 (김민우)
   ├── 4-state: ALLOWED / PENDING / UNKNOWN / BLOCKED
   ├── 공식 문서 크롤러 (mod1) — PyTorch / Transformers / NumPy 문서에서 안전 API 추출
   ├── Verified Org 분석 (mod2) — HuggingFace 공식 조직(google/meta 등) 실제 모델에서 API 사용 패턴 학습
   └── 감사 로그 (SHA256 hash chain) — 변조 불가 기록

[4] 결과 응답 (orchestrator)
   ├── 안전 → 사용자에게 모델 전달
   ├── 위험 → 차단 + 사유 반환
   └── 검토 필요 → 운영 대시보드의 PENDING 목록으로 → 보안 담당자 승인
```

### 3.3 핵심 기술 포인트 4가지

**① 4-state 적응형 화이트리스트 (김민우)**
- 단순 allow/deny가 아니라 **PENDING / UNKNOWN** 중간 상태를 둠
- 처음 보는 API는 자동 PENDING → 운영 담당자가 4탭 대시보드에서 승인·거부
- 결정은 SHA256 해시 체인으로 감사 기록 (변조 불가)

**② 제한 런타임 9겹 격리 (김민우, 양유상 영역에서 양도)**
1. multiprocessing.Process (spawn) — 메인 프로세스 보호
2. resource.setrlimit(RLIMIT_AS) — 메모리 폭탄 차단 (Linux/Mac)
3. sys.meta_path import hook — 차단 모듈 즉시 reject
4. sys.modules 캐시 정리 — cache hit 우회 방지
5. sys.addaudithook — subprocess.Popen / socket.connect 등 즉시 raise
6. builtins overlay — eval/exec/compile/open 제거
7. AST 사전 검사 — `__subclasses__` / `__mro__` 등 30개 introspection dunder 차단
8. _SafeSysProxy — sys._getframe / settrace 등 frame/trace 우회 봉쇄
9. Process.join(timeout) + kill — 무한 루프 강제 종료

**③ 공급망 신뢰 학습 (김민우 mod1+mod2)**
- 공식 문서를 정기 크롤링해 안전 API 목록 자동 생성 (mod1)
- HuggingFace Verified Org(google/meta/microsoft 등) 실제 모델 코드에서 API 사용 패턴 분석 → API 별 사용 모델 수 집계 (mod2)
- 두 결과를 DB에 자동 반영해 화이트리스트 엔진의 판정 근거로 사용

**④ 가중치 사전 검증 (정은미)**
- pickle opcode 파서로 역직렬화 폭탄 탐지
- safetensors 변환 후 헤더 검증 + tensor diff 비교
- YARA 룰 1,219줄로 시그니처 기반 악성 패턴 탐지

---

## 4. 팀 역할 분담

| 멤버 | 담당 영역 | 핵심 모듈 | 누적 PR |
|---|---|---|---|
| 양유상 | 코드 검증 (검증1·검증3) + Orchestrator | `analyzer/validators/code_*` + `analyzer/orchestrator.py` | PR #1, #4-#12 등 (베이스라인) |
| 박용담 | 파일 분류 + 설정 검증 + 전처리 | `analyzer/classifier.py` + `analyzer/validators/preprocessing_validator.py` | PR #23 (5/17) |
| 정은미 | 가중치 검증 + 샌드박스 | `analyzer/validators/weight/` (14파일, YARA 1,219줄) | PR #15 (5/9), PR #24 (5/17) |
| **김민우** | **적응형 화이트리스트 엔진 + 제한 런타임 (양도)** | `whitelist/` 전체 + `analyzer/validators/code_restricted_runtime.py` | PR #9, #14, #16, #18→#20, #17 |

---

## 5. 진행 현황 시기별

### 5.1 1단계 — 환경·설계 (3월 말 ~ 4월 중순)

- **3-29 ~ 4-01**: 레포 셋업, FastAPI 부트스트랩, CI 설정, 인터페이스 정의서 v1.0 합의
- **4-17 ~ 4-22**: 코드 검증 파이프라인 설계 + 인터페이스 계약 정합화 (양유상 PR #6 ~ #10)

### 5.2 2단계 — 핵심 엔진 구현 (4월 말 ~ 5월 초)

- **4-20 ~ 4-22**: 김민우 화이트리스트 엔진 초기 구현 (PR #9 머지, 87 신규 테스트)
- **4-27 ~ 5-04**: 양유상 config.json/tokenizer_config.json 검증 엔진 (PR #11, #12)
- **5-05 ~ 5-06**: 김민우 양유상 코드 검증기 통합 어댑터 (PR #14 머지, 238 테스트)
- **5-06**: 김민우 mod1 공식 문서 크롤러 + mod2 Verified Org 분석 (PR #16 머지, 266 테스트) → 화이트리스트 5/5 모듈 풀스택 완성

### 5.3 3단계 — 양도분·확장 (5월 둘째 주)

- **5-07 ~ 5-08**: 양유상 영역에서 김민우에게 검증2(제한 런타임 별4) 양도
  - PR #17 — multiprocessing + 9겹 격리, 35 신규 테스트
- **5-08**: 김민우 운영 대시보드 + bulk 승인 스크립트 (PR #18 → revert → PR #20 재제출)
- **5-09**: 정은미 가중치 검증 풀스택 머지 (PR #15)
- **5-09**: 김민우 PR #17 양유상 리뷰 P1+P2+P3 응답 — 9겹 격리로 강화, 287 passed / 3 skipped

### 5.4 4단계 — 정리·점검 (5월 셋째 주)

- **5-11 ~ 5-13**: 팀 설계서 상호 리뷰 (.docx 6편 작성), 정은미 코드 정밀 분석 후 Issue #21 (P0 5·P1 5·P2 5건)
- **5-17**: 박용담 전처리 AST 검증기 PR #23 추가, 정은미 보안 피드백 반영 PR #24 추가
- **5-18**: 김민우 PR #17 dev 머지로 drift 해소 (diff -7709 → -3, 머지 사고 방지). 양유상이 9일 침묵 깨고 PR #17·#20·#23 일제 리뷰

### 5.5 누적 통계 (5-19 기준)

| 항목 | 값 |
|---|---|
| 총 머지된 PR | 17개 |
| 현재 OPEN PR | 4개 (PR #17 김민우, #20 김민우, #23 박용담, #24 정은미) |
| 현재 OPEN Issue | 2개 (#21 정은미 follow-up, #25 본인 영역 새 버그) |
| 신규 자동 회귀 테스트 | **363+ passed / 3 skipped** (브랜치별로 상이) |
| 추가 코드 라인 | **22,500+ 줄** (.py / yara / docs / evidence 합산) |
| 작성된 설계·리뷰 문서 (.docx) | 6편 |

---

## 6. 김민우 본인 영역 — 상세 산출물

### 6.1 적응형 화이트리스트 엔진 5/5 모듈 풀스택

```
whitelist/
├── engine.py          ─ 4-state 판정 엔진 (ALLOWED/PENDING/UNKNOWN/BLOCKED)
├── router.py          ─ FastAPI 엔드포인트 9개 (check/upsert/review/feedback/audit/...)
├── pending_store.py   ─ PendingApi 저장소 (dedup, seen_count 추적)
├── audit.py           ─ SHA256 hash chain 감사 로그 (변조 불가)
├── feedback.py        ─ 오탐 피드백 루프
├── integration.py     ─ 양유상 code_validator 통합 어댑터 (Protocol 주입)
├── cache_loader.py    ─ mod1/mod2 결과 자동 동기화
├── mod1_doc_crawler.py + mod1_real_crawler.py + mod1_package_inspector.py
│                      ─ 모듈 ①: 공식 문서 크롤러 (PyTorch / Transformers / NumPy)
├── mod2_verified_org.py + mod2_real_fetcher.py
│                      ─ 모듈 ②: HuggingFace Verified Org 분석
├── rules.py           ─ 정책 상수 (CRAWL_TARGETS / VERIFIED_ORGANIZATIONS 등)
└── static/dashboard.html ─ 운영 4탭 UI
```

### 6.2 제한 런타임 (양도분)

```
analyzer/validators/code_restricted_runtime.py  (약 600줄, 9겹 격리)
tests/test_restricted_runtime.py                (962줄, 63 회귀 테스트)
```

### 6.3 운영 대시보드 4탭

- 탭 1: 분류 테스트 — 임의 API 입력 즉시 판정
- 탭 2: 리뷰 대기 — PENDING API 목록 / 페이지·검색·필터
- 탭 3: 승인 — bulk 승인 / 조건부 승인
- 탭 4: 오탐·감사 — feedback 신고 + audit chain 검증

### 6.4 누적 PR 상태

| PR | 제목 | 상태 |
|---|---|---|
| #9 | 화이트리스트 엔진 초기 구현 | ✅ MERGED (4-22) |
| #14 | 양유상 코드 검증자 통합 어댑터 | ✅ MERGED (5-9) |
| #16 | mod1 + mod2 + cache_loader | ✅ MERGED (5-9) |
| #17 | 제한 런타임 9겹 격리 | OPEN, 양유상 리뷰 응답 중 |
| #18 → #20 | 운영 대시보드 + bulk 스크립트 | OPEN (#18 revert 후 #20 재제출) |

---

## 7. 현재 사용 중인 보안 메커니즘 — 외부에 설명할 핵심 8개

| # | 메커니즘 | 위치 | 효과 |
|---|---|---|---|
| 1 | pickle opcode 파서 | weight 검증 | 역직렬화 폭탄 사전 차단 |
| 2 | safetensors 변환 + diff | weight 검증 | 안전 포맷 강제 |
| 3 | YARA 1,219줄 룰 | weight 검증 | 시그니처 기반 악성 패턴 |
| 4 | AST 정적 검증 | code 검증1 + preprocessing | eval/exec/os.system 즉시 차단 |
| 5 | 9겹 제한 런타임 | code 검증2 | 동적 격리 실행 |
| 6 | gVisor 컨테이너 (설계 완료) | code 검증3 | OS-level 격리 |
| 7 | 4-state 화이트리스트 | whitelist | API 단위 적응형 판정 |
| 8 | SHA256 hash chain 감사 | whitelist | 변조 불가 의사결정 로그 |

---

## 8. 검증 시나리오 — 실제 동작 예시

### 시나리오 A — 안전한 모델
```
사용자 다운로드: huggingface.co/google/bert-base-uncased
   ↓
classifier:    config.json + tokenizer.json + model.safetensors + .py 4종
   ↓
config 검증:   auto_map / trust_remote_code 없음 → PASS
weight 검증:   safetensors 헤더 정상 + YARA 매칭 없음 → PASS
code 검증1:    AST 정적 → 위험 함수 0건 → PASS
화이트리스트:  사용 API 모두 ALLOWED → PASS
   ↓
결과: ✅ 안전, 사용자에게 전달
```

### 시나리오 B — 악성 코드 모델
```
사용자 다운로드: huggingface.co/<unknown_user>/evil-bert
   ↓
classifier:    modeling_bert.py 안에 `eval(config.get("init"))` 발견
code 검증1:    AST 정적 → eval 호출 즉시 차단
   ↓
결과: 🚫 BLOCKED, 사유 = "DangerousCallDetected: eval()"
화이트리스트: 사용된 API "evil_lib.exec" → 처음 보는 API → PENDING으로 등록
운영자: 대시보드 탭 2에서 확인 후 거부
```

### 시나리오 C — 검토 필요 (PENDING)
```
사용자 다운로드: huggingface.co/research_lab/custom-audio-model
   ↓
code 검증1:    AST 정적 → 위험 함수 0건 → PASS
화이트리스트:  사용 API "custom_audio_lib.normalize" → 처음 보는 API
              → 자동 PENDING 등록 + B-2 격상 → 제한 런타임으로
code 검증2:    9겹 격리 실행 → 외부 통신 시도 없음 / 메모리·시간 정상 → PASS
   ↓
결과: ⚠️ 검토 필요, 운영 담당자가 대시보드에서 ALLOWED 또는 BLOCKED 결정
       결정은 SHA256 chain에 영구 기록
```

---

## 9. 남은 일정 (5-19 기준)

- 단기 (~5-25): PR #17 / #20 양유상 신규 리뷰 응답 (어젯밤 일제 리뷰), Issue #25 신규 버그 fix
- 중기 (~6-05): 박용담 PR #23 머지 + 정은미 PR #24 머지 + 결합 인터페이스 정합화
- 장기 (~6-15): 양유상 검증3 gVisor 샌드박스 구현 완료 → 4명 풀스택 결합 e2e
- 발표·캡스톤 데모: `docker compose up --build` → 4탭 대시보드 4종 시나리오 시연

---

## 10. 관련 자료

- GitHub: https://github.com/yangyu0330/HuggingMask
- 인터페이스 정의서 v1.0: `docs/HuggingMask_인터페이스정의서_v1_0_Notion.md`
- 개발 표준: `docs/dev_standard.md`
- 데모 스크립트: `docs/final_demo_script.md`
- 실행 가이드: `SETUP_GUIDE.md`, `TASK_GUIDE.md`
- 증빙 자료: `evidence/worklog/` (작업 로그), `evidence/tests/` (테스트 결과), `evidence/demo/` (시연 자료)

---

*이 문서는 비교과 활동 제출용으로 외부 독자가 읽을 수 있도록 작성되었습니다. 코드 세부사항은 위 GitHub 저장소에서 직접 확인 가능합니다.*
