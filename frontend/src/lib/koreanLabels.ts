const statusLabels: Record<string, string> = {
  PASS: '통과 (PASS)',
  BLOCK: '차단 (BLOCK)',
  PENDING_REVIEW: '검토 필요 (PENDING_REVIEW)',
  ERROR: '오류 (ERROR)',
  SKIPPED: '건너뜀 (SKIPPED)',
  APPROVE: '승인 (APPROVE)',
  APPROVE_WITH_TRANSFORM: '변환 후 승인 (APPROVE_WITH_TRANSFORM)',
  DENY: '거부 (DENY)',
  REVIEW_REQUIRED: '검토 필요 (REVIEW_REQUIRED)',
  ALLOWED: '허용 (ALLOWED)',
  BLOCKED: '차단 (BLOCKED)',
  UNKNOWN: '미확인 (UNKNOWN)',
  PENDING: '대기 (PENDING)',
  UNDER_REVIEW: '검토 중 (UNDER_REVIEW)',
  APPROVED: '승인됨 (APPROVED)',
  REJECTED: '거부됨 (REJECTED)',
  DEFERRED: '보류됨 (DEFERRED)',
  AUTO_APPROVE: '승인 추천 (AUTO_APPROVE)',
  CONDITIONAL: '조건부 검토 (CONDITIONAL)',
  MANUAL: '수동 검토 (MANUAL)',
  INITIAL: '초기 규칙 (INITIAL)',
  AUTO_CRAWL: '자동 수집 (AUTO_CRAWL)',
  MANUAL_REVIEW: '수동 검토 (MANUAL_REVIEW)',
};

const reviewDecisionLabels: Record<string, string> = {
  approve: '승인',
  reject: '거부',
  defer: '보류',
  conditional: '조건부 승인',
};

const evidenceKindLabels: Record<string, string> = {
  demo: '데모',
  design: '설계',
  worklog: '작업 기록',
  tests: '테스트',
};

const fileKindLabels: Record<string, string> = {
  SAFETENSORS: '안전 가중치 파일',
  PICKLE: 'pickle/bin 가중치 파일',
  PYTHON: 'Python 코드 파일',
  CONFIG_JSON: 'config 설정 파일',
  TOKENIZER_CONFIG_JSON: 'tokenizer 설정 파일',
  TOKENIZER_JSON: 'tokenizer 파일',
  SPECIAL_TOKENS_MAP_JSON: '특수 토큰 설정',
  ADDED_TOKENS_JSON: '추가 토큰 설정',
  VOCAB_JSON: '어휘 파일',
  MERGES_TXT: '토크나이저 병합 파일',
  PREPROCESSOR_CONFIG_JSON: '전처리 설정 파일',
  PROCESSOR_CONFIG_JSON: '프로세서 설정 파일',
  CHAT_TEMPLATE_JINJA: '채팅 템플릿 파일',
  OTHER: '기타 파일',
};

const routeKindLabels: Record<string, string> = {
  SAFETENSORS_FAST_PATH: 'safetensors 빠른 검증',
  PICKLE_PATH_A: 'pickle 정적 검사',
  PICKLE_PATH_B: 'pickle 샌드박스 근거',
  CODE_AST_SCAN: 'Python 정적 코드 검사',
  CODE_RESTRICTED_RUNTIME: 'Python 제한 런타임 검사',
  CODE_SANDBOX_RUNTIME: 'Python B-2 샌드박스 근거',
  CONFIG_SCHEMA_VALIDATION: 'config 설정 검사',
  PREPROCESSING_SEMANTIC_SCAN: '전처리 의미 검사',
};

const reviewActionLabels: Record<string, string> = {
  NONE: '추가 조치 없음',
  AUTO_APPROVE: '자동 승인 추천',
  AUTO_APPROVE_REGENERATED: '재생성 산출물 승인 추천',
  SECURITY_OWNER_GATE: '보안 담당자 검토 필요',
  MANUAL_REVIEW_REQUIRED: '수동 검토 필요',
  BLOCK_IMMEDIATELY: '즉시 차단',
  AUTO_LOG_REVIEW: '로그 검토',
};

const releaseActionLabels: Record<string, string> = {
  APPROVE_AND_STORE: '승인 후 저장',
  APPROVE: '승인',
  DENY: '릴리스 거부',
  REVIEW_QUEUE: '검토 대기열로 이동',
  ERROR: '오류 확인 필요',
};

const reasonCodeLabels: Record<string, { title: string; detail: string }> = {
  SAFE_TENSORS_HASH_OK: {
    title: 'safetensors 해시 확인',
    detail: '가중치 파일의 해시와 기본 메타데이터가 기대한 형식으로 확인됐습니다.',
  },
  PICKLE_OPCODE_ALLOWED_ONLY: {
    title: 'pickle 정적 검사 통과',
    detail: 'pickle 내부 opcode에서 즉시 차단해야 할 위험 패턴을 발견하지 못했습니다.',
  },
  PICKLE_OPCODE_BLOCKED: {
    title: '위험 pickle opcode 차단',
    detail: 'pickle이 로드될 때 임의 코드 실행으로 이어질 수 있는 위험 opcode가 발견됐습니다.',
  },
  PICKLE_CONVERTED: {
    title: '안전 산출물로 변환',
    detail: '원본 pickle을 그대로 배포하지 않고 safetensors 산출물로 변환하는 흐름입니다.',
  },
  PICKLE_PATH_B_NOT_AVAILABLE: {
    title: 'Path B 샌드박스 미사용',
    detail: '현재 환경에서 선택 샌드박스 근거를 실행할 수 없어 보안 검토 근거로 남깁니다.',
  },
  PICKLE_PATH_B_LOAD_OK: {
    title: 'Path B 샌드박스 로드 관찰',
    detail: '제한된 환경에서 pickle 로드 관찰 근거가 수집됐습니다. 최종 승인은 별도 정책을 따릅니다.',
  },
  DANGEROUS_IMPORT: {
    title: '위험 import 발견',
    detail: '운영 환경에서 허용하기 어려운 모듈 import가 발견되어 차단합니다.',
  },
  DANGEROUS_CALL: {
    title: '위험 함수 호출 발견',
    detail: 'eval, exec, 파일 삭제, 프로세스 실행처럼 안전하지 않은 호출이 발견됐습니다.',
  },
  DANGEROUS_API: {
    title: '차단 API 발견',
    detail: '화이트리스트 정책에서 영구 차단한 API가 사용됐습니다.',
  },
  CONTEXT_API_REVIEW: {
    title: '문맥 검토 API',
    detail: 'API 이름만으로는 안전성을 확정할 수 없어 호출 문맥을 보안 담당자가 확인해야 합니다.',
  },
  CONTEXT_API_BLOCKED: {
    title: '문맥상 차단 API',
    detail: '파일 쓰기, 외부 통신, 민감 정보 접근 등 위험한 문맥으로 판단됐습니다.',
  },
  UNREGISTERED_API: {
    title: '미등록 API 사용',
    detail: '아직 승인 목록에 없는 API가 사용되어 자동 승인 대신 검토 대기열로 보냅니다.',
  },
  GRADE_B2_GATE_REQUIRED: {
    title: 'B-2 보안 게이트 필요',
    detail: '자동 승인하기에는 근거가 부족해 샌드박스 근거 또는 보안 담당자 검토가 필요합니다.',
  },
  GRADE_B1_RUNTIME_OK: {
    title: 'B-1 제한 런타임 통과',
    detail: '정형 모델링 코드가 제한 런타임 게이트를 통과했습니다.',
  },
  GRADE_A_REGENERATED: {
    title: 'A 등급 재생성 가능',
    detail: '원본 코드를 신뢰하지 않고 안전한 설정 또는 산출물로 재생성할 수 있습니다.',
  },
  GRADE_C_MANUAL_REVIEW: {
    title: 'C 등급 수동 검토',
    detail: '동적 코드, 난독화, 역할 불명 등으로 자동 판단이 어렵습니다.',
  },
  CONFIG_TRIGGER_FIELD_FOUND: {
    title: 'config 트리거 필드 발견',
    detail: 'auto_map, custom pipeline처럼 Python 코드 로딩을 유도할 수 있는 설정이 발견됐습니다.',
  },
  RUNTIME_GATE_SKIPPED: {
    title: '제한 런타임 미실행',
    detail: 'B-1 자동 승인을 위한 제한 런타임 근거가 없어 B-2 검토로 보냅니다.',
  },
  RUNTIME_GATE_ERROR: {
    title: '제한 런타임 오류',
    detail: '코드 자체의 악성 증거가 아니라 실행 환경 또는 검증기 오류를 확인해야 합니다.',
  },
  VALIDATOR_INFRA_ERROR: {
    title: '검증기 인프라 오류',
    detail: '파일 읽기, 검증기 실행, 환경 준비 중 오류가 발생해 결과를 확정할 수 없습니다.',
  },
  UNROUTED_ARTIFACT_KIND: {
    title: '검증 경로 없는 파일',
    detail: '현재 통합 파이프라인에서 직접 검증하는 파일 종류가 아니어서 수동 확인이 필요합니다.',
  },
  ARTIFACT_RESULT_MISSING: {
    title: '검증 결과 누락',
    detail: '제출된 산출물에 대한 검증 결과가 생성되지 않아 수동 확인이 필요합니다.',
  },
  SANDBOX_NOT_CONFIGURED: {
    title: '샌드박스 runner 미연결',
    detail: 'B-2 대상은 있었지만 현재 실행 환경에 실제 gVisor/runsc runner가 연결되지 않았습니다.',
  },
  SANDBOX_CHECK_NOT_ATTACHED: {
    title: '샌드박스 근거 미첨부',
    detail: 'B-2 대상이지만 응답에 sandbox_check 근거가 붙지 않아 검토가 필요합니다.',
  },
  SANDBOX_POLICY_GATE_REQUIRED: {
    title: '샌드박스 후 정책 검토 필요',
    detail: '샌드박스에서 이상이 없어 보여도 B-2 코드는 자동 승인하지 않고 정책 검토로 남깁니다.',
  },
  SANDBOX_SECURITY_EVENT: {
    title: '샌드박스 보안 이벤트',
    detail: '네트워크, execve, 쓰기 시도 같은 보안 이벤트가 관찰되어 차단 또는 검토가 필요합니다.',
  },
};

export function koreanStatusLabel(value: unknown): string {
  const text = String(value ?? '').toUpperCase();
  return statusLabels[text] ?? String(value ?? '');
}

export function koreanReviewDecisionLabel(value: string): string {
  return reviewDecisionLabels[value] ?? value;
}

export function koreanEvidenceKindLabel(value: string): string {
  return evidenceKindLabels[value] ?? value;
}

export function koreanPresentMissing(exists: boolean): string {
  return exists ? '있음' : '누락';
}

export function koreanRequired(required: boolean): string {
  return required ? '필요' : '불필요';
}

export function koreanCacheLabel(cacheHit: boolean): string {
  return cacheHit ? '적중' : '미적중';
}

export function koreanFileKindLabel(value: unknown): string {
  const text = String(value ?? '');
  return fileKindLabels[text] ?? text;
}

export function koreanRouteKindLabel(value: unknown): string {
  const text = String(value ?? '');
  return routeKindLabels[text] ?? text;
}

export function koreanReviewActionLabel(value: unknown): string {
  const text = String(value ?? '');
  return reviewActionLabels[text] ?? text;
}

export function koreanReleaseActionLabel(value: unknown): string {
  const text = String(value ?? '');
  return releaseActionLabels[text] ?? text;
}

export function koreanReasonCodeTitle(value: unknown): string {
  const text = String(value ?? '');
  return reasonCodeLabels[text]?.title ?? text;
}

export function koreanReasonCodeDetail(value: unknown): string {
  const text = String(value ?? '');
  return reasonCodeLabels[text]?.detail ?? '이 사유 코드는 세부 검증기에서 전달한 기술 근거입니다.';
}

export function koreanFallback(value: string | null | undefined, fallback = '없음'): string {
  return value && value.trim() ? value : fallback;
}

export function koreanBackendMessage(value: string): string {
  if (!value) return value;

  const quotedApi = value.match(/^'([^']+)'/)?.[1] ?? '해당 API';
  if (value.includes('李⑤떒') || value.includes('API濡')) {
    return `'${quotedApi}'는 영구 차단 목록에 등록된 API라 자동 거부되었습니다. 다른 접근 방식을 사용하세요.`;
  }
  if (value.includes('蹂닿퀬') || value.includes('遺꾨쪟')) {
    return '보고 접수 완료. 자동 분류와 공식 문서 등록 여부를 기준으로 보안 담당자 검토 대기열에 반영했습니다.';
  }

  if (value === 'not applied') return '적용되지 않았습니다.';
  if (value === 'reviewer_id and review_note are required') {
    return '검토자와 검토 메모가 필요합니다.';
  }
  if (value === 'review decision already applied') {
    return '검토 결정이 이미 적용되었습니다.';
  }
  if (value === 'review_id already exists for a different review payload') {
    return '같은 review_id가 다른 검토 내용으로 이미 존재합니다.';
  }
  if (value === 'pending API not found') {
    return '검토 대기 API를 찾을 수 없습니다.';
  }

  const applied = value.match(/^review decision applied: (.+)$/);
  if (applied) {
    return `검토 결정 적용됨: ${koreanReviewDecisionLabel(applied[1])}`;
  }

  const unsupported = value.match(/^unsupported review decision: (.+)$/);
  if (unsupported) {
    return `지원하지 않는 검토 결정: ${unsupported[1]}`;
  }

  const already = value.match(/^pending API is already (.+)$/);
  if (already) {
    return `검토 대기 API가 이미 ${koreanStatusLabel(already[1])} 상태입니다.`;
  }

  return value;
}
