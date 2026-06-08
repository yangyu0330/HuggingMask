import { FormEvent, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, RefreshCw, Search, ShieldAlert } from 'lucide-react';

import {
  checkWhitelist,
  getStats,
  listApproved,
  listAudit,
  listFeedback,
  listPending,
  reviewPending,
  submitFeedback,
  verifyAudit,
} from '../../api/ops';
import type {
  FeedbackReportRequest,
  PendingApiRecord,
  PendingClassification,
  ReviewDecision,
  ReviewDecisionResult,
  ReviewStatus,
  WhitelistCheckResult,
} from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { MetricTile } from '../../components/MetricTile';
import { StatusPill } from '../../components/StatusPill';
import {
  koreanBackendMessage,
  koreanFallback,
  koreanRequired,
  koreanReviewDecisionLabel,
  koreanStatusLabel,
} from '../../lib/koreanLabels';

const defaultApiInput = [
  'torch.nn.Linear',
  'torch.load',
  'torch.nn.NewDashboardLayer',
  'torch.optim.NewScheduler',
  'my_custom_lib.UnknownCall',
].join('\n');

const reviewStatuses: Array<ReviewStatus | ''> = ['', 'PENDING', 'APPROVED', 'REJECTED', 'DEFERRED'];
const classifications: Array<PendingClassification | ''> = ['', 'AUTO_APPROVE', 'CONDITIONAL', 'MANUAL', 'BLOCKED'];
const reviewDecisions: ReviewDecision[] = ['approve', 'reject', 'defer', 'conditional'];
const auditActionLabels: Record<string, string> = {
  seed_loaded: '시드 로드',
  pending_registered: '대기 항목 등록',
  pending_upserted: '대기 항목 갱신',
  review_approve: '검토 승인',
  review_reject: '검토 거부',
  review_defer: '검토 보류',
  feedback_received: '피드백 접수',
};

function toneForStatus(value: unknown): 'ok' | 'warn' | 'bad' | 'info' {
  const text = String(value ?? '').toUpperCase();
  if (['ALLOWED', 'APPROVED', 'APPROVE', 'PASS'].includes(text)) return 'ok';
  if (['BLOCKED', 'REJECTED', 'DENY', 'ERROR'].includes(text)) return 'bad';
  if (['PENDING', 'UNKNOWN', 'UNDER_REVIEW', 'DEFERRED', 'CONDITIONAL', 'MANUAL'].includes(text)) return 'warn';
  return 'info';
}

function toneForClassification(value: PendingClassification): 'ok' | 'warn' | 'bad' | 'info' {
  if (value === 'AUTO_APPROVE') return 'info';
  if (value === 'BLOCKED') return 'bad';
  return 'warn';
}

function splitApis(input: string) {
  return input
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value: string) {
  if (!value) return '없음';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('ko-KR');
}

function errorMessage(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return koreanBackendMessage(message);
}

function auditActionLabel(value: string) {
  return auditActionLabels[value] ?? value;
}

function ReviewModal({
  error,
  result,
  target,
  onClose,
  onSubmit,
  pending,
}: {
  error: unknown;
  result: ReviewDecisionResult | null;
  target: PendingApiRecord;
  onClose: () => void;
  onSubmit: (payload: {
    decision: ReviewDecision;
    reviewer_id: string;
    review_note: string;
    condition: string;
  }) => void;
  pending: boolean;
}) {
  const [decision, setDecision] = useState<ReviewDecision>('approve');
  const [reviewerId, setReviewerId] = useState('security_admin');
  const [reviewNote, setReviewNote] = useState('대시보드 검토 결정');
  const [condition, setCondition] = useState('');

  return (
    <div className="modal-backdrop" role="presentation">
      <form
        className="review-modal"
        aria-labelledby="review-modal-title"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({ decision, reviewer_id: reviewerId, review_note: reviewNote, condition });
        }}
      >
        <div className="section-title-row">
          <div>
            <h2 id="review-modal-title">검토 결정</h2>
            <p className="quiet-copy">{target.api_path}</p>
          </div>
          <StatusPill tone={toneForClassification(target.auto_classification)}>
            {koreanStatusLabel(target.auto_classification)}
          </StatusPill>
        </div>

        <div className="segmented-row" role="group" aria-label="검토 결정">
          {reviewDecisions.map((item) => (
            <button
              key={item}
              type="button"
              className={decision === item ? 'active' : undefined}
              onClick={() => setDecision(item)}
            >
              {koreanReviewDecisionLabel(item)}
            </button>
          ))}
        </div>

        <label className="field-stack">
          <span>검토자</span>
          <input value={reviewerId} onChange={(event) => setReviewerId(event.currentTarget.value)} />
        </label>
        <label className="field-stack">
          <span>검토 메모</span>
          <textarea value={reviewNote} onChange={(event) => setReviewNote(event.currentTarget.value)} />
        </label>
        {decision === 'conditional' ? (
          <label className="field-stack">
            <span>조건</span>
            <input value={condition} onChange={(event) => setCondition(event.currentTarget.value)} />
          </label>
        ) : null}

        {result ? (
          <div className="inline-result">
            <StatusPill tone={result.applied ? 'ok' : 'bad'}>
              {result.applied ? '적용됨' : '미적용'}
            </StatusPill>
            <span>{koreanBackendMessage(result.message)}</span>
          </div>
        ) : null}
        {error ? <ErrorPanel title="검토 결정 실패" message={errorMessage(error)} /> : null}

        <div className="button-row">
          <button type="button" className="primary-link secondary-action" onClick={onClose}>
            취소
          </button>
          <button type="submit" className="primary-link" disabled={pending || !reviewerId.trim() || !reviewNote.trim()}>
            {pending ? <RefreshCw aria-hidden="true" size={16} /> : <CheckCircle2 aria-hidden="true" size={16} />}
            <span>{pending ? '적용 중' : '결정 적용'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}

export function OperationsPage() {
  const queryClient = useQueryClient();
  const [apiInput, setApiInput] = useState(defaultApiInput);
  const [modelId, setModelId] = useState('dashboard/test');
  const [checkResults, setCheckResults] = useState<WhitelistCheckResult[]>([]);
  const [pendingStatus, setPendingStatus] = useState<ReviewStatus | ''>('');
  const [pendingClass, setPendingClass] = useState<PendingClassification | ''>('');
  const [approvedSearch, setApprovedSearch] = useState('');
  const [approvedSource, setApprovedSource] = useState('');
  const [auditSearch, setAuditSearch] = useState('');
  const [auditAction, setAuditAction] = useState('');
  const [reviewTarget, setReviewTarget] = useState<PendingApiRecord | null>(null);
  const [lastReviewResult, setLastReviewResult] = useState<ReviewDecisionResult | null>(null);
  const [feedbackForm, setFeedbackForm] = useState<FeedbackReportRequest>({
    blocked_api: 'torch.load',
    model_id: 'demo/model',
    purpose: '검증 중 모델 로더에서 필요합니다',
    reporter_id: 'demo_operator',
  });

  const statsQuery = useQuery({ queryKey: ['ops', 'stats'], queryFn: getStats });
  const pendingQuery = useQuery({
    queryKey: ['ops', 'pending', pendingStatus, pendingClass],
    queryFn: () => listPending({ review_status: pendingStatus, classification: pendingClass }),
  });
  const approvedQuery = useQuery({
    queryKey: ['ops', 'approved', approvedSearch, approvedSource],
    queryFn: () => listApproved({ search: approvedSearch, source: approvedSource, include_blocked: true }),
  });
  const feedbackQuery = useQuery({ queryKey: ['ops', 'feedback'], queryFn: () => listFeedback() });
  const auditQuery = useQuery({
    queryKey: ['ops', 'audit', auditSearch, auditAction],
    queryFn: () => listAudit({ api_path: auditSearch, action: auditAction }),
  });
  const auditVerifyQuery = useQuery({ queryKey: ['ops', 'auditVerify'], queryFn: verifyAudit });

  const parsedApis = useMemo(() => splitApis(apiInput), [apiInput]);

  const refreshOps = () => {
    void queryClient.invalidateQueries({ queryKey: ['ops'] });
  };

  const checkMutation = useMutation({
    mutationFn: () => checkWhitelist(parsedApis, modelId),
    onSuccess: (result) => {
      setCheckResults(result);
      refreshOps();
    },
  });

  const reviewMutation = useMutation({
    mutationFn: (payload: {
      target: PendingApiRecord;
      decision: ReviewDecision;
      reviewer_id: string;
      review_note: string;
      condition: string;
    }) =>
      reviewPending({
        api_path: payload.target.api_path,
        decision: payload.decision,
        reviewer_id: payload.reviewer_id,
        review_note: payload.review_note,
        condition: payload.decision === 'conditional' ? payload.condition || null : null,
        source_evidence: [
          `ui_auto_classification=${payload.target.auto_classification}`,
          `ui_review_status=${payload.target.review_status}`,
        ],
      }),
    onSuccess: (result) => {
      setLastReviewResult(result);
      refreshOps();
      if (result.applied) {
        setReviewTarget(null);
      }
    },
  });

  const feedbackMutation = useMutation({
    mutationFn: () => submitFeedback(feedbackForm),
    onSuccess: () => refreshOps(),
  });

  const stats = statsQuery.data;
  const checkCounts = checkResults.reduce<Record<string, number>>((counts, item) => {
    counts[item.status] = (counts[item.status] ?? 0) + 1;
    return counts;
  }, {});

  return (
    <section className="console-panel operations-panel" aria-labelledby="operations-title">
      <div className="section-kicker">운영</div>
      <div className="overview-heading">
        <div>
          <h1 id="operations-title">화이트리스트 운영</h1>
          <p>화이트리스트 확인, 보안 담당자 검토, 정책 조회, 피드백 제출, 감사 체인 검증을 수행합니다.</p>
        </div>
        <StatusPill tone={auditVerifyQuery.data?.valid ? 'ok' : 'warn'}>
          감사 체인 {auditVerifyQuery.data?.valid ? '정상' : '확인 대기'}
        </StatusPill>
      </div>

      <div className="metric-grid metric-grid-four">
        <MetricTile label="승인 API" value={stats?.approved_active ?? '...'} detail={`버전 ${stats?.whitelist_version ?? '...'}`} />
        <MetricTile label="검토 대기" value={stats?.pending_review ?? '...'} detail="보안 담당자 대기열" />
        <MetricTile label="차단 API" value={stats?.blocked ?? '...'} detail="수동/영구 거부 경로" />
        <MetricTile label="피드백 제보" value={stats?.feedback_total ?? '...'} detail="운영자 제출 건수" />
      </div>

      <div className="operations-grid">
        <section className="section-block ops-wide" aria-labelledby="check-title">
          <div className="section-title-row">
            <div>
              <h2 id="check-title">화이트리스트 확인</h2>
              <p className="quiet-copy">POST /internal/v1/whitelist/check</p>
            </div>
            <StatusPill tone="info">{parsedApis.length}개 API</StatusPill>
          </div>
          <form
            className="ops-form"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              checkMutation.mutate();
            }}
          >
            <label className="field-stack">
              <span>API 경로</span>
              <textarea value={apiInput} onChange={(event) => setApiInput(event.currentTarget.value)} />
            </label>
            <div className="inline-form">
              <label className="field-stack">
                <span>모델 ID</span>
                <input value={modelId} onChange={(event) => setModelId(event.currentTarget.value)} />
              </label>
              <button type="submit" className="primary-link" disabled={!parsedApis.length || checkMutation.isPending}>
                {checkMutation.isPending ? <RefreshCw aria-hidden="true" size={16} /> : <Search aria-hidden="true" size={16} />}
                <span>{checkMutation.isPending ? '확인 중' : '확인 실행'}</span>
              </button>
            </div>
          </form>
          {checkMutation.error ? <ErrorPanel title="화이트리스트 확인 실패" message={errorMessage(checkMutation.error)} /> : null}
          {checkResults.length ? (
            <>
              <div className="result-summary" aria-label="화이트리스트 상태 요약">
                {(['ALLOWED', 'BLOCKED', 'PENDING', 'UNKNOWN'] as const).map((status) => (
                  <div key={status}>
                    <span>{koreanStatusLabel(status)}</span>
                    <strong>{checkCounts[status] ?? 0}</strong>
                  </div>
                ))}
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>API 경로</th>
                      <th>상태</th>
                      <th>매칭 규칙</th>
                      <th>검토</th>
                      <th>사유</th>
                    </tr>
                  </thead>
                  <tbody>
                    {checkResults.map((item) => (
                      <tr key={item.api_path}>
                        <td>{item.api_path}</td>
                        <td><StatusPill tone={toneForStatus(item.status)}>{koreanStatusLabel(item.status)}</StatusPill></td>
                        <td>{item.matched_rule ?? '없음'}</td>
                        <td>{koreanRequired(item.review_required)}</td>
                        <td>{item.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
        </section>

        <section className="section-block ops-wide" aria-labelledby="pending-title">
          <div className="section-title-row">
            <div>
              <h2 id="pending-title">검토 대기열</h2>
              <p className="quiet-copy">AUTO_APPROVE는 추천일 뿐이며 최종 검토 상태와 분리됩니다.</p>
            </div>
            <div className="filter-row">
              <select value={pendingStatus} onChange={(event) => setPendingStatus(event.currentTarget.value as ReviewStatus | '')} aria-label="검토 상태 필터">
                {reviewStatuses.map((status) => <option key={status || 'all'} value={status}>{status ? koreanStatusLabel(status) : '전체 상태'}</option>)}
              </select>
              <select value={pendingClass} onChange={(event) => setPendingClass(event.currentTarget.value as PendingClassification | '')} aria-label="추천 분류 필터">
                {classifications.map((classification) => <option key={classification || 'all'} value={classification}>{classification ? koreanStatusLabel(classification) : '전체 추천'}</option>)}
              </select>
            </div>
          </div>
          {pendingQuery.error ? <ErrorPanel title="검토 대기열을 불러올 수 없습니다" message={errorMessage(pendingQuery.error)} /> : null}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>API 경로</th>
                  <th>추천 분류</th>
                  <th>검토 상태</th>
                  <th>발견 횟수</th>
                  <th>위험 키워드</th>
                  <th>조치</th>
                </tr>
              </thead>
              <tbody>
                {(pendingQuery.data?.items ?? []).map((item) => (
                  <tr key={item.api_path}>
                    <td>
                      <strong>{item.api_path}</strong>
                      <small>{item.matched_namespace_rule ?? 'namespace 규칙 없음'}</small>
                    </td>
                    <td><StatusPill tone={toneForClassification(item.auto_classification)}>{koreanStatusLabel(item.auto_classification)}</StatusPill></td>
                    <td><StatusPill tone={toneForStatus(item.review_status)}>{koreanStatusLabel(item.review_status)}</StatusPill></td>
                    <td>{item.seen_count}</td>
                    <td>{item.risk_keywords.join(', ') || '없음'}</td>
                    <td>
                      <button
                        type="button"
                        className="primary-link"
                        onClick={() => {
                          reviewMutation.reset();
                          setLastReviewResult(null);
                          setReviewTarget(item);
                        }}
                        disabled={item.review_status !== 'PENDING'}
                      >
                        검토
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="section-block" aria-labelledby="policies-title">
          <div className="section-title-row">
            <div>
              <h2 id="policies-title">승인/차단 정책</h2>
              <p className="quiet-copy">GET /internal/v1/approved?include_blocked=true</p>
            </div>
          </div>
          <div className="filter-row">
            <input value={approvedSearch} onChange={(event) => setApprovedSearch(event.currentTarget.value)} placeholder="API 검색" aria-label="승인 정책 검색" />
            <select value={approvedSource} onChange={(event) => setApprovedSource(event.currentTarget.value)} aria-label="승인 정책 출처 필터">
              <option value="">전체 출처</option>
              <option value="INITIAL">{koreanStatusLabel('INITIAL')}</option>
              <option value="AUTO_CRAWL">{koreanStatusLabel('AUTO_CRAWL')}</option>
              <option value="MANUAL_REVIEW">{koreanStatusLabel('MANUAL_REVIEW')}</option>
            </select>
          </div>
          {approvedQuery.error ? <ErrorPanel title="정책 목록을 불러올 수 없습니다" message={errorMessage(approvedQuery.error)} /> : null}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>API 경로</th>
                  <th>상태</th>
                  <th>출처</th>
                  <th>검토자</th>
                  <th>메모</th>
                </tr>
              </thead>
              <tbody>
                {(approvedQuery.data?.items ?? []).map((item) => (
                  <tr key={item.api_path}>
                    <td>{item.api_path}</td>
                    <td><StatusPill tone={item.is_blocked ? 'bad' : 'ok'}>{koreanStatusLabel(item.is_blocked ? 'BLOCKED' : 'ALLOWED')}</StatusPill></td>
                    <td>{koreanStatusLabel(item.source)}</td>
                    <td>{item.reviewer_id || 'system'}</td>
                    <td>{koreanFallback(item.review_note || item.matched_rule, '시드 규칙')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="section-block" aria-labelledby="feedback-title">
          <div className="section-title-row">
            <div>
              <h2 id="feedback-title">피드백</h2>
              <p className="quiet-copy">POST /internal/v1/feedback</p>
            </div>
          </div>
          <form
            className="ops-form"
            onSubmit={(event) => {
              event.preventDefault();
              feedbackMutation.mutate();
            }}
          >
            <label className="field-stack">
              <span>차단 API</span>
              <input value={feedbackForm.blocked_api} onChange={(event) => setFeedbackForm({ ...feedbackForm, blocked_api: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>모델 ID</span>
              <input value={feedbackForm.model_id} onChange={(event) => setFeedbackForm({ ...feedbackForm, model_id: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>제보자</span>
              <input value={feedbackForm.reporter_id} onChange={(event) => setFeedbackForm({ ...feedbackForm, reporter_id: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>사용 목적</span>
              <textarea value={feedbackForm.purpose} onChange={(event) => setFeedbackForm({ ...feedbackForm, purpose: event.currentTarget.value })} />
            </label>
            <button type="submit" className="primary-link" disabled={feedbackMutation.isPending}>
              <span>{feedbackMutation.isPending ? '제출 중' : '피드백 제출'}</span>
            </button>
          </form>
          {feedbackMutation.error ? <ErrorPanel title="피드백 제출 실패" message={errorMessage(feedbackMutation.error)} /> : null}
          {feedbackMutation.data ? (
            <div className="inline-result">
              <StatusPill tone={feedbackMutation.data.auto_rejected ? 'bad' : toneForClassification(feedbackMutation.data.auto_classification)}>
                {koreanStatusLabel(feedbackMutation.data.auto_classification)}
              </StatusPill>
              <span>{koreanBackendMessage(feedbackMutation.data.message)}</span>
            </div>
          ) : null}
          <div className="compact-list">
            {(feedbackQuery.data?.items ?? []).slice(0, 6).map((item) => (
              <div key={item.report_id}>
                <strong>{item.blocked_api}</strong>
                <span>{item.model_id}</span>
                <StatusPill tone={toneForStatus(item.review_status)}>{koreanStatusLabel(item.review_status)}</StatusPill>
              </div>
            ))}
          </div>
        </section>

        <section className="section-block" aria-labelledby="audit-title">
          <div className="section-title-row">
            <div>
              <h2 id="audit-title">감사 로그</h2>
              <p className="quiet-copy">GET /internal/v1/audit</p>
            </div>
            <button type="button" className="primary-link" onClick={() => auditVerifyQuery.refetch()}>
              <ShieldAlert aria-hidden="true" size={16} />
              <span>체인 검증</span>
            </button>
          </div>
          <div className="verify-panel">
            <StatusPill tone={auditVerifyQuery.data?.valid ? 'ok' : 'bad'}>
              {auditVerifyQuery.data?.valid ? '체인 정상' : '체인 검토 필요'}
            </StatusPill>
            <span>{auditVerifyQuery.data?.total_entries ?? 0}건</span>
            <span>위반 {auditVerifyQuery.data?.violation_count ?? 0}건</span>
          </div>
          <div className="filter-row">
            <input value={auditSearch} onChange={(event) => setAuditSearch(event.currentTarget.value)} placeholder="API 경로 필터" aria-label="감사 API 필터" />
            <select value={auditAction} onChange={(event) => setAuditAction(event.currentTarget.value)} aria-label="감사 조치 필터">
              <option value="">전체 조치</option>
              {Object.entries(auditActionLabels).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>
          {auditQuery.error ? <ErrorPanel title="감사 로그를 불러올 수 없습니다" message={errorMessage(auditQuery.error)} /> : null}
          {auditVerifyQuery.data?.violations.length ? (
            <ul className="notice-list">
              {auditVerifyQuery.data.violations.map((violation) => <li key={violation}>{violation}</li>)}
            </ul>
          ) : null}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>시각</th>
                  <th>조치</th>
                  <th>API 경로</th>
                  <th>행위자</th>
                  <th>해시</th>
                </tr>
              </thead>
              <tbody>
                {(auditQuery.data?.items ?? []).map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{formatDate(item.timestamp)}</td>
                    <td>{auditActionLabel(item.action)}</td>
                    <td>{item.api_path}</td>
                    <td>{item.actor}</td>
                    <td>{item.entry_hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {lastReviewResult ? (
        <div className="floating-result" role="status">
          <StatusPill tone={lastReviewResult.applied ? 'ok' : 'bad'}>{lastReviewResult.applied ? '적용됨' : '실패'}</StatusPill>
          <span>{koreanBackendMessage(lastReviewResult.message)}</span>
        </div>
      ) : null}
      {reviewTarget ? (
        <ReviewModal
          error={reviewMutation.error}
          target={reviewTarget}
          result={lastReviewResult}
          pending={reviewMutation.isPending}
          onClose={() => {
            reviewMutation.reset();
            setReviewTarget(null);
          }}
          onSubmit={(payload) => reviewMutation.mutate({ target: reviewTarget, ...payload })}
        />
      ) : null}
    </section>
  );
}
