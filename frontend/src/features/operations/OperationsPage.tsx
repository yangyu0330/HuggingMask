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
  if (!value) return 'n/a';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
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
  const [reviewNote, setReviewNote] = useState('Phase 5 dashboard review decision');
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
            <h2 id="review-modal-title">Review Decision</h2>
            <p className="quiet-copy">{target.api_path}</p>
          </div>
          <StatusPill tone={toneForClassification(target.auto_classification)}>
            {target.auto_classification}
          </StatusPill>
        </div>

        <div className="segmented-row" role="group" aria-label="Review decision">
          {reviewDecisions.map((item) => (
            <button
              key={item}
              type="button"
              className={decision === item ? 'active' : undefined}
              onClick={() => setDecision(item)}
            >
              {item}
            </button>
          ))}
        </div>

        <label className="field-stack">
          <span>Reviewer</span>
          <input value={reviewerId} onChange={(event) => setReviewerId(event.currentTarget.value)} />
        </label>
        <label className="field-stack">
          <span>Review note</span>
          <textarea value={reviewNote} onChange={(event) => setReviewNote(event.currentTarget.value)} />
        </label>
        {decision === 'conditional' ? (
          <label className="field-stack">
            <span>Condition</span>
            <input value={condition} onChange={(event) => setCondition(event.currentTarget.value)} />
          </label>
        ) : null}

        {result ? (
          <div className="inline-result">
            <StatusPill tone={result.applied ? 'ok' : 'bad'}>
              {result.applied ? 'Applied' : 'Not Applied'}
            </StatusPill>
            <span>{result.message}</span>
          </div>
        ) : null}
        {error ? <ErrorPanel title="Review decision failed" message={errorMessage(error)} /> : null}

        <div className="button-row">
          <button type="button" className="primary-link secondary-action" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary-link" disabled={pending || !reviewerId.trim() || !reviewNote.trim()}>
            {pending ? <RefreshCw aria-hidden="true" size={16} /> : <CheckCircle2 aria-hidden="true" size={16} />}
            <span>{pending ? 'Applying' : 'Apply decision'}</span>
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
    purpose: 'Needed by a model loader during validation',
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
      <div className="section-kicker">Operations</div>
      <div className="overview-heading">
        <div>
          <h1 id="operations-title">Whitelist Operations</h1>
          <p>Run whitelist checks, apply security-owner reviews, inspect policies, submit feedback, and verify audit chain integrity.</p>
        </div>
        <StatusPill tone={auditVerifyQuery.data?.valid ? 'ok' : 'warn'}>
          Audit {auditVerifyQuery.data?.valid ? 'Valid' : 'Pending Check'}
        </StatusPill>
      </div>

      <div className="metric-grid metric-grid-four">
        <MetricTile label="Approved APIs" value={stats?.approved_active ?? '...'} detail={`Version ${stats?.whitelist_version ?? '...'}`} />
        <MetricTile label="Pending Review" value={stats?.pending_review ?? '...'} detail="Security owner queue" />
        <MetricTile label="Blocked APIs" value={stats?.blocked ?? '...'} detail="Manual and permanent deny paths" />
        <MetricTile label="Feedback Reports" value={stats?.feedback_total ?? '...'} detail="Operator submissions" />
      </div>

      <div className="operations-grid">
        <section className="section-block ops-wide" aria-labelledby="check-title">
          <div className="section-title-row">
            <div>
              <h2 id="check-title">Whitelist Check</h2>
              <p className="quiet-copy">POST /internal/v1/whitelist/check</p>
            </div>
            <StatusPill tone="info">{parsedApis.length} APIs</StatusPill>
          </div>
          <form
            className="ops-form"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              checkMutation.mutate();
            }}
          >
            <label className="field-stack">
              <span>API paths</span>
              <textarea value={apiInput} onChange={(event) => setApiInput(event.currentTarget.value)} />
            </label>
            <div className="inline-form">
              <label className="field-stack">
                <span>Model ID</span>
                <input value={modelId} onChange={(event) => setModelId(event.currentTarget.value)} />
              </label>
              <button type="submit" className="primary-link" disabled={!parsedApis.length || checkMutation.isPending}>
                {checkMutation.isPending ? <RefreshCw aria-hidden="true" size={16} /> : <Search aria-hidden="true" size={16} />}
                <span>{checkMutation.isPending ? 'Checking' : 'Run check'}</span>
              </button>
            </div>
          </form>
          {checkMutation.error ? <ErrorPanel title="Whitelist check failed" message={errorMessage(checkMutation.error)} /> : null}
          {checkResults.length ? (
            <>
              <div className="result-summary" aria-label="Whitelist status summary">
                {(['ALLOWED', 'BLOCKED', 'PENDING', 'UNKNOWN'] as const).map((status) => (
                  <div key={status}>
                    <span>{status}</span>
                    <strong>{checkCounts[status] ?? 0}</strong>
                  </div>
                ))}
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>API Path</th>
                      <th>Status</th>
                      <th>Matched Rule</th>
                      <th>Review</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {checkResults.map((item) => (
                      <tr key={item.api_path}>
                        <td>{item.api_path}</td>
                        <td><StatusPill tone={toneForStatus(item.status)}>{item.status}</StatusPill></td>
                        <td>{item.matched_rule ?? 'None'}</td>
                        <td>{item.review_required ? 'Required' : 'Not required'}</td>
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
              <h2 id="pending-title">Pending Review Queue</h2>
              <p className="quiet-copy">AUTO_APPROVE is a recommendation; final status remains separate.</p>
            </div>
            <div className="filter-row">
              <select value={pendingStatus} onChange={(event) => setPendingStatus(event.currentTarget.value as ReviewStatus | '')} aria-label="Review status filter">
                {reviewStatuses.map((status) => <option key={status || 'all'} value={status}>{status || 'All statuses'}</option>)}
              </select>
              <select value={pendingClass} onChange={(event) => setPendingClass(event.currentTarget.value as PendingClassification | '')} aria-label="Classification filter">
                {classifications.map((classification) => <option key={classification || 'all'} value={classification}>{classification || 'All recommendations'}</option>)}
              </select>
            </div>
          </div>
          {pendingQuery.error ? <ErrorPanel title="Pending queue unavailable" message={errorMessage(pendingQuery.error)} /> : null}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>API Path</th>
                  <th>Recommendation</th>
                  <th>Review Status</th>
                  <th>Seen</th>
                  <th>Risk</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {(pendingQuery.data?.items ?? []).map((item) => (
                  <tr key={item.api_path}>
                    <td>
                      <strong>{item.api_path}</strong>
                      <small>{item.matched_namespace_rule ?? 'No namespace rule'}</small>
                    </td>
                    <td><StatusPill tone={toneForClassification(item.auto_classification)}>{item.auto_classification}</StatusPill></td>
                    <td><StatusPill tone={toneForStatus(item.review_status)}>{item.review_status}</StatusPill></td>
                    <td>{item.seen_count}</td>
                    <td>{item.risk_keywords.join(', ') || 'None'}</td>
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
                        Review
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
              <h2 id="policies-title">Approved and Blocked Policies</h2>
              <p className="quiet-copy">GET /internal/v1/approved?include_blocked=true</p>
            </div>
          </div>
          <div className="filter-row">
            <input value={approvedSearch} onChange={(event) => setApprovedSearch(event.currentTarget.value)} placeholder="Search API" aria-label="Approved search" />
            <select value={approvedSource} onChange={(event) => setApprovedSource(event.currentTarget.value)} aria-label="Approved source filter">
              <option value="">All sources</option>
              <option value="INITIAL">INITIAL</option>
              <option value="AUTO_CRAWL">AUTO_CRAWL</option>
              <option value="MANUAL_REVIEW">MANUAL_REVIEW</option>
            </select>
          </div>
          {approvedQuery.error ? <ErrorPanel title="Policy list unavailable" message={errorMessage(approvedQuery.error)} /> : null}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>API Path</th>
                  <th>Status</th>
                  <th>Source</th>
                  <th>Reviewer</th>
                  <th>Note</th>
                </tr>
              </thead>
              <tbody>
                {(approvedQuery.data?.items ?? []).map((item) => (
                  <tr key={item.api_path}>
                    <td>{item.api_path}</td>
                    <td><StatusPill tone={item.is_blocked ? 'bad' : 'ok'}>{item.is_blocked ? 'BLOCKED' : 'ALLOWED'}</StatusPill></td>
                    <td>{item.source}</td>
                    <td>{item.reviewer_id || 'system'}</td>
                    <td>{item.review_note || item.matched_rule || 'Seeded rule'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="section-block" aria-labelledby="feedback-title">
          <div className="section-title-row">
            <div>
              <h2 id="feedback-title">Feedback</h2>
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
              <span>Blocked API</span>
              <input value={feedbackForm.blocked_api} onChange={(event) => setFeedbackForm({ ...feedbackForm, blocked_api: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>Model ID</span>
              <input value={feedbackForm.model_id} onChange={(event) => setFeedbackForm({ ...feedbackForm, model_id: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>Reporter</span>
              <input value={feedbackForm.reporter_id} onChange={(event) => setFeedbackForm({ ...feedbackForm, reporter_id: event.currentTarget.value })} />
            </label>
            <label className="field-stack">
              <span>Purpose</span>
              <textarea value={feedbackForm.purpose} onChange={(event) => setFeedbackForm({ ...feedbackForm, purpose: event.currentTarget.value })} />
            </label>
            <button type="submit" className="primary-link" disabled={feedbackMutation.isPending}>
              <span>{feedbackMutation.isPending ? 'Submitting' : 'Submit feedback'}</span>
            </button>
          </form>
          {feedbackMutation.error ? <ErrorPanel title="Feedback failed" message={errorMessage(feedbackMutation.error)} /> : null}
          {feedbackMutation.data ? (
            <div className="inline-result">
              <StatusPill tone={feedbackMutation.data.auto_rejected ? 'bad' : toneForClassification(feedbackMutation.data.auto_classification)}>
                {feedbackMutation.data.auto_classification}
              </StatusPill>
              <span>{feedbackMutation.data.message}</span>
            </div>
          ) : null}
          <div className="compact-list">
            {(feedbackQuery.data?.items ?? []).slice(0, 6).map((item) => (
              <div key={item.report_id}>
                <strong>{item.blocked_api}</strong>
                <span>{item.model_id}</span>
                <StatusPill tone={toneForStatus(item.review_status)}>{item.review_status}</StatusPill>
              </div>
            ))}
          </div>
        </section>

        <section className="section-block" aria-labelledby="audit-title">
          <div className="section-title-row">
            <div>
              <h2 id="audit-title">Audit Log</h2>
              <p className="quiet-copy">GET /internal/v1/audit</p>
            </div>
            <button type="button" className="primary-link" onClick={() => auditVerifyQuery.refetch()}>
              <ShieldAlert aria-hidden="true" size={16} />
              <span>Verify chain</span>
            </button>
          </div>
          <div className="verify-panel">
            <StatusPill tone={auditVerifyQuery.data?.valid ? 'ok' : 'bad'}>
              {auditVerifyQuery.data?.valid ? 'Chain Valid' : 'Chain Needs Review'}
            </StatusPill>
            <span>{auditVerifyQuery.data?.total_entries ?? 0} entries</span>
            <span>{auditVerifyQuery.data?.violation_count ?? 0} violations</span>
          </div>
          <div className="filter-row">
            <input value={auditSearch} onChange={(event) => setAuditSearch(event.currentTarget.value)} placeholder="Filter API path" aria-label="Audit API filter" />
            <select value={auditAction} onChange={(event) => setAuditAction(event.currentTarget.value)} aria-label="Audit action filter">
              <option value="">All actions</option>
              <option value="seed_loaded">seed_loaded</option>
              <option value="pending_registered">pending_registered</option>
              <option value="pending_upserted">pending_upserted</option>
              <option value="review_approve">review_approve</option>
              <option value="review_reject">review_reject</option>
              <option value="review_defer">review_defer</option>
              <option value="feedback_received">feedback_received</option>
            </select>
          </div>
          {auditQuery.error ? <ErrorPanel title="Audit log unavailable" message={errorMessage(auditQuery.error)} /> : null}
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
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>API Path</th>
                  <th>Actor</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {(auditQuery.data?.items ?? []).map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{formatDate(item.timestamp)}</td>
                    <td>{item.action}</td>
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
          <StatusPill tone={lastReviewResult.applied ? 'ok' : 'bad'}>{lastReviewResult.applied ? 'Applied' : 'Failed'}</StatusPill>
          <span>{lastReviewResult.message}</span>
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
