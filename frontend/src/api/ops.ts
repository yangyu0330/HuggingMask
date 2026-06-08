import { apiGet, apiPost } from './client';
import type {
  ApprovedListResponse,
  AuditListResponse,
  AuditVerifyResponse,
  DemoReadiness,
  FeedbackListResponse,
  FeedbackReportRequest,
  FeedbackReportResponse,
  HealthResponse,
  PendingClassification,
  PendingListResponse,
  ReviewDecisionRequest,
  ReviewDecisionResult,
  ReviewStatus,
  WhitelistCheckRequest,
  WhitelistCheckResult,
  WhitelistStats,
} from './types';

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch('/health', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`/health failed with ${response.status}`);
  }
  return response.json() as Promise<HealthResponse>;
}

export function getStats(): Promise<WhitelistStats> {
  return apiGet<WhitelistStats>('/stats');
}

export function getDemoReadiness(): Promise<DemoReadiness> {
  return apiGet<DemoReadiness>('/demo/readiness');
}

function appendParams(path: string, params: Record<string, string | number | boolean | undefined>) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') {
      search.set(key, String(value));
    }
  });
  const suffix = search.toString();
  return suffix ? `${path}?${suffix}` : path;
}

function randomId(prefix: string) {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function buildWhitelistCheckRequest(apis: string[], modelId: string): WhitelistCheckRequest {
  const requestedAt = new Date().toISOString();
  return {
    schema_version: '1.0',
    request_id: randomId('ops-req'),
    job_id: randomId('ops-job'),
    model: {
      repo_id: modelId,
      revision: 'main',
      source_host: 'huggingface.co',
      source_url: `https://huggingface.co/${modelId}`,
      requested_by: 'demo_operations',
      requested_at: requestedAt,
      endpoint_mode: 'HF_ENDPOINT_PROXY',
    },
    apis,
  };
}

export function checkWhitelist(apis: string[], modelId: string): Promise<WhitelistCheckResult[]> {
  return apiPost<WhitelistCheckResult[], WhitelistCheckRequest>(
    '/whitelist/check',
    buildWhitelistCheckRequest(apis, modelId),
  );
}

export function listPending(params: {
  review_status?: ReviewStatus | '';
  classification?: PendingClassification | '';
  limit?: number;
  offset?: number;
} = {}): Promise<PendingListResponse> {
  return apiGet<PendingListResponse>(appendParams('/pending', {
    review_status: params.review_status,
    classification: params.classification,
    limit: params.limit ?? 50,
    offset: params.offset ?? 0,
  }));
}

export function reviewPending(request: ReviewDecisionRequest): Promise<ReviewDecisionResult> {
  return apiPost<ReviewDecisionResult, ReviewDecisionRequest>('/review', request);
}

export function listApproved(params: {
  search?: string;
  namespace?: string;
  source?: string;
  include_blocked?: boolean;
  limit?: number;
  offset?: number;
} = {}): Promise<ApprovedListResponse> {
  return apiGet<ApprovedListResponse>(appendParams('/approved', {
    search: params.search,
    namespace: params.namespace,
    source: params.source,
    include_blocked: params.include_blocked ?? true,
    limit: params.limit ?? 50,
    offset: params.offset ?? 0,
  }));
}

export function submitFeedback(request: FeedbackReportRequest): Promise<FeedbackReportResponse> {
  return apiPost<FeedbackReportResponse, FeedbackReportRequest>('/feedback', request);
}

export function listFeedback(params: {
  reporter_id?: string;
  status?: ReviewStatus | '';
  limit?: number;
  offset?: number;
} = {}): Promise<FeedbackListResponse> {
  return apiGet<FeedbackListResponse>(appendParams('/feedback', {
    reporter_id: params.reporter_id,
    status: params.status,
    limit: params.limit ?? 50,
    offset: params.offset ?? 0,
  }));
}

export function listAudit(params: {
  api_path?: string;
  action?: string;
  actor?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<AuditListResponse> {
  return apiGet<AuditListResponse>(appendParams('/audit', {
    api_path: params.api_path,
    action: params.action,
    actor: params.actor,
    limit: params.limit ?? 50,
    offset: params.offset ?? 0,
  }));
}

export function verifyAudit(): Promise<AuditVerifyResponse> {
  return apiGet<AuditVerifyResponse>('/audit/verify');
}
