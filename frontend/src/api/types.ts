export type ValidationStatus = 'PASS' | 'BLOCK' | 'PENDING_REVIEW' | 'ERROR' | 'SKIPPED';
export type OverallDecision = 'APPROVE' | 'APPROVE_WITH_TRANSFORM' | 'DENY' | 'REVIEW_REQUIRED' | 'ERROR';
export type WhitelistStatus = 'ALLOWED' | 'BLOCKED' | 'UNKNOWN' | 'PENDING';
export type ReviewDecision = 'approve' | 'conditional' | 'reject' | 'defer';
export type ReviewStatus = 'PENDING' | 'UNDER_REVIEW' | 'APPROVED' | 'REJECTED' | 'DEFERRED';
export type PendingClassification = 'AUTO_APPROVE' | 'CONDITIONAL' | 'MANUAL' | 'BLOCKED';

export interface ReasonEntry {
  code: string;
  message: string;
  severity: string;
  evidence: string[];
  review_required: boolean;
}

export interface ArtifactRef {
  artifact_id: string;
  repo_path: string;
  file_name: string;
  file_kind: string;
  detected_extension: string;
  size_bytes: number;
  sha256: string;
  source_url: string;
  temp_local_path: string;
  media_type?: string | null;
  referenced_by: string[];
  is_generated: boolean;
}

export interface ArtifactValidationResult {
  artifact: ArtifactRef;
  route_kind: string;
  status: ValidationStatus;
  grade: string;
  review_action: string;
  cache_key: string;
  cache_hit: boolean;
  reason_entries: ReasonEntry[];
  started_at: string;
  finished_at: string;
  details: Record<string, unknown>;
  generated_artifact?: ArtifactRef | null;
}

export interface ValidationJobResponse {
  schema_version: string;
  request_id: string;
  job_id: string;
  overall_decision: OverallDecision;
  overall_status: ValidationStatus;
  release_action: string;
  artifact_results: ArtifactValidationResult[];
  approved_artifact_ids: string[];
  blocked_artifact_ids: string[];
  pending_artifact_ids: string[];
  generated_artifacts: ArtifactRef[];
  report_id: string;
  report_path: string;
  reason_entries: ReasonEntry[];
  created_at: string;
  coverage_summary: Record<string, unknown>;
}

export interface DemoScenarioSummary {
  scenario_id: string;
  title: string;
  category: 'safe' | 'transform' | 'blocked' | 'review';
  policy_profile: string;
  expected_overall_decision: OverallDecision;
  expected_overall_status: ValidationStatus;
  expected_release_action: string;
  expected_reason_codes: string[];
  primary_stage: string;
  fixture_path: string;
  stable: boolean;
  notes: string[];
}

export interface DemoSourcePreview {
  repo_path: string;
  exists: boolean;
  size_bytes?: number;
  sha256?: string;
  preview: string;
  truncated: boolean;
}

export interface DemoScenarioDetail extends DemoScenarioSummary {
  required_repo_files: string[];
  files_present_in_repo: string[];
  artifacts_to_generate: Array<Record<string, unknown>>;
  expected: Record<string, unknown>;
  manifest: Record<string, unknown>;
  source_files: DemoSourcePreview[];
  presentation_notes: string[];
  limitations: string[];
}

export interface DemoScenarioListResponse {
  items: DemoScenarioSummary[];
}

export interface DemoRunRequest {
  repeat_cache_check: boolean;
  reset_demo_state: boolean;
  enable_path_b: boolean;
  requested_by: string;
}

export interface DemoRunResponse {
  scenario_id: string;
  run_id: string;
  started_at: string;
  finished_at: string;
  expected: Record<string, unknown>;
  actual: Record<string, unknown>;
  matched_expectation: boolean;
  expectation_checks: Record<string, boolean>;
  expectation_mismatches: string[];
  snapshot_root: string;
  validation_response: ValidationJobResponse;
  cache_check_response: ValidationJobResponse | null;
}

export interface WhitelistCheckResult {
  api_path: string;
  status: WhitelistStatus;
  matched_rule: string | null;
  source: string;
  whitelist_version: string;
  review_required: boolean;
  reason: string;
}

export interface ModelRef {
  repo_id: string;
  revision: string;
  source_host: string;
  source_url: string;
  requested_by: string;
  requested_at: string;
  endpoint_mode: 'HF_ENDPOINT_PROXY' | 'DIRECT';
}

export interface WhitelistCheckRequest {
  schema_version: string;
  request_id: string;
  job_id: string;
  model: ModelRef;
  apis: string[];
}

export interface PendingApiRecord {
  api_path: string;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
  auto_classification: PendingClassification;
  verified_org_count: number;
  verified_org_list: string[];
  in_official_docs: boolean;
  review_status: ReviewStatus;
  model_list: string[];
  risk_keywords: string[];
  matched_namespace_rule?: string | null;
  documentation_url?: string | null;
  sample_callsites: string[];
  created_from_job_id: string;
}

export interface PendingListResponse {
  items: PendingApiRecord[];
  count: number;
}

export interface ReviewDecisionRequest {
  api_path: string;
  decision: ReviewDecision;
  reviewer_id: string;
  review_note: string;
  review_id?: string | null;
  condition?: string | null;
  source_evidence?: string[];
}

export interface ReviewDecisionResult {
  api_path: string;
  decision: ReviewDecision;
  applied: boolean;
  message: string;
  review_id?: string | null;
  final_review_status?: ReviewStatus | null;
  audit_event_id?: number | null;
  audit_event_hash?: string | null;
}

export interface ApprovedApiRecord {
  api_path: string;
  namespace: string;
  source: string;
  matched_rule?: string | null;
  source_version: string;
  added_date: string;
  reviewer_id: string;
  review_note: string;
  is_blocked: boolean;
}

export interface ApprovedListResponse {
  items: ApprovedApiRecord[];
  total: number;
  count: number;
}

export interface FeedbackReportRequest {
  blocked_api: string;
  model_id: string;
  purpose: string;
  reporter_id: string;
}

export interface FeedbackReportResponse {
  report_id: string;
  blocked_api: string;
  auto_classification: PendingClassification;
  in_official_docs: boolean;
  verified_org_count: number;
  estimated_response_hours: number;
  review_status: ReviewStatus;
  auto_rejected: boolean;
  message: string;
}

export interface FeedbackReportRecord extends Omit<FeedbackReportResponse, 'message'> {
  model_id: string;
  purpose: string;
  reporter_id: string;
  submitted_at: string;
}

export interface FeedbackListResponse {
  items: FeedbackReportRecord[];
  count: number;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  action: string;
  api_path: string;
  actor: string;
  detail: string;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditListResponse {
  items: AuditLogEntry[];
  total: number;
  count: number;
}

export interface AuditVerifyResponse {
  valid: boolean;
  total_entries: number;
  violation_count: number;
  violations: string[];
}

export interface HealthResponse {
  status: string;
}

export interface WhitelistStats {
  whitelist_version: string | number;
  approved_active: number;
  blocked: number;
  rejected: number;
  pending_review: number;
  feedback_total: number;
}

export interface DemoEvidenceItem {
  kind: string;
  title: string;
  path: string;
  summary: string;
  exists: boolean;
  last_modified: string | null;
}

export interface DemoEvidenceResponse {
  items: DemoEvidenceItem[];
}

export interface DemoReadiness {
  health: { ok: boolean };
  openapi: { ok: boolean };
  dashboard: { ok: boolean };
  audit_chain: {
    valid: boolean;
    violation_count: number;
    violations: string[];
  };
  stats: WhitelistStats;
  evidence: {
    missing: string[];
    items: DemoEvidenceItem[];
  };
  warnings: string[];
}
