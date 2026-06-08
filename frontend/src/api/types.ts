export type ValidationStatus = 'PASS' | 'BLOCK' | 'PENDING_REVIEW' | 'ERROR' | 'SKIPPED';
export type OverallDecision = 'APPROVE' | 'APPROVE_WITH_TRANSFORM' | 'DENY' | 'REVIEW_REQUIRED' | 'ERROR';
export type WhitelistStatus = 'ALLOWED' | 'BLOCKED' | 'UNKNOWN' | 'PENDING';
export type ReviewDecision = 'approve' | 'conditional' | 'reject' | 'defer';
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

export interface PendingApiRecord {
  api_path: string;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
  auto_classification: PendingClassification;
  verified_org_count: number;
  verified_org_list: string[];
  in_official_docs: boolean;
  review_status: string;
  model_list: string[];
  risk_keywords: string[];
  matched_namespace_rule?: string | null;
  documentation_url?: string | null;
  sample_callsites: string[];
  created_from_job_id: string;
}

export interface ReviewDecisionResult {
  api_path: string;
  decision: ReviewDecision;
  applied: boolean;
  message: string;
  review_id?: string | null;
  final_review_status?: string | null;
  audit_event_id?: number | null;
  audit_event_hash?: string | null;
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
