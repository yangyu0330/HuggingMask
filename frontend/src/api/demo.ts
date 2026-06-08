import { apiGet, apiPost } from './client';
import type {
  DemoEvidenceResponse,
  DemoRunRequest,
  DemoRunResponse,
  DemoScenarioDetail,
  DemoScenarioListResponse,
} from './types';

export const LAST_DEMO_RUN_KEY = 'huggingmask:last-demo-run';

export function listDemoScenarios(): Promise<DemoScenarioListResponse> {
  return apiGet<DemoScenarioListResponse>('/demo/scenarios');
}

export function getDemoScenario(scenarioId: string): Promise<DemoScenarioDetail> {
  return apiGet<DemoScenarioDetail>(`/demo/scenarios/${encodeURIComponent(scenarioId)}`);
}

export function runDemoScenario(
  scenarioId: string,
  request: Partial<DemoRunRequest>,
): Promise<DemoRunResponse> {
  return apiPost<DemoRunResponse>(`/demo/scenarios/${encodeURIComponent(scenarioId)}/run`, {
    repeat_cache_check: false,
    reset_demo_state: false,
    enable_path_b: false,
    requested_by: 'demo_presenter',
    ...request,
  });
}

export function getDemoEvidence(): Promise<DemoEvidenceResponse> {
  return apiGet<DemoEvidenceResponse>('/demo/evidence');
}

export function saveLastDemoRun(run: DemoRunResponse) {
  window.localStorage.setItem(LAST_DEMO_RUN_KEY, JSON.stringify(run));
}

export function loadLastDemoRun(): DemoRunResponse | null {
  const raw = window.localStorage.getItem(LAST_DEMO_RUN_KEY);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw) as DemoRunResponse;
  } catch {
    return null;
  }
}
