import { apiGet } from './client';
import type { DemoReadiness, HealthResponse, WhitelistStats } from './types';

export interface OverviewData {
  health: HealthResponse;
  stats: WhitelistStats;
  readiness: DemoReadiness;
}

async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch('/health', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`GET /health failed with ${response.status}`);
  }
  return response.json() as Promise<HealthResponse>;
}

export async function fetchOverviewData(): Promise<OverviewData> {
  const [health, stats, readiness] = await Promise.all([
    fetchHealth(),
    apiGet<WhitelistStats>('/stats'),
    apiGet<DemoReadiness>('/demo/readiness'),
  ]);

  return { health, stats, readiness };
}
