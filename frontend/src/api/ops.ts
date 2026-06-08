import { apiGet } from './client';
import type { DemoReadiness, HealthResponse, WhitelistStats } from './types';

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
