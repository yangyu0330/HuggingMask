export const API_BASE = '/internal/v1';

type JsonBody = Record<string, unknown> | unknown[] | string | number | boolean | null;
type JsonRequestInit = Omit<RequestInit, 'body'> & { body?: BodyInit | JsonBody };

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export async function fetchJson<T>(
  path: string,
  init: JsonRequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');

  let body = init.body;
  if (
    body !== undefined &&
    body !== null &&
    typeof body !== 'string' &&
    !(body instanceof FormData) &&
    !(body instanceof Blob) &&
    !(body instanceof ArrayBuffer) &&
    !(body instanceof URLSearchParams)
  ) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${path.startsWith('/') ? path : `/${path}`}`, {
    ...init,
    headers,
    body: body as BodyInit | undefined,
  });

  const contentType = response.headers.get('content-type') ?? '';
  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    throw new ApiError(`요청 실패: HTTP ${response.status}`, response.status, payload);
  }

  if (
    payload &&
    typeof payload === 'object' &&
    'applied' in payload &&
    (payload as { applied?: unknown }).applied === false
  ) {
    throw new ApiError('요청은 완료됐지만 적용되지 않았습니다', response.status, payload);
  }

  return payload as T;
}

export function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  return fetchJson<T>(path, init);
}

export function apiPost<TResponse, TBody = unknown>(
  path: string,
  body: TBody,
  init?: RequestInit,
): Promise<TResponse> {
  const { body: _ignoredBody, ...rest } = init ?? {};
  return fetchJson<TResponse>(path, {
    method: 'POST',
    ...rest,
    body: body as JsonBody,
  });
}
