import { useEffect, useState } from 'react';
import { ClipboardCopy } from 'lucide-react';

import { loadLastDemoRun } from '../../api/demo';
import type { DemoRunResponse } from '../../api/types';
import { StatusPill } from '../../components/StatusPill';
import {
  koreanReasonCodeTitle,
  koreanRouteKindLabel,
  koreanStatusLabel,
} from '../../lib/koreanLabels';
import {
  artifactFactRows,
  artifactNextAction,
  artifactPlainSummary,
  reasonExplanation,
  responseFactRows,
  validationDecisionSummary,
} from '../../lib/validationExplain';

const routeDescriptions: Record<string, string> = {
  SAFETENSORS_FAST_PATH: 'safetensors 메타데이터와 해시를 빠르게 검증합니다.',
  PICKLE_PATH_A: 'pickle을 실행하지 않고 opcode와 tensor 스키마를 검증합니다.',
  PICKLE_PATH_B: '선택적으로 켜는 샌드박스 비교 근거 경로입니다.',
  CODE_AST_SCAN: 'Python AST와 API 정책을 정적으로 검사합니다.',
  CODE_RESTRICTED_RUNTIME: 'B-1 후보에 대한 제한 런타임 게이트입니다.',
  CODE_SANDBOX_RUNTIME: 'B-2 샌드박스와 보안 담당자 검토 근거 경로입니다.',
  CONFIG_SCHEMA_VALIDATION: '설정 트리거와 연결 코드 라우팅을 검증합니다.',
  PREPROCESSING_SEMANTIC_SCAN: '토크나이저와 전처리 메타데이터 의미를 검사합니다.',
};

function tone(value: unknown): 'ok' | 'warn' | 'bad' | 'info' {
  const text = String(value ?? '').toUpperCase();
  if (['PASS', 'APPROVE', 'APPROVE_WITH_TRANSFORM'].includes(text)) return 'ok';
  if (['BLOCK', 'DENY', 'ERROR'].includes(text)) return 'bad';
  if (['PENDING_REVIEW', 'REVIEW_REQUIRED', 'SKIPPED'].includes(text)) return 'warn';
  return 'info';
}

export function ValidationDetailPage() {
  const [run, setRun] = useState<DemoRunResponse | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setRun(loadLastDemoRun());
  }, []);

  if (!run) {
    return (
      <section className="console-panel" aria-labelledby="validation-title">
        <div className="section-kicker">검증</div>
        <h1 id="validation-title">검증 상세</h1>
        <p className="quiet-copy">검증 상세를 보려면 먼저 데모 시나리오를 실행하세요.</p>
      </section>
    );
  }

  const response = run.validation_response;
  const metadata = [
    ['시나리오', run.scenario_id],
    ['실행 ID', run.run_id],
    ['요청 ID', response.request_id],
    ['작업 ID', response.job_id],
    ['생성 시각', response.created_at],
  ];

  return (
    <section className="console-panel validation-detail" aria-labelledby="validation-title">
      <div className="section-kicker">검증</div>
      <div className="overview-heading">
        <div>
          <h1 id="validation-title">검증 상세</h1>
          <p>작업 판정, 산출물 상태, 사유 계층, 검증 경로, 커버리지, 원본 응답을 확인합니다.</p>
        </div>
        <StatusPill tone={tone(response.overall_decision)}>{koreanStatusLabel(response.overall_decision)}</StatusPill>
      </div>

      <section className="section-block">
        <div className="metadata-grid">
          {metadata.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="section-block" aria-labelledby="plain-summary-title">
        <div className="section-title-row">
          <h2 id="plain-summary-title">한눈에 보는 판정 해설</h2>
          <StatusPill tone={tone(response.overall_decision)}>{koreanStatusLabel(response.overall_decision)}</StatusPill>
        </div>
        <p>{validationDecisionSummary(response)}</p>
        <div className="explanation-grid">
          {responseFactRows(response).map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="section-block" aria-labelledby="hierarchy-title">
        <div className="section-title-row">
          <h2 id="hierarchy-title">판정 계층</h2>
          <StatusPill tone={tone(response.overall_status)}>{koreanStatusLabel(response.overall_status)}</StatusPill>
        </div>
        <div className="decision-grid">
          <div>
            <span>작업 판정</span>
            <strong>{koreanStatusLabel(response.overall_decision)}</strong>
          </div>
          <div>
            <span>전체 산출물 상태</span>
            <strong>{koreanStatusLabel(response.overall_status)}</strong>
          </div>
          <div>
            <span>릴리스 조치</span>
            <strong>{response.release_action}</strong>
          </div>
          <div>
            <span>보고서</span>
            <strong>{response.report_id}</strong>
          </div>
        </div>
      </section>

      <section className="section-block" aria-labelledby="route-title">
        <h2 id="route-title">검증 경로 설명</h2>
        <div className="route-grid">
          {Object.entries(routeDescriptions).map(([route, description]) => (
            <div key={route}>
              <strong>{route}</strong>
              <span>{description}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="section-block" aria-labelledby="artifact-explain-title">
        <h2 id="artifact-explain-title">파일별 해설</h2>
        <div className="explain-card-grid">
          {response.artifact_results.map((item) => (
            <article key={`${item.artifact.artifact_id}-${item.route_kind}`} className="explain-card">
              <div className="section-title-row">
                <div>
                  <strong>{item.artifact.repo_path}</strong>
                  <span>{koreanRouteKindLabel(item.route_kind)}</span>
                </div>
                <StatusPill tone={tone(item.status)}>{koreanStatusLabel(item.status)}</StatusPill>
              </div>
              <p>{artifactPlainSummary(item)}</p>
              <div className="explanation-grid">
                {artifactFactRows(item).map(([label, value]) => (
                  <div key={label}>
                    <span>{label}</span>
                    <strong>{value}</strong>
                  </div>
                ))}
              </div>
              <div className="live-explain-box">
                <span>{artifactNextAction(item)}</span>
              </div>
              {item.reason_entries.length ? (
                <ul className="reason-list">
                  {item.reason_entries.map((entry) => (
                    <li key={`${item.artifact.artifact_id}-${entry.code}`}>
                      <strong>{koreanReasonCodeTitle(entry.code)}</strong>
                      <span>{reasonExplanation(entry)}</span>
                      <small>{entry.code}</small>
                    </li>
                  ))}
                </ul>
              ) : null}
            </article>
          ))}
        </div>
      </section>

      <section className="section-block" aria-labelledby="results-title">
        <h2 id="results-title">산출물 결과와 사유</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>산출물</th>
                <th>상태</th>
                <th>경로</th>
                <th>사유 항목</th>
              </tr>
            </thead>
            <tbody>
              {response.artifact_results.map((item) => (
                <tr key={`${item.artifact.artifact_id}-${item.route_kind}`}>
                  <td>{item.artifact.repo_path}</td>
                  <td>
                    <StatusPill tone={tone(item.status)}>{koreanStatusLabel(item.status)}</StatusPill>
                  </td>
                  <td>{koreanRouteKindLabel(item.route_kind)}</td>
                  <td>
                    {item.reason_entries.map((entry) => (
                      <span className="reason-chip" key={`${item.artifact.artifact_id}-${entry.code}`}>
                        {koreanReasonCodeTitle(entry.code)}
                      </span>
                    ))}
                    {item.reason_entries.length ? null : '없음'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section-block" aria-labelledby="coverage-title">
        <h2 id="coverage-title">커버리지 요약</h2>
        <details className="json-details">
          <summary>커버리지 JSON</summary>
          <pre className="raw-json">{JSON.stringify(response.coverage_summary, null, 2)}</pre>
        </details>
      </section>

      <section className="section-block" aria-labelledby="validation-json-title">
        <div className="section-title-row">
          <h2 id="validation-json-title">원본 JSON</h2>
          <button
            type="button"
            className="icon-link"
            aria-label="검증 JSON 복사"
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(response, null, 2));
              setCopied(true);
            }}
          >
            <ClipboardCopy aria-hidden="true" size={17} />
          </button>
        </div>
        {copied ? <p className="quiet-copy">검증 JSON을 복사했습니다.</p> : null}
        <details className="json-details">
          <summary>전체 검증 응답 JSON</summary>
          <pre className="raw-json">{JSON.stringify(response, null, 2)}</pre>
        </details>
      </section>
    </section>
  );
}
