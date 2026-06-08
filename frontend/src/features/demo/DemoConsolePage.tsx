import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { CheckCircle2, CircleAlert, ExternalLink, Play, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';

import {
  getDemoScenario,
  listDemoScenarios,
  runDemoScenario,
  saveLastDemoRun,
} from '../../api/demo';
import type {
  DemoRunResponse,
  DemoScenarioSummary,
} from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { StatusPill } from '../../components/StatusPill';
import {
  koreanCacheLabel,
  koreanFileKindLabel,
  koreanReasonCodeTitle,
  koreanRouteKindLabel,
  koreanStatusLabel,
} from '../../lib/koreanLabels';
import {
  artifactFactRows,
  artifactNextAction,
  artifactPlainSummary,
  reasonExplanation,
  validationDecisionSummary,
} from '../../lib/validationExplain';

function statusTone(value: unknown): 'ok' | 'warn' | 'bad' | 'info' {
  const text = String(value ?? '').toUpperCase();
  if (['PASS', 'APPROVE', 'APPROVE_WITH_TRANSFORM', 'ALLOWED'].includes(text)) return 'ok';
  if (['DENY', 'BLOCK', 'BLOCKED', 'ERROR'].includes(text)) return 'bad';
  if (['PENDING_REVIEW', 'REVIEW_REQUIRED', 'PENDING', 'UNKNOWN'].includes(text)) return 'warn';
  return 'info';
}

export function DemoConsolePage() {
  const scenariosQuery = useQuery({ queryKey: ['demo', 'scenarios'], queryFn: listDemoScenarios });
  const [selectedId, setSelectedId] = useState<string>('');
  const [selectedArtifactId, setSelectedArtifactId] = useState<string>('');
  const [runResult, setRunResult] = useState<DemoRunResponse | null>(null);
  const [cacheCheck, setCacheCheck] = useState(false);
  const [enablePathB, setEnablePathB] = useState(false);

  const scenarios = scenariosQuery.data?.items ?? [];

  useEffect(() => {
    if (!selectedId && scenarios.length > 0) {
      setSelectedId(scenarios[0].scenario_id);
    }
  }, [scenarios, selectedId]);

  const detailQuery = useQuery({
    queryKey: ['demo', 'scenario', selectedId],
    queryFn: () => getDemoScenario(selectedId),
    enabled: Boolean(selectedId),
  });

  const runMutation = useMutation({
    mutationFn: () =>
      runDemoScenario(selectedId, {
        repeat_cache_check: cacheCheck,
        enable_path_b: enablePathB,
        requested_by: 'demo_presenter',
      }),
    onSuccess: (result) => {
      setRunResult(result);
      setSelectedArtifactId(result.validation_response.artifact_results[0]?.artifact.artifact_id ?? '');
      saveLastDemoRun(result);
    },
  });

  const selectedScenario = scenarios.find((scenario) => scenario.scenario_id === selectedId);
  const selectedArtifact = useMemo(() => {
    return runResult?.validation_response.artifact_results.find(
      (item) => item.artifact.artifact_id === selectedArtifactId,
    );
  }, [runResult, selectedArtifactId]);

  return (
    <section className="console-panel demo-console" aria-labelledby="demo-title">
      <div className="section-kicker">고정 시나리오</div>
      <div className="overview-heading">
        <div>
          <h1 id="demo-title">데모 콘솔</h1>
          <p>5개 mock_hf 시나리오로 safetensors, pickle, Python 코드, 설정 라우팅 검증을 보여줍니다.</p>
        </div>
        <StatusPill tone={runResult?.matched_expectation ? 'ok' : runResult ? 'bad' : 'info'}>
          {runResult ? (runResult.matched_expectation ? '기대값 일치' : '불일치') : '준비 완료'}
        </StatusPill>
      </div>

      {scenariosQuery.error ? (
        <ErrorPanel title="시나리오 목록을 불러올 수 없습니다" message={(scenariosQuery.error as Error).message} />
      ) : null}
      {runMutation.error ? (
        <ErrorPanel title="시나리오 실행 실패" message={(runMutation.error as Error).message} />
      ) : null}

      <div className="demo-layout">
        <aside className="scenario-list" aria-label="데모 시나리오">
          {scenarios.map((scenario: DemoScenarioSummary) => (
            <button
              key={scenario.scenario_id}
              type="button"
              className={scenario.scenario_id === selectedId ? 'active' : undefined}
              onClick={() => {
                setSelectedId(scenario.scenario_id);
                setRunResult(null);
                setSelectedArtifactId('');
              }}
            >
              <span>{scenario.scenario_id}</span>
              <strong>{scenario.title}</strong>
              <StatusPill tone={statusTone(scenario.expected_overall_status)}>
                {koreanStatusLabel(scenario.expected_overall_status)}
              </StatusPill>
            </button>
          ))}
        </aside>

        <div className="demo-main">
          <section className="section-block" aria-labelledby="scenario-detail-title">
            <div className="section-title-row">
              <div>
                <h2 id="scenario-detail-title">{selectedScenario?.title ?? '시나리오'}</h2>
                <p className="quiet-copy">{selectedScenario?.fixture_path}</p>
              </div>
              <StatusPill tone={statusTone(selectedScenario?.expected_overall_decision)}>
                예상: {koreanStatusLabel(selectedScenario?.expected_overall_decision ?? '...')}
              </StatusPill>
            </div>
            {detailQuery.data ? (
              <div className="scenario-detail-grid">
                <div>
                  <strong>필수 파일</strong>
                  <ul>
                    {detailQuery.data.required_repo_files.map((file) => (
                      <li key={file}>{file}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>예상 사유 코드</strong>
                  <ul>
                    {detailQuery.data.expected_reason_codes.map((code) => (
                      <li key={code}>{koreanReasonCodeTitle(code)} <small>{code}</small></li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>생성 산출물</strong>
                  <ul>
                    {detailQuery.data.artifacts_to_generate.map((item) => (
                      <li key={String(item.path)}>{String(item.path)}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <div className="loading-line" />
            )}
          </section>

          <section className="section-block run-panel" aria-labelledby="run-panel-title">
            <div className="section-title-row">
              <h2 id="run-panel-title">시나리오 실행</h2>
              <div className="run-actions">
                <label>
                  <input
                    type="checkbox"
                    checked={cacheCheck}
                    onChange={(event) => setCacheCheck(event.currentTarget.checked)}
                  />
                  <span>캐시 확인</span>
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={enablePathB}
                    onChange={(event) => setEnablePathB(event.currentTarget.checked)}
                  />
                  <span>Path B 근거</span>
                </label>
                <button type="button" className="primary-link" onClick={() => runMutation.mutate()} disabled={!selectedId || runMutation.isPending}>
                  {runMutation.isPending ? <RefreshCw aria-hidden="true" size={16} /> : <Play aria-hidden="true" size={16} />}
                  <span>{runMutation.isPending ? '실행 중' : '실행'}</span>
                </button>
              </div>
            </div>

            {runResult ? (
              <div className="run-summary-grid">
                <div>
                  <span>작업 판정</span>
                  <StatusPill tone={statusTone(runResult.actual.overall_decision)}>
                    {koreanStatusLabel(runResult.actual.overall_decision)}
                  </StatusPill>
                </div>
                <div>
                  <span>산출물 상태</span>
                  <StatusPill tone={statusTone(runResult.actual.overall_status)}>
                    {koreanStatusLabel(runResult.actual.overall_status)}
                  </StatusPill>
                </div>
                <div>
                  <span>릴리스 조치</span>
                  <strong>{String(runResult.actual.release_action)}</strong>
                </div>
                <div>
                  <span>기대값</span>
                  <StatusPill tone={runResult.matched_expectation ? 'ok' : 'bad'}>
                    {runResult.matched_expectation ? '일치' : '불일치'}
                  </StatusPill>
                </div>
              </div>
            ) : (
              <p className="quiet-copy">이 시나리오는 아직 실행되지 않았습니다.</p>
            )}
          </section>

          {runResult ? (
            <>
              <section className="section-block" aria-labelledby="expectation-title">
                <div className="section-title-row">
                  <h2 id="expectation-title">예상값과 실제값</h2>
                  {runResult.matched_expectation ? <CheckCircle2 aria-hidden="true" /> : <CircleAlert aria-hidden="true" />}
                </div>
                <p className="quiet-copy">{validationDecisionSummary(runResult.validation_response)}</p>
                <div className="comparison-grid">
                  <pre>{JSON.stringify(runResult.expected, null, 2)}</pre>
                  <pre>{JSON.stringify(runResult.actual, null, 2)}</pre>
                </div>
                {runResult.expectation_mismatches.length ? (
                  <p className="mismatch-line">불일치 항목: {runResult.expectation_mismatches.join(', ')}</p>
                ) : null}
              </section>

              <section className="section-block" aria-labelledby="artifact-title">
                <div className="section-title-row">
                  <h2 id="artifact-title">산출물 검증 결과</h2>
                  <Link className="icon-link" to="/validation" aria-label="검증 상세 열기">
                    <ExternalLink aria-hidden="true" size={17} />
                  </Link>
                </div>
                <div className="table-scroll">
                  <table className="artifact-result-table">
                    <thead>
                      <tr>
                        <th>파일</th>
                        <th>종류</th>
                        <th>경로</th>
                        <th>상태</th>
                        <th>등급</th>
                        <th>검토 조치</th>
                        <th>사유</th>
                        <th>캐시</th>
                      </tr>
                    </thead>
                    <tbody>
                      {runResult.validation_response.artifact_results.map((item) => (
                        <tr
                          key={`${item.artifact.artifact_id}-${item.route_kind}`}
                          className={item.artifact.artifact_id === selectedArtifactId ? 'selected' : undefined}
                        >
                          <td>
                            <button
                              type="button"
                              className="table-select-button"
                              onClick={() => setSelectedArtifactId(item.artifact.artifact_id)}
                            >
                              {item.artifact.file_name}
                            </button>
                          </td>
                          <td>{koreanFileKindLabel(item.artifact.file_kind)}</td>
                          <td>{koreanRouteKindLabel(item.route_kind)}</td>
                          <td>
                            <StatusPill tone={statusTone(item.status)}>{koreanStatusLabel(item.status)}</StatusPill>
                          </td>
                          <td>{item.grade}</td>
                          <td>{item.review_action}</td>
                          <td>{item.reason_entries.map((entry) => koreanReasonCodeTitle(entry.code)).join(', ')}</td>
                          <td>{koreanCacheLabel(item.cache_hit)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="detail-split">
                <div className="section-block" aria-labelledby="reason-title">
                  <h2 id="reason-title">선택한 파일 해설</h2>
                  {selectedArtifact ? (
                    <div className="reason-detail">
                      <p>{artifactPlainSummary(selectedArtifact)}</p>
                      <div className="explanation-grid">
                        {artifactFactRows(selectedArtifact).map(([label, value]) => (
                          <div key={label}>
                            <span>{label}</span>
                            <strong>{value}</strong>
                          </div>
                        ))}
                      </div>
                      <div className="live-explain-box">
                        <span>{artifactNextAction(selectedArtifact)}</span>
                      </div>
                      {selectedArtifact.reason_entries.length ? (
                        <ul className="reason-list">
                          {selectedArtifact.reason_entries.map((entry) => (
                            <li key={`${entry.code}-${entry.message}`}>
                              <strong>{koreanReasonCodeTitle(entry.code)}</strong>
                              <span>{reasonExplanation(entry)}</span>
                              <small>{entry.code}</small>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="quiet-copy">추가 사유 항목이 없습니다.</p>
                      )}
                      <details className="json-details">
                        <summary>기술 상세 JSON</summary>
                        <pre>{JSON.stringify(selectedArtifact.details ?? {}, null, 2)}</pre>
                      </details>
                    </div>
                  ) : (
                    <p className="quiet-copy">산출물 행을 선택하면 파일별 해설이 표시됩니다.</p>
                  )}
                </div>
                <div className="section-block" aria-labelledby="generated-title">
                  <h2 id="generated-title">생성된 산출물</h2>
                  {runResult.validation_response.generated_artifacts.length ? (
                    <ul className="generated-list">
                      {runResult.validation_response.generated_artifacts.map((artifact) => (
                        <li key={artifact.artifact_id}>
                          <strong>{artifact.file_name}</strong>
                          <span>{artifact.file_kind}</span>
                          <small>{artifact.sha256}</small>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="quiet-copy">이번 실행에서 생성된 산출물이 없습니다.</p>
                  )}
                </div>
              </section>

              <section className="section-block" aria-labelledby="raw-json-title">
                <div className="section-title-row">
                  <h2 id="raw-json-title">원본 JSON</h2>
                  <Link to="/validation" className="primary-link">
                    <span>검증 상세</span>
                  </Link>
                </div>
                <details className="json-details">
                  <summary>검증 응답 JSON</summary>
                  <pre className="raw-json">{JSON.stringify(runResult.validation_response, null, 2)}</pre>
                </details>
              </section>
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
