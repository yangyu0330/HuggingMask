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
  ArtifactValidationResult,
  DemoRunResponse,
  DemoScenarioSummary,
  ReasonEntry,
} from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { StatusPill } from '../../components/StatusPill';

function statusTone(value: unknown): 'ok' | 'warn' | 'bad' | 'info' {
  const text = String(value ?? '').toUpperCase();
  if (['PASS', 'APPROVE', 'APPROVE_WITH_TRANSFORM', 'ALLOWED'].includes(text)) return 'ok';
  if (['DENY', 'BLOCK', 'BLOCKED', 'ERROR'].includes(text)) return 'bad';
  if (['PENDING_REVIEW', 'REVIEW_REQUIRED', 'PENDING', 'UNKNOWN'].includes(text)) return 'warn';
  return 'info';
}

function reasonCodes(result?: DemoRunResponse | null) {
  return Array.isArray(result?.actual.reason_codes)
    ? (result?.actual.reason_codes as string[])
    : [];
}

function firstArtifactReason(artifact?: ArtifactValidationResult | null): ReasonEntry | null {
  return artifact?.reason_entries?.[0] ?? null;
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
  const selectedReason = firstArtifactReason(selectedArtifact);

  return (
    <section className="console-panel demo-console" aria-labelledby="demo-title">
      <div className="section-kicker">Fixtures</div>
      <div className="overview-heading">
        <div>
          <h1 id="demo-title">Demo Console</h1>
          <p>Five fixed mock_hf scenarios exercise safetensors, pickle, Python code, and config routing.</p>
        </div>
        <StatusPill tone={runResult?.matched_expectation ? 'ok' : runResult ? 'bad' : 'info'}>
          {runResult ? (runResult.matched_expectation ? 'Expectation Match' : 'Mismatch') : 'Ready'}
        </StatusPill>
      </div>

      {scenariosQuery.error ? (
        <ErrorPanel title="Scenario list unavailable" message={(scenariosQuery.error as Error).message} />
      ) : null}
      {runMutation.error ? (
        <ErrorPanel title="Scenario run failed" message={(runMutation.error as Error).message} />
      ) : null}

      <div className="demo-layout">
        <aside className="scenario-list" aria-label="Demo scenarios">
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
                {scenario.expected_overall_status}
              </StatusPill>
            </button>
          ))}
        </aside>

        <div className="demo-main">
          <section className="section-block" aria-labelledby="scenario-detail-title">
            <div className="section-title-row">
              <div>
                <h2 id="scenario-detail-title">{selectedScenario?.title ?? 'Scenario'}</h2>
                <p className="quiet-copy">{selectedScenario?.fixture_path}</p>
              </div>
              <StatusPill tone={statusTone(selectedScenario?.expected_overall_decision)}>
                Expected {selectedScenario?.expected_overall_decision ?? '...'}
              </StatusPill>
            </div>
            {detailQuery.data ? (
              <div className="scenario-detail-grid">
                <div>
                  <strong>Required files</strong>
                  <ul>
                    {detailQuery.data.required_repo_files.map((file) => (
                      <li key={file}>{file}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Expected reason codes</strong>
                  <ul>
                    {detailQuery.data.expected_reason_codes.map((code) => (
                      <li key={code}>{code}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Generated artifacts</strong>
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
              <h2 id="run-panel-title">Run Scenario</h2>
              <div className="run-actions">
                <label>
                  <input
                    type="checkbox"
                    checked={cacheCheck}
                    onChange={(event) => setCacheCheck(event.currentTarget.checked)}
                  />
                  <span>Cache check</span>
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={enablePathB}
                    onChange={(event) => setEnablePathB(event.currentTarget.checked)}
                  />
                  <span>Path B evidence</span>
                </label>
                <button type="button" className="primary-link" onClick={() => runMutation.mutate()} disabled={!selectedId || runMutation.isPending}>
                  {runMutation.isPending ? <RefreshCw aria-hidden="true" size={16} /> : <Play aria-hidden="true" size={16} />}
                  <span>{runMutation.isPending ? 'Running' : 'Run'}</span>
                </button>
              </div>
            </div>

            {runResult ? (
              <div className="run-summary-grid">
                <div>
                  <span>Job Decision</span>
                  <StatusPill tone={statusTone(runResult.actual.overall_decision)}>
                    {String(runResult.actual.overall_decision)}
                  </StatusPill>
                </div>
                <div>
                  <span>Artifact Status</span>
                  <StatusPill tone={statusTone(runResult.actual.overall_status)}>
                    {String(runResult.actual.overall_status)}
                  </StatusPill>
                </div>
                <div>
                  <span>Release Action</span>
                  <strong>{String(runResult.actual.release_action)}</strong>
                </div>
                <div>
                  <span>Expectation</span>
                  <StatusPill tone={runResult.matched_expectation ? 'ok' : 'bad'}>
                    {runResult.matched_expectation ? 'Matched' : 'Mismatch'}
                  </StatusPill>
                </div>
              </div>
            ) : (
              <p className="quiet-copy">No run has been started for this scenario.</p>
            )}
          </section>

          {runResult ? (
            <>
              <section className="section-block" aria-labelledby="expectation-title">
                <div className="section-title-row">
                  <h2 id="expectation-title">Expected vs Actual</h2>
                  {runResult.matched_expectation ? <CheckCircle2 aria-hidden="true" /> : <CircleAlert aria-hidden="true" />}
                </div>
                <div className="comparison-grid">
                  <pre>{JSON.stringify(runResult.expected, null, 2)}</pre>
                  <pre>{JSON.stringify(runResult.actual, null, 2)}</pre>
                </div>
                {runResult.expectation_mismatches.length ? (
                  <p className="mismatch-line">Mismatch: {runResult.expectation_mismatches.join(', ')}</p>
                ) : null}
              </section>

              <section className="section-block" aria-labelledby="artifact-title">
                <div className="section-title-row">
                  <h2 id="artifact-title">Artifact Results</h2>
                  <Link className="icon-link" to="/validation" aria-label="Open validation detail">
                    <ExternalLink aria-hidden="true" size={17} />
                  </Link>
                </div>
                <div className="table-scroll">
                  <table className="artifact-result-table">
                    <thead>
                      <tr>
                        <th>File</th>
                        <th>Kind</th>
                        <th>Route</th>
                        <th>Status</th>
                        <th>Grade</th>
                        <th>Review Action</th>
                        <th>Reason</th>
                        <th>Cache</th>
                      </tr>
                    </thead>
                    <tbody>
                      {runResult.validation_response.artifact_results.map((item) => (
                        <tr
                          key={`${item.artifact.artifact_id}-${item.route_kind}`}
                          className={item.artifact.artifact_id === selectedArtifactId ? 'selected' : undefined}
                          onClick={() => setSelectedArtifactId(item.artifact.artifact_id)}
                        >
                          <td>{item.artifact.file_name}</td>
                          <td>{item.artifact.file_kind}</td>
                          <td>{item.route_kind}</td>
                          <td>
                            <StatusPill tone={statusTone(item.status)}>{item.status}</StatusPill>
                          </td>
                          <td>{item.grade}</td>
                          <td>{item.review_action}</td>
                          <td>{item.reason_entries.map((entry) => entry.code).join(', ')}</td>
                          <td>{item.cache_hit ? 'Hit' : 'Miss'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="detail-split">
                <div className="section-block" aria-labelledby="reason-title">
                  <h2 id="reason-title">Reason Detail</h2>
                  {selectedReason ? (
                    <div className="reason-detail">
                      <StatusPill tone={statusTone(selectedArtifact?.status)}>{selectedReason.code}</StatusPill>
                      <p>{selectedReason.message}</p>
                      <pre>{JSON.stringify(selectedArtifact?.details ?? {}, null, 2)}</pre>
                    </div>
                  ) : (
                    <p className="quiet-copy">Select an artifact row to inspect reason details.</p>
                  )}
                </div>
                <div className="section-block" aria-labelledby="generated-title">
                  <h2 id="generated-title">Generated Artifacts</h2>
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
                    <p className="quiet-copy">No generated artifacts for this run.</p>
                  )}
                </div>
              </section>

              <section className="section-block" aria-labelledby="raw-json-title">
                <div className="section-title-row">
                  <h2 id="raw-json-title">Raw JSON</h2>
                  <Link to="/validation" className="primary-link">
                    <span>Validation Detail</span>
                  </Link>
                </div>
                <pre className="raw-json">{JSON.stringify(runResult.validation_response, null, 2)}</pre>
              </section>
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
