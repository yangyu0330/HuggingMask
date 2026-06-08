import { useEffect, useState } from 'react';
import { ClipboardCopy } from 'lucide-react';

import { loadLastDemoRun } from '../../api/demo';
import type { DemoRunResponse } from '../../api/types';
import { StatusPill } from '../../components/StatusPill';

const routeDescriptions: Record<string, string> = {
  SAFETENSORS_FAST_PATH: 'Safetensors metadata and hash validation.',
  PICKLE_PATH_A: 'Non-executing pickle opcode and tensor-schema validation.',
  PICKLE_PATH_B: 'Opt-in sandbox comparison evidence path.',
  CODE_AST_SCAN: 'Static Python AST and API policy scan.',
  CODE_RESTRICTED_RUNTIME: 'Restricted runtime gate for B-1 candidates.',
  CODE_SANDBOX_RUNTIME: 'B-2 sandbox/security owner evidence path.',
  CONFIG_SCHEMA_VALIDATION: 'Config trigger and linked-code routing validation.',
  PREPROCESSING_SEMANTIC_SCAN: 'Tokenizer and preprocessing metadata semantic scan.',
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
        <div className="section-kicker">Validation</div>
        <h1 id="validation-title">Validation Detail</h1>
        <p className="quiet-copy">Run a demo scenario to populate validation detail.</p>
      </section>
    );
  }

  const response = run.validation_response;
  const metadata = [
    ['Scenario', run.scenario_id],
    ['Run ID', run.run_id],
    ['Request ID', response.request_id],
    ['Job ID', response.job_id],
    ['Created', response.created_at],
  ];

  return (
    <section className="console-panel validation-detail" aria-labelledby="validation-title">
      <div className="section-kicker">Validation</div>
      <div className="overview-heading">
        <div>
          <h1 id="validation-title">Validation Detail</h1>
          <p>Job decision, artifact status, reason hierarchy, routes, coverage, and raw response.</p>
        </div>
        <StatusPill tone={tone(response.overall_decision)}>{response.overall_decision}</StatusPill>
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

      <section className="section-block" aria-labelledby="hierarchy-title">
        <div className="section-title-row">
          <h2 id="hierarchy-title">Decision Hierarchy</h2>
          <StatusPill tone={tone(response.overall_status)}>{response.overall_status}</StatusPill>
        </div>
        <div className="decision-grid">
          <div>
            <span>Job decision</span>
            <strong>{response.overall_decision}</strong>
          </div>
          <div>
            <span>Overall artifact status</span>
            <strong>{response.overall_status}</strong>
          </div>
          <div>
            <span>Release action</span>
            <strong>{response.release_action}</strong>
          </div>
          <div>
            <span>Report</span>
            <strong>{response.report_id}</strong>
          </div>
        </div>
      </section>

      <section className="section-block" aria-labelledby="route-title">
        <h2 id="route-title">Route Explanation</h2>
        <div className="route-grid">
          {Object.entries(routeDescriptions).map(([route, description]) => (
            <div key={route}>
              <strong>{route}</strong>
              <span>{description}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="section-block" aria-labelledby="results-title">
        <h2 id="results-title">Artifact Results and Reasons</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Status</th>
                <th>Route</th>
                <th>Reason Entries</th>
              </tr>
            </thead>
            <tbody>
              {response.artifact_results.map((item) => (
                <tr key={`${item.artifact.artifact_id}-${item.route_kind}`}>
                  <td>{item.artifact.repo_path}</td>
                  <td>
                    <StatusPill tone={tone(item.status)}>{item.status}</StatusPill>
                  </td>
                  <td>{item.route_kind}</td>
                  <td>{item.reason_entries.map((entry) => entry.code).join(', ') || 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section-block" aria-labelledby="coverage-title">
        <h2 id="coverage-title">Coverage Summary</h2>
        <pre className="raw-json">{JSON.stringify(response.coverage_summary, null, 2)}</pre>
      </section>

      <section className="section-block" aria-labelledby="validation-json-title">
        <div className="section-title-row">
          <h2 id="validation-json-title">Raw JSON</h2>
          <button
            type="button"
            className="icon-link"
            aria-label="Copy validation JSON"
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(response, null, 2));
              setCopied(true);
            }}
          >
            <ClipboardCopy aria-hidden="true" size={17} />
          </button>
        </div>
        {copied ? <p className="quiet-copy">Copied validation JSON.</p> : null}
        <pre className="raw-json">{JSON.stringify(response, null, 2)}</pre>
      </section>
    </section>
  );
}

