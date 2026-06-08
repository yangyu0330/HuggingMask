import { useQuery } from '@tanstack/react-query';
import { Archive, FileText, RefreshCw } from 'lucide-react';

import { getDemoEvidence } from '../../api/demo';
import { getDemoReadiness } from '../../api/ops';
import type { DemoEvidenceItem } from '../../api/types';
import { ErrorPanel } from '../../components/ErrorPanel';
import { StatusPill } from '../../components/StatusPill';

const documentPaths = [
  {
    title: 'README',
    path: 'README.md',
    note: 'Project scope, run commands, and presentation status summary.',
  },
  {
    title: 'Setup Guide',
    path: 'SETUP_GUIDE.md',
    note: 'Local Python, Docker, port, and test setup checklist.',
  },
  {
    title: 'Detailed Setup Guide',
    path: 'docs/setup_guide.md',
    note: 'Developer-facing setup notes and command references.',
  },
  {
    title: 'Final Demo Script',
    path: 'docs/final_demo_script.md',
    note: 'Four-to-six minute presenter flow and scenario talking points.',
  },
  {
    title: 'Frontend Console Blueprint',
    path: 'docs/frontend_demo_console_blueprint.md',
    note: 'Source design plan for this React console and supporting APIs.',
  },
];

const limitationItems = [
  {
    title: 'B-2/gVisor',
    body: 'Path B is opt-in evidence. The default fixture demo does not claim gVisor is always executed.',
  },
  {
    title: 'Test Count',
    body: 'This phase used focused build and pytest checks. Archived full-test evidence is listed separately, and final full verification belongs to Phase 7.',
  },
  {
    title: 'Live Hugging Face',
    body: 'Fixture scenarios are the reliable default. Live HF downloads are optional evidence and are not a production crawler claim.',
  },
  {
    title: 'Operations Scope',
    body: 'The console has no role-based login in this demo; review actions are shown through the local operations API.',
  },
];

const presentationSteps = ['Overview', 'Demo Console', 'Validation Detail', 'Operations', 'Evidence'];

function statusTone(item: DemoEvidenceItem): 'ok' | 'warn' {
  return item.exists ? 'ok' : 'warn';
}

function formatDate(value: string | null) {
  if (!value) return 'Missing';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export function EvidencePage() {
  const evidenceQuery = useQuery({ queryKey: ['demo', 'evidence'], queryFn: getDemoEvidence });
  const readinessQuery = useQuery({ queryKey: ['demo', 'readiness'], queryFn: getDemoReadiness });

  const evidenceItems = evidenceQuery.data?.items ?? [];
  const missing = readinessQuery.data?.evidence.missing ?? [];

  return (
    <section className="console-panel evidence-panel" aria-labelledby="evidence-title">
      <div className="section-kicker">Evidence</div>
      <div className="overview-heading">
        <div>
          <h1 id="evidence-title">Evidence Matrix</h1>
          <p>Design docs, demo scripts, worklogs, test logs, missing files, and known presentation limits.</p>
        </div>
        <StatusPill tone={missing.length ? 'warn' : 'ok'}>
          {missing.length ? `${missing.length} Missing` : 'Evidence Present'}
        </StatusPill>
      </div>

      {(evidenceQuery.error || readinessQuery.error) ? (
        <ErrorPanel
          title="Evidence data unavailable"
          message={errorMessage(evidenceQuery.error ?? readinessQuery.error)}
        />
      ) : null}

      <section className="section-block" aria-labelledby="matrix-title">
        <div className="section-title-row">
          <div>
            <h2 id="matrix-title">Files and Status</h2>
            <p className="quiet-copy">GET /internal/v1/demo/evidence</p>
          </div>
          <button type="button" className="primary-link" onClick={() => evidenceQuery.refetch()}>
            <RefreshCw aria-hidden="true" size={16} />
            <span>Refresh</span>
          </button>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Title</th>
                <th>Path</th>
                <th>Status</th>
                <th>Last Modified</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {evidenceItems.map((item) => (
                <tr key={`${item.kind}-${item.path}`}>
                  <td>{item.kind}</td>
                  <td>{item.title}</td>
                  <td><code>{item.path}</code></td>
                  <td><StatusPill tone={statusTone(item)}>{item.exists ? 'Present' : 'Missing'}</StatusPill></td>
                  <td>{formatDate(item.last_modified)}</td>
                  <td>{item.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="evidence-grid">
        <section className="section-block" aria-labelledby="missing-title">
          <div className="section-title-row">
            <h2 id="missing-title">Missing Evidence</h2>
            <StatusPill tone={missing.length ? 'warn' : 'ok'}>{missing.length ? 'Review' : 'Clear'}</StatusPill>
          </div>
          {missing.length ? (
            <ul className="notice-list">
              {missing.map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : (
            <p className="quiet-copy">Readiness reports no missing evidence files for the configured matrix.</p>
          )}
        </section>

        <section className="section-block" aria-labelledby="documents-title">
          <h2 id="documents-title">Demo Documents</h2>
          <ul className="document-list">
            {documentPaths.map((item) => (
              <li key={item.path}>
                <FileText aria-hidden="true" size={17} />
                <div>
                  <strong>{item.title}</strong>
                  <code>{item.path}</code>
                  <span>{item.note}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="section-block" aria-labelledby="limits-title">
          <div className="section-title-row">
            <h2 id="limits-title">Known Limitations</h2>
            <StatusPill tone="info">No Overclaim</StatusPill>
          </div>
          <div className="limitations-list">
            {limitationItems.map((item) => (
              <div key={item.title}>
                <strong>{item.title}</strong>
                <span>{item.body}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="section-block" aria-labelledby="flow-title">
          <h2 id="flow-title">Presentation Flow</h2>
          <ol className="presentation-flow">
            {presentationSteps.map((step, index) => (
              <li key={step}>
                <span>{index + 1}</span>
                <strong>{step}</strong>
              </li>
            ))}
          </ol>
          <div className="inline-result">
            <Archive aria-hidden="true" size={18} />
            <span>Use the final demo script path above as the presenter checklist.</span>
          </div>
        </section>
      </div>
    </section>
  );
}
