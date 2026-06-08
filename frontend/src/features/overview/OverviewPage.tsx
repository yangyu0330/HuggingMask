import { AlertTriangle, ArrowRight, ExternalLink, Play } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

import { fetchOverviewData } from '../../api/overview';
import { ErrorPanel } from '../../components/ErrorPanel';
import { MetricTile } from '../../components/MetricTile';
import { StatusPill } from '../../components/StatusPill';

const pipelineStages = [
  'Model Repository',
  'File Classification',
  'Weight Validator',
  'Code/Config Validator',
  'Whitelist Engine',
  'Final Decision',
  'Evidence/Audit',
];

function okTone(ok: boolean) {
  return ok ? 'ok' : 'bad';
}

export function OverviewPage() {
  const { data, error, isLoading } = useQuery({
    queryKey: ['overview'],
    queryFn: fetchOverviewData,
  });

  if (isLoading) {
    return (
      <section className="console-panel" aria-busy="true">
        <div className="section-kicker">Readiness</div>
        <h1>System Overview</h1>
        <div className="loading-line" />
        <div className="loading-grid">
          <div />
          <div />
          <div />
          <div />
        </div>
      </section>
    );
  }

  if (error || !data) {
    return (
      <section className="console-panel">
        <div className="section-kicker">Readiness</div>
        <h1>System Overview</h1>
        <ErrorPanel
          title="Overview data unavailable"
          message={error instanceof Error ? error.message : 'The overview requests did not complete.'}
        />
      </section>
    );
  }

  const { health, readiness, stats } = data;
  const missing = readiness.evidence.missing;
  const warnings = readiness.warnings;

  return (
    <section className="console-panel overview-panel" aria-labelledby="overview-title">
      <div className="section-kicker">Readiness</div>
      <div className="overview-heading">
        <div>
          <h1 id="overview-title">System Overview</h1>
          <p>Model files, code, and config are validated separately before release decisions.</p>
        </div>
        <Link className="primary-link" to="/demo">
          <Play aria-hidden="true" size={16} />
          <span>Demo Console</span>
        </Link>
      </div>

      <div className="readiness-strip" aria-label="Readiness status">
        <StatusPill tone={okTone(health.status === 'ok')}>Health {health.status.toUpperCase()}</StatusPill>
        <StatusPill tone={okTone(readiness.openapi.ok)}>OpenAPI {readiness.openapi.ok ? 'OK' : 'Issue'}</StatusPill>
        <StatusPill tone={okTone(readiness.dashboard.ok)}>Dashboard {readiness.dashboard.ok ? 'OK' : 'Issue'}</StatusPill>
        <StatusPill tone={okTone(readiness.audit_chain.valid)}>
          Audit {readiness.audit_chain.valid ? 'Valid' : 'Invalid'}
        </StatusPill>
        <StatusPill tone={missing.length ? 'warn' : 'ok'}>Evidence {missing.length ? `${missing.length} Missing` : 'Ready'}</StatusPill>
      </div>

      <div className="metric-grid metric-grid-four" aria-label="Whitelist metrics">
        <MetricTile label="Approved APIs" value={stats.approved_active} detail={`Version ${stats.whitelist_version}`} />
        <MetricTile label="Pending Review" value={stats.pending_review} detail="Security owner queue" />
        <MetricTile label="Blocked APIs" value={stats.blocked} detail="Denied release paths" />
        <MetricTile label="Feedback Reports" value={stats.feedback_total} detail="Operator reports" />
      </div>

      <div className="overview-grid">
        <section className="section-block" aria-labelledby="pipeline-title">
          <div className="section-title-row">
            <h2 id="pipeline-title">Pipeline</h2>
            <StatusPill tone="info">Fixture mode</StatusPill>
          </div>
          <ol className="pipeline-list">
            {pipelineStages.map((stage, index) => (
              <li key={stage}>
                <span>{stage}</span>
                {index < pipelineStages.length - 1 ? <ArrowRight aria-hidden="true" size={15} /> : null}
              </li>
            ))}
          </ol>
        </section>

        <section className="section-block" aria-labelledby="readiness-title">
          <div className="section-title-row">
            <h2 id="readiness-title">Readiness Notes</h2>
            <a href="/docs" target="_blank" rel="noreferrer" className="icon-link" aria-label="Open Swagger documentation">
              <ExternalLink aria-hidden="true" size={17} />
            </a>
          </div>
          {warnings.length ? (
            <ul className="notice-list">
              {warnings.map((warning) => (
                <li key={warning}>
                  <AlertTriangle aria-hidden="true" size={16} />
                  <span>{warning}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="quiet-copy">No readiness warnings reported.</p>
          )}
          {missing.length ? (
            <div className="missing-evidence">
              <strong>Missing Evidence</strong>
              <ul>
                {missing.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="quiet-copy">All tracked evidence files are present.</p>
          )}
        </section>
      </div>
    </section>
  );
}
