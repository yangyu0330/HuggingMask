import { API_BASE } from '../api/client';

const sections = {
  overview: {
    eyebrow: 'Readiness',
    title: 'System Overview',
    body: 'Health, whitelist metrics, demo readiness, and pipeline state.',
  },
  demo: {
    eyebrow: 'Fixtures',
    title: 'Demo Console',
    body: 'Scenario execution, expectation matching, and artifact evidence.',
  },
  validation: {
    eyebrow: 'Validation',
    title: 'Validation Detail',
    body: 'Job decisions, artifact status, reason entries, and generated artifacts.',
  },
  operations: {
    eyebrow: 'Operations',
    title: 'Whitelist Operations',
    body: 'Whitelist checks, pending reviews, audit verification, and feedback.',
  },
  evidence: {
    eyebrow: 'Evidence',
    title: 'Evidence Matrix',
    body: 'Documents, worklogs, test evidence, and known limitations.',
  },
};

export type ConsoleSection = keyof typeof sections;

type PlaceholderPageProps = {
  section: ConsoleSection;
};

export function PlaceholderPage({ section }: PlaceholderPageProps) {
  const item = sections[section];
  return (
    <section className="console-panel" aria-labelledby={`${section}-title`}>
      <div className="section-kicker">{item.eyebrow}</div>
      <h1 id={`${section}-title`}>{item.title}</h1>
      <p>{item.body}</p>
      <div className="metric-grid" aria-label={`${item.title} summary`}>
        <div className="metric-tile">
          <span>API Base</span>
          <strong>{API_BASE}</strong>
        </div>
        <div className="metric-tile">
          <span>Route</span>
          <strong>{section}</strong>
        </div>
        <div className="metric-tile">
          <span>Stage</span>
          <strong>Phase 2</strong>
        </div>
      </div>
    </section>
  );
}
