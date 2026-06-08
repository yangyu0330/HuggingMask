import type { ReactNode } from 'react';

type StatusTone = 'ok' | 'warn' | 'bad' | 'info';

export function StatusPill({
  tone,
  children,
}: {
  tone: StatusTone;
  children: ReactNode;
}) {
  return <span className={`status-pill status-pill-${tone}`}>{children}</span>;
}
