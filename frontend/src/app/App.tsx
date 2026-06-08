import { Activity, Archive, FileText, Gauge, ListChecks, ShieldCheck } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { API_BASE } from '../api/client';
import { AppRoutes } from './routes';

const navItems = [
  { to: '/overview', label: 'Overview', icon: Gauge },
  { to: '/demo', label: 'Demo Console', icon: Activity },
  { to: '/validation', label: 'Validation Detail', icon: ListChecks },
  { to: '/operations', label: 'Operations', icon: ShieldCheck },
  { to: '/evidence', label: 'Evidence', icon: Archive },
];

export function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary">
        <div className="brand-lockup">
          <FileText aria-hidden="true" size={24} />
          <div>
            <span>HuggingMask</span>
            <strong>Demo Console</strong>
          </div>
        </div>
        <nav className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => (isActive ? 'active' : undefined)}>
                <Icon aria-hidden="true" size={18} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </aside>
      <main className="main-surface">
        <div className="status-strip" role="status">
          <span className="status-dot" aria-hidden="true" />
          <span>Frontend shell ready</span>
          <span className="api-chip">{API_BASE}</span>
        </div>
        <AppRoutes />
      </main>
    </div>
  );
}
