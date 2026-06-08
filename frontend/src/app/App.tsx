import { Activity, Archive, FileText, Gauge, ListChecks, ShieldCheck, UploadCloud } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { API_BASE } from '../api/client';
import { AppRoutes } from './routes';

const navItems = [
  { to: '/overview', label: '개요', icon: Gauge },
  { to: '/demo', label: '데모 콘솔', icon: Activity },
  { to: '/live', label: '실제 모델', icon: UploadCloud },
  { to: '/validation', label: '검증 상세', icon: ListChecks },
  { to: '/operations', label: '운영 관리', icon: ShieldCheck },
  { to: '/evidence', label: '근거 자료', icon: Archive },
];

export function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="주 메뉴">
        <div className="brand-lockup">
          <FileText aria-hidden="true" size={24} />
          <div>
            <span>HuggingMask</span>
            <strong>데모 콘솔</strong>
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
          <span>프론트엔드 준비 완료</span>
          <span className="api-chip">{API_BASE}</span>
        </div>
        <AppRoutes />
      </main>
    </div>
  );
}
