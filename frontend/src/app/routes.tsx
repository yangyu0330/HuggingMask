import { Navigate, Route, Routes } from 'react-router-dom';
import { OverviewPage } from '../features/overview/OverviewPage';
import { DemoConsolePage } from '../features/demo/DemoConsolePage';
import { ValidationDetailPage } from '../features/validation/ValidationDetailPage';
import { PlaceholderPage } from './PlaceholderPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route index element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<OverviewPage />} />
      <Route path="/demo" element={<DemoConsolePage />} />
      <Route path="/validation" element={<ValidationDetailPage />} />
      <Route path="/operations" element={<PlaceholderPage section="operations" />} />
      <Route path="/evidence" element={<PlaceholderPage section="evidence" />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
