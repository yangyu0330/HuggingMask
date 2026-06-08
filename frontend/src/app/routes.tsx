import { Navigate, Route, Routes } from 'react-router-dom';
import { OverviewPage } from '../features/overview/OverviewPage';
import { PlaceholderPage } from './PlaceholderPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route index element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<OverviewPage />} />
      <Route path="/demo" element={<PlaceholderPage section="demo" />} />
      <Route path="/validation" element={<PlaceholderPage section="validation" />} />
      <Route path="/operations" element={<PlaceholderPage section="operations" />} />
      <Route path="/evidence" element={<PlaceholderPage section="evidence" />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
