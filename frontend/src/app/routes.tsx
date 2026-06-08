import { Navigate, Route, Routes } from 'react-router-dom';
import { OverviewPage } from '../features/overview/OverviewPage';
import { DemoConsolePage } from '../features/demo/DemoConsolePage';
import { EvidencePage } from '../features/evidence/EvidencePage';
import { OperationsPage } from '../features/operations/OperationsPage';
import { ValidationDetailPage } from '../features/validation/ValidationDetailPage';
import { PlaceholderPage } from './PlaceholderPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route index element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<OverviewPage />} />
      <Route path="/demo" element={<DemoConsolePage />} />
      <Route path="/validation" element={<ValidationDetailPage />} />
      <Route path="/operations" element={<OperationsPage />} />
      <Route path="/evidence" element={<EvidencePage />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
