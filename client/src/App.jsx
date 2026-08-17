import { Navigate, Route, Routes } from 'react-router-dom';
import { Header } from './components/Header.jsx';
import { DashboardPage } from './pages/DashboardPage.jsx';
import { HistoryPage } from './pages/HistoryPage.jsx';
import { ScanViewPage } from './pages/ScanViewPage.jsx';
import { AboutPage } from './pages/AboutPage.jsx';

export default function App() {
  return (
    <div className="min-h-screen bg-surface-0">
      <Header />
      <main className="mx-auto max-w-[1400px] px-6 py-6">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/scans/:id" element={<ScanViewPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="mx-auto max-w-[1400px] px-6 pb-8 pt-2">
        <p className="text-[11px] text-ink-muted">
          Authorized security testing only. Scan history is stored in this browser&apos;s localStorage and is never
          uploaded.
        </p>
      </footer>
    </div>
  );
}
