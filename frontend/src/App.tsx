import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useSetupStatus } from "@/api/client";
import { useAdvancedMode } from "@/api/preferences";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/Card";
import { Spinner } from "@/components/Spinner";
import { ChainDetail, ChainList } from "@/pages/Chains";
import { FindingList } from "@/pages/Findings";
import { Placeholder } from "@/pages/Placeholder";
import { ProjectDetail, ProjectList } from "@/pages/Projects";
import { QuarantineList } from "@/pages/Quarantine";
import { LiveScanView } from "@/pages/Runs";
import { Settings } from "@/pages/Settings";
import { SetupWizard } from "@/pages/Setup";

export function App() {
  const status = useSetupStatus();
  const location = useLocation();
  const [advanced] = useAdvancedMode();

  if (status.isPending) {
    return (
      <AppLayout>
        <Card>
          <div style={{ padding: 40, textAlign: "center" }}>
            <Spinner size="lg" />
          </div>
        </Card>
      </AppLayout>
    );
  }

  const complete = status.data?.complete ?? false;
  const onSetup = location.pathname === "/setup";

  // Fresh-install gate: every route bounces to /setup until the
  // wizard writes nyctos.toml. After completion, /setup itself
  // bounces back to /projects so the operator does not accidentally
  // re-run the wizard.
  if (!complete && !onSetup) {
    return <Navigate to="/setup" replace />;
  }
  if (complete && onSetup) {
    return <Navigate to="/projects" replace />;
  }

  return (
    <AppLayout setupComplete={complete}>
      <Routes>
        <Route path="/" element={<Navigate to="/projects" replace />} />
        <Route path="/setup" element={<SetupWizard />} />
        <Route path="/projects" element={<ProjectList />} />
        <Route path="/projects/:projectId" element={<ProjectDetail />} />
        <Route path="/runs" element={<Placeholder />} />
        <Route path="/runs/:runId" element={<LiveScanView />} />
        <Route path="/findings" element={<FindingList />} />
        <Route path="/chains" element={<ChainList />} />
        <Route path="/chains/:chainId" element={<ChainDetail />} />
        <Route
          path="/quarantine"
          element={advanced ? <QuarantineList /> : <Navigate to="/settings" replace />}
        />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Routes>
    </AppLayout>
  );
}
