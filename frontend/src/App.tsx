import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { Card } from "@/components/Card";
import { Spinner } from "@/components/Spinner";
import { FindingList } from "@/pages/Findings";
import { Placeholder } from "@/pages/Placeholder";
import { RepoList } from "@/pages/Repos";
import { LiveScanView } from "@/pages/Runs";
import { SetupWizard } from "@/pages/Setup";
import { useSetupStatus } from "@/api/client";

export function App() {
  const status = useSetupStatus();
  const location = useLocation();

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
  // wizard writes nyx-agent.toml. After completion, /setup itself
  // bounces back to /repos so the operator does not accidentally
  // re-run the wizard.
  if (!complete && !onSetup) {
    return <Navigate to="/setup" replace />;
  }
  if (complete && onSetup) {
    return <Navigate to="/repos" replace />;
  }

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/repos" replace />} />
        <Route path="/setup" element={<SetupWizard />} />
        <Route path="/repos" element={<RepoList />} />
        <Route path="/runs" element={<Placeholder />} />
        <Route path="/runs/:runId" element={<LiveScanView />} />
        <Route path="/findings" element={<FindingList />} />
        <Route path="/chains" element={<Placeholder />} />
        <Route path="/quarantine" element={<Placeholder />} />
        <Route path="/settings" element={<Placeholder />} />
        <Route path="*" element={<Navigate to="/repos" replace />} />
      </Routes>
    </AppLayout>
  );
}
