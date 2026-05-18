import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { Placeholder } from "@/pages/Placeholder";

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/repos" replace />} />
        <Route
          path="/setup"
          element={
            <Placeholder
              title="Setup"
              description="First-launch wizard lives here. Phase 09 wires it up."
            />
          }
        />
        <Route
          path="/repos"
          element={
            <Placeholder
              title="Repos"
              description="Configured repositories and scan triggers. Phase 10 wires it up."
            />
          }
        />
        <Route
          path="/runs"
          element={
            <Placeholder
              title="Runs"
              description="Recent scan runs and their outcomes."
            />
          }
        />
        <Route
          path="/findings"
          element={
            <Placeholder
              title="Findings"
              description="Findings browser and detail panel. Phase 11 wires it up."
            />
          }
        />
        <Route
          path="/chains"
          element={
            <Placeholder
              title="Chains"
              description="Cross-finding chains and reasoning traces."
            />
          }
        />
        <Route
          path="/quarantine"
          element={
            <Placeholder
              title="Quarantine"
              description="Findings parked for manual triage."
            />
          }
        />
        <Route
          path="/settings"
          element={
            <Placeholder
              title="Settings"
              description="Daemon configuration, API keys, and runtimes."
            />
          }
        />
        <Route path="*" element={<Navigate to="/repos" replace />} />
      </Routes>
    </AppLayout>
  );
}
