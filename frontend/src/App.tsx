import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { Placeholder } from "@/pages/Placeholder";

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/repos" replace />} />
        <Route path="/setup" element={<Placeholder />} />
        <Route path="/repos" element={<Placeholder />} />
        <Route path="/runs" element={<Placeholder />} />
        <Route path="/findings" element={<Placeholder />} />
        <Route path="/chains" element={<Placeholder />} />
        <Route path="/quarantine" element={<Placeholder />} />
        <Route path="/settings" element={<Placeholder />} />
        <Route path="*" element={<Navigate to="/repos" replace />} />
      </Routes>
    </AppLayout>
  );
}
