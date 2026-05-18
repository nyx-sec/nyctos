import { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export interface AppLayoutProps {
  children: ReactNode;
  setupComplete?: boolean;
}

export function AppLayout({ children, setupComplete = true }: AppLayoutProps) {
  return (
    <div className="app-layout">
      <Sidebar setupComplete={setupComplete} />
      <TopBar />
      <main className="app-layout__main">{children}</main>
    </div>
  );
}
