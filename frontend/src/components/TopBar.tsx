import { useLocation } from "react-router-dom";

const TITLE_BY_PATH: Record<string, string> = {
  "/setup": "Setup",
  "/repos": "Repos",
  "/runs": "Runs",
  "/findings": "Findings",
  "/chains": "Chains",
  "/quarantine": "Quarantine",
  "/settings": "Settings",
};

export function TopBar() {
  const { pathname } = useLocation();
  const title = TITLE_BY_PATH[pathname] ?? "Nyx";

  return (
    <header className="app-layout__topbar">
      <nav className="breadcrumbs" aria-label="Breadcrumb">
        <span className="breadcrumb-current" aria-current="page">
          {title}
        </span>
      </nav>
      <div className="topbar__spacer" />
      <div className="topbar__status">
        <span className="topbar__status-dot" aria-hidden="true" />
        <span>Daemon ready</span>
      </div>
    </header>
  );
}
