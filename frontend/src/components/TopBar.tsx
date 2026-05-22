import { useLocation } from "react-router-dom";

const TITLE_BY_PATH: Record<string, string> = {
  "/setup": "Setup",
  "/projects": "Projects",
  "/runs": "Pentest Runs",
  "/vulnerabilities": "Vulnerabilities",
  "/findings": "Legacy Findings",
  "/chains": "Raw Chains",
  "/quarantine": "Quarantine",
  "/settings": "Settings",
};

export function TopBar() {
  const { pathname } = useLocation();
  const title =
    TITLE_BY_PATH[pathname] ??
    (pathname.startsWith("/projects/")
      ? "Project"
      : pathname.startsWith("/runs/")
        ? "Pentest Run"
        : pathname.startsWith("/chains/")
          ? "Chain"
          : "Nyctos");

  return (
    <header className="app-layout__topbar">
      <nav className="breadcrumbs" aria-label="Breadcrumb">
        <span className="breadcrumb-current" aria-current="page">
          {title}
        </span>
      </nav>
    </header>
  );
}
