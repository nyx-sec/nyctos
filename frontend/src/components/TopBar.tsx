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
      ? projectScopedTitle(pathname)
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

function projectScopedTitle(pathname: string): string {
  if (/^\/projects\/[^/]+\/runs\/[^/]+/.test(pathname)) return "Pentest Run";
  if (/^\/projects\/[^/]+\/runs/.test(pathname)) return "Pentest Runs";
  if (/^\/projects\/[^/]+\/vulnerabilities/.test(pathname)) return "Vulnerabilities";
  if (/^\/projects\/[^/]+\/repos/.test(pathname)) return "Repositories";
  if (/^\/projects\/[^/]+\/environments/.test(pathname)) return "Environments";
  if (/^\/projects\/[^/]+\/integrations/.test(pathname)) return "Integrations";
  return "Project";
}
