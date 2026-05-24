import type { FC } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { type ProjectRecord, useProjects } from "@/api/client";
import { useAdvancedMode } from "@/api/preferences";
import {
  ChainsIcon,
  EnvironmentsIcon,
  FindingsIcon,
  type IconProps,
  OverviewIcon,
  PlusIcon,
  QuarantineIcon,
  ReposIcon,
  RunsIcon,
  SettingsIcon,
  SetupIcon,
} from "./icons/Icons";

interface NavItem {
  to: string;
  label: string;
  Icon: FC<IconProps>;
  group: "primary" | "secondary" | "footer";
  /** Hidden unless the operator opts into Settings → Show advanced. */
  advanced?: boolean;
  end?: boolean;
  section?: string;
}

const SETUP_NAV: NavItem[] = [{ to: "/setup", label: "Setup", Icon: SetupIcon, group: "primary" }];

const GLOBAL_NAV: NavItem[] = [
  { to: "/runs", label: "Pentest Runs", Icon: RunsIcon, group: "primary" },
  { to: "/vulnerabilities", label: "Vulnerabilities", Icon: FindingsIcon, group: "primary" },
];

const SECONDARY_NAV: NavItem[] = [
  {
    to: "/findings",
    label: "Legacy Findings",
    Icon: FindingsIcon,
    group: "secondary",
    advanced: true,
  },
  { to: "/chains", label: "Raw Chains", Icon: ChainsIcon, group: "secondary", advanced: true },
  {
    to: "/quarantine",
    label: "Candidate Queue",
    Icon: QuarantineIcon,
    group: "secondary",
    advanced: true,
  },
];

const FOOTER_NAV: NavItem[] = [
  { to: "/settings", label: "Settings", Icon: SettingsIcon, group: "footer" },
];

function navLinkClass({ isActive }: { isActive: boolean }) {
  return `sidebar__link${isActive ? " active" : ""}`;
}

interface SidebarProps {
  setupComplete: boolean;
}

export function Sidebar({ setupComplete }: SidebarProps) {
  const [advanced] = useAdvancedMode();
  const { pathname } = useLocation();
  const activeProjectId = setupComplete ? projectIdFromPathname(pathname) : undefined;
  const primary = setupComplete
    ? activeProjectId
      ? scopedProjectNav(activeProjectId)
      : GLOBAL_NAV
    : SETUP_NAV;
  const secondary = setupComplete ? SECONDARY_NAV.filter((item) => !item.advanced || advanced) : [];

  return (
    <aside className="app-layout__sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <Link to="/projects" className="sidebar__brand-link" aria-label="Nyctos projects">
          <img src="/logo.png" alt="Nyctos" className="sidebar__brand-logo" />
        </Link>
      </div>
      {setupComplete && <ProjectSwitcher activeProjectId={activeProjectId} />}
      <nav className="sidebar__nav">
        {primary.map((item, idx) => (
          <NavItemLink
            key={item.to}
            item={item}
            showSection={Boolean(item.section && item.section !== primary[idx - 1]?.section)}
          />
        ))}
        {secondary.length > 0 && <span className="sidebar__nav-section">Triage</span>}
        {secondary.map((item) => (
          <NavLink key={item.to} to={item.to} className={navLinkClass}>
            <span className="sidebar__link-glyph" aria-hidden="true">
              <item.Icon />
            </span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__footer">
        {FOOTER_NAV.map((item) => (
          <NavLink key={item.to} to={item.to} className={navLinkClass}>
            <span className="sidebar__link-glyph" aria-hidden="true">
              <item.Icon />
            </span>
            <span>{item.label}</span>
          </NavLink>
        ))}
        <span className="sidebar__version">v0.1.0</span>
      </div>
    </aside>
  );
}

function NavItemLink({ item, showSection }: { item: NavItem; showSection?: boolean }) {
  return (
    <>
      {showSection && <span className="sidebar__nav-section">{item.section}</span>}
      <NavLink to={item.to} end={item.end} className={navLinkClass}>
        <span className="sidebar__link-glyph" aria-hidden="true">
          <item.Icon />
        </span>
        <span>{item.label}</span>
      </NavLink>
    </>
  );
}

function ProjectSwitcher({ activeProjectId }: { activeProjectId?: string }) {
  const projects = useProjects(true);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const rows = projects.data ?? [];
  const activeProject = rows.find((project) => project.id === activeProjectId);
  const activeLabel = activeProject?.name ?? (activeProjectId ? "Project" : "All projects");
  const activeInitial = initialForProject(activeProject);
  const selectValue = activeProjectId ?? "";
  const hasActiveOption =
    !activeProjectId || rows.some((project) => project.id === activeProjectId);

  return (
    <div className="sidebar__workspace">
      <div className="sidebar__workspace-current">
        <Link
          to={activeProjectId ? `/projects/${encodeURIComponent(activeProjectId)}` : "/projects"}
          className="sidebar__workspace-avatar"
          aria-label={activeProjectId ? `${activeLabel} overview` : "All projects"}
        >
          {activeInitial}
        </Link>
        <label className="sidebar__workspace-label" htmlFor="project-switcher">
          Project
        </label>
        <select
          id="project-switcher"
          className="sidebar__workspace-select"
          value={selectValue}
          onChange={(event) => {
            const nextProjectId = event.target.value || undefined;
            navigate(nextProjectId ? pathForProjectSwitch(pathname, nextProjectId) : "/projects");
          }}
          disabled={projects.isPending}
          aria-label="Switch project"
        >
          <option value="">All projects</option>
          {!hasActiveOption && <option value={activeProjectId}>{activeLabel}</option>}
          {rows.map((project) => (
            <option key={project.id} value={project.id}>
              {project.name}
            </option>
          ))}
        </select>
        <Link className="sidebar__new-project" to="/projects?new=1" aria-label="Create project">
          <PlusIcon size={16} />
        </Link>
      </div>
    </div>
  );
}

function scopedProjectNav(projectId: string): NavItem[] {
  const encoded = encodeURIComponent(projectId);
  return [
    {
      to: `/projects/${encoded}`,
      label: "Overview",
      Icon: OverviewIcon,
      group: "primary",
      end: true,
    },
    {
      to: `/projects/${encoded}/runs`,
      label: "Pentest Runs",
      Icon: RunsIcon,
      group: "primary",
    },
    {
      to: `/projects/${encoded}/vulnerabilities`,
      label: "Vulnerabilities",
      Icon: FindingsIcon,
      group: "primary",
    },
    {
      to: `/projects/${encoded}/repos`,
      label: "Repositories",
      Icon: ReposIcon,
      group: "primary",
      section: "Sources",
    },
    {
      to: `/projects/${encoded}/environments`,
      label: "Environments",
      Icon: EnvironmentsIcon,
      group: "primary",
      section: "Sources",
    },
  ];
}

function projectIdFromPathname(pathname: string): string | undefined {
  const match = pathname.match(/^\/projects\/([^/]+)/);
  if (!match) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

function pathForProjectSwitch(pathname: string, projectId: string): string {
  const encoded = encodeURIComponent(projectId);
  if (/^\/projects\/[^/]+\/runs(\/|$)/.test(pathname) || pathname.startsWith("/runs")) {
    return `/projects/${encoded}/runs`;
  }
  if (/^\/projects\/[^/]+\/repos(\/|$)/.test(pathname)) {
    return `/projects/${encoded}/repos`;
  }
  if (/^\/projects\/[^/]+\/environments(\/|$)/.test(pathname)) {
    return `/projects/${encoded}/environments`;
  }
  if (
    /^\/projects\/[^/]+\/vulnerabilities(\/|$)/.test(pathname) ||
    pathname.startsWith("/vulnerabilities")
  ) {
    return `/projects/${encoded}/vulnerabilities`;
  }
  return `/projects/${encoded}`;
}

function initialForProject(project: ProjectRecord | undefined): string {
  const name = project?.name.trim();
  return name ? name.slice(0, 1).toUpperCase() : "N";
}
