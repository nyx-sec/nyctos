import { type FC, useEffect, useRef, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { type ProjectRecord, useProjects } from "@/api/client";
import { useActiveProjectPreference, useAdvancedMode } from "@/api/preferences";
import {
  ChainsIcon,
  EnvironmentsIcon,
  FindingsIcon,
  type IconProps,
  IntegrationsIcon,
  OverviewIcon,
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

const SECONDARY_NAV: Omit<NavItem, "to">[] = [
  {
    label: "Legacy Findings",
    Icon: FindingsIcon,
    group: "secondary",
    advanced: true,
  },
  { label: "Raw Chains", Icon: ChainsIcon, group: "secondary", advanced: true },
  {
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
  const pathProjectId = setupComplete ? projectIdFromPathname(pathname) : undefined;
  const [rememberedProjectId, setRememberedProjectId] = useActiveProjectPreference();
  const activeProjectId = setupComplete
    ? (pathProjectId ??
      (usesRememberedProjectSelection(pathname) ? rememberedProjectId : undefined))
    : undefined;
  const primary = setupComplete
    ? activeProjectId
      ? scopedProjectNav(activeProjectId)
      : GLOBAL_NAV
    : SETUP_NAV;
  const secondary = setupComplete
    ? scopedSecondaryNav(activeProjectId).filter((item) => !item.advanced || advanced)
    : [];

  useEffect(() => {
    if (!setupComplete) return;
    if (pathProjectId) {
      setRememberedProjectId(pathProjectId);
    } else if (pathname === "/projects") {
      setRememberedProjectId(undefined);
    }
  }, [pathProjectId, pathname, setupComplete, setRememberedProjectId]);

  return (
    <aside className="app-layout__sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <Link to="/projects" className="sidebar__brand-link" aria-label="Nyctos projects">
          <img src="/logo.png" alt="Nyctos" className="sidebar__brand-logo" />
        </Link>
      </div>
      {setupComplete && (
        <ProjectSwitcher
          activeProjectId={activeProjectId}
          rememberProjectId={setRememberedProjectId}
        />
      )}
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

function ProjectSwitcher({
  activeProjectId,
  rememberProjectId,
}: {
  activeProjectId?: string;
  rememberProjectId: (projectId: string | undefined) => void;
}) {
  const projects = useProjects(true);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(false);
  const rows = projects.data ?? [];
  const activeProject = rows.find((project) => project.id === activeProjectId);
  const activeLabel = activeProject?.name ?? (activeProjectId ? "Project" : "All projects");
  const activeInitial = initialForProject(activeProject);
  const hasActiveOption =
    !activeProjectId || rows.some((project) => project.id === activeProjectId);

  useEffect(() => {
    function onPointerDown(event: PointerEvent) {
      if (!menuRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  function selectProject(nextProjectId?: string) {
    setOpen(false);
    rememberProjectId(nextProjectId);
    navigate(nextProjectId ? pathForProjectSwitch(pathname, nextProjectId) : "/projects");
  }

  function createProject() {
    setOpen(false);
    navigate("/projects?new=1");
  }

  return (
    <div className="sidebar__workspace">
      <div className="sidebar__workspace-current" ref={menuRef}>
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
        <button
          id="project-switcher"
          type="button"
          className="sidebar__workspace-trigger"
          disabled={projects.isPending}
          role="combobox"
          aria-controls="project-switcher-menu"
          aria-expanded={open}
          aria-label="Switch project"
          onClick={() => setOpen((cur) => !cur)}
        >
          <span>{activeLabel}</span>
          <span className="sidebar__workspace-caret" aria-hidden="true" />
        </button>
        {open && (
          <div id="project-switcher-menu" className="sidebar__workspace-menu" role="listbox">
            <button
              type="button"
              className="sidebar__workspace-option"
              role="option"
              aria-selected={!activeProjectId}
              onClick={() => selectProject()}
            >
              <span className="sidebar__workspace-check" aria-hidden="true">
                {!activeProjectId ? "✓" : ""}
              </span>
              <span>All projects</span>
            </button>
            {!hasActiveOption && (
              <button
                type="button"
                className="sidebar__workspace-option"
                role="option"
                aria-selected
                onClick={() => selectProject(activeProjectId)}
              >
                <span className="sidebar__workspace-check" aria-hidden="true">
                  ✓
                </span>
                <span>{activeLabel}</span>
              </button>
            )}
            {rows.map((project) => (
              <button
                key={project.id}
                type="button"
                className="sidebar__workspace-option"
                role="option"
                aria-selected={project.id === activeProjectId}
                onClick={() => selectProject(project.id)}
              >
                <span className="sidebar__workspace-check" aria-hidden="true">
                  {project.id === activeProjectId ? "✓" : ""}
                </span>
                <span>{project.name}</span>
              </button>
            ))}
            <div className="sidebar__workspace-menu-separator" />
            <button type="button" className="sidebar__workspace-action" onClick={createProject}>
              New project
            </button>
          </div>
        )}
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
    {
      to: `/projects/${encoded}/integrations`,
      label: "Integrations",
      Icon: IntegrationsIcon,
      group: "primary",
      section: "External",
    },
  ];
}

function scopedSecondaryNav(projectId: string | undefined): NavItem[] {
  const prefix = projectId ? `/projects/${encodeURIComponent(projectId)}` : "";
  return SECONDARY_NAV.map((item) => ({
    ...item,
    to: `${prefix}${secondaryPathForLabel(item.label)}`,
  }));
}

function secondaryPathForLabel(label: string): string {
  switch (label) {
    case "Legacy Findings":
      return "/findings";
    case "Raw Chains":
      return "/chains";
    case "Candidate Queue":
      return "/quarantine";
    default:
      return "/findings";
  }
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

function usesRememberedProjectSelection(pathname: string): boolean {
  return pathname !== "/projects" && pathname !== "/setup";
}

function pathForProjectSwitch(pathname: string, projectId: string): string {
  const encoded = encodeURIComponent(projectId);
  if (pathname === "/settings") {
    return "/settings";
  }
  if (/^\/projects\/[^/]+\/runs(\/|$)/.test(pathname) || pathname.startsWith("/runs")) {
    return `/projects/${encoded}/runs`;
  }
  if (/^\/projects\/[^/]+\/repos(\/|$)/.test(pathname)) {
    return `/projects/${encoded}/repos`;
  }
  if (/^\/projects\/[^/]+\/environments(\/|$)/.test(pathname)) {
    return `/projects/${encoded}/environments`;
  }
  if (/^\/projects\/[^/]+\/integrations(\/|$)/.test(pathname)) {
    return `/projects/${encoded}/integrations`;
  }
  if (
    /^\/projects\/[^/]+\/vulnerabilities(\/|$)/.test(pathname) ||
    pathname.startsWith("/vulnerabilities")
  ) {
    return `/projects/${encoded}/vulnerabilities`;
  }
  if (/^\/projects\/[^/]+\/findings(\/|$)/.test(pathname) || pathname.startsWith("/findings")) {
    return `/projects/${encoded}/findings`;
  }
  if (/^\/projects\/[^/]+\/chains(\/|$)/.test(pathname) || pathname.startsWith("/chains")) {
    return `/projects/${encoded}/chains`;
  }
  if (/^\/projects\/[^/]+\/quarantine(\/|$)/.test(pathname) || pathname.startsWith("/quarantine")) {
    return `/projects/${encoded}/quarantine`;
  }
  return `/projects/${encoded}`;
}

function initialForProject(project: ProjectRecord | undefined): string {
  const name = project?.name.trim();
  return name ? name.slice(0, 1).toUpperCase() : "N";
}
