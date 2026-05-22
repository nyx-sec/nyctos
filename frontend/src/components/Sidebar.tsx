import type { FC } from "react";
import { NavLink } from "react-router-dom";
import { useAdvancedMode } from "@/api/preferences";
import {
  ChainsIcon,
  FindingsIcon,
  type IconProps,
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
}

const NAV: NavItem[] = [
  { to: "/setup", label: "Setup", Icon: SetupIcon, group: "primary" },
  { to: "/projects", label: "Projects", Icon: ReposIcon, group: "primary" },
  { to: "/runs", label: "Pentest Runs", Icon: RunsIcon, group: "primary" },
  { to: "/vulnerabilities", label: "Vulnerabilities", Icon: FindingsIcon, group: "primary" },
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
  const visible = NAV.filter((item) => {
    if (setupComplete && item.to === "/setup") return false;
    return !item.advanced || advanced;
  });
  const primary = visible.filter((item) => item.group === "primary");
  const secondary = visible.filter((item) => item.group === "secondary");
  const footer = visible.filter((item) => item.group === "footer");

  return (
    <aside className="app-layout__sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <img src="/logo.png" alt="Nyctos" className="sidebar__brand-logo" />
      </div>
      <nav className="sidebar__nav">
        {primary.map((item) => (
          <NavLink key={item.to} to={item.to} className="sidebar__link">
            <span className="sidebar__link-glyph" aria-hidden="true">
              <item.Icon />
            </span>
            <span>{item.label}</span>
          </NavLink>
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
        {footer.map((item) => (
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
