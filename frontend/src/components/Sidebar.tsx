import { NavLink } from "react-router-dom";

interface NavItem {
  to: string;
  label: string;
  glyph: string;
}

const NAV: NavItem[] = [
  { to: "/setup", label: "Setup", glyph: "S" },
  { to: "/repos", label: "Repos", glyph: "R" },
  { to: "/runs", label: "Runs", glyph: "T" },
  { to: "/findings", label: "Findings", glyph: "F" },
  { to: "/chains", label: "Chains", glyph: "C" },
  { to: "/quarantine", label: "Quarantine", glyph: "Q" },
  { to: "/settings", label: "Settings", glyph: "⚙" },
];

export function Sidebar() {
  return (
    <aside className="app-layout__sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <span className="sidebar__brand-mark" aria-hidden="true" />
        <span className="sidebar__brand-name">nyx-agent</span>
      </div>
      <nav className="sidebar__nav">
        {NAV.map((item) => (
          <NavLink key={item.to} to={item.to} className="sidebar__link">
            <span className="sidebar__link-glyph" aria-hidden="true">
              {item.glyph}
            </span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__footer">v0.1.0</div>
    </aside>
  );
}
