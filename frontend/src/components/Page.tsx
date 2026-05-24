import { type HTMLAttributes, type ReactNode } from "react";

export type PageShellSize = "default" | "wide" | "narrow";

export interface PageShellProps extends HTMLAttributes<HTMLDivElement> {
  size?: PageShellSize;
}

export function PageShell({ size = "default", className, ...rest }: PageShellProps) {
  const classes = ["page-shell", size !== "default" ? `page-shell--${size}` : "", className]
    .filter(Boolean)
    .join(" ");
  return <div className={classes} {...rest} />;
}

export interface PageHeaderProps extends Omit<HTMLAttributes<HTMLElement>, "title"> {
  eyebrow?: ReactNode;
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ eyebrow, title, meta, actions, className, ...rest }: PageHeaderProps) {
  const classes = ["page-header", className].filter(Boolean).join(" ");
  return (
    <header className={classes} {...rest}>
      <div className="page-header__copy">
        {eyebrow && <div className="page-header__eyebrow">{eyebrow}</div>}
        <h1 className="page-header__title">{title}</h1>
        {meta && <p className="page-header__meta">{meta}</p>}
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  );
}
