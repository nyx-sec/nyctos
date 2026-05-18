import { ReactNode } from "react";

export interface EmptyStateProps {
  title: ReactNode;
  body?: ReactNode;
  actions?: ReactNode;
}

export function EmptyState({ title, body, actions }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <h3 className="empty-state__title">{title}</h3>
      {body && <p className="empty-state__body">{body}</p>}
      {actions}
    </div>
  );
}
