import { ReactNode } from "react";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";

interface PlaceholderProps {
  title: string;
  description: ReactNode;
  body?: ReactNode;
}

export function Placeholder({ title, description, body }: PlaceholderProps) {
  return (
    <div>
      <div className="page__heading">
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <Card>
        {body ?? (
          <EmptyState
            title="Coming up"
            body="This view is scaffolded by Phase 08 and will gain real content in a later phase."
          />
        )}
      </Card>
    </div>
  );
}
