import { ReactNode } from "react";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";

interface PlaceholderProps {
  body?: ReactNode;
}

export function Placeholder({ body }: PlaceholderProps) {
  return (
    <Card>
      {body ?? (
        <EmptyState
          title="Coming up"
          body="This view is scaffolded by Phase 08 and will gain real content in a later phase."
        />
      )}
    </Card>
  );
}
