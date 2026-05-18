import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import { useProjects, type ProjectRecord } from "@/api/client";
import { ProjectAddModal } from "./ProjectAddModal";

export function ProjectList() {
  const projects = useProjects();
  const [showAdd, setShowAdd] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);

  const rows = useMemo(() => projects.data ?? [], [projects.data]);
  const noneConfigured = !projects.isPending && rows.length === 0;

  return (
    <>
      <Card
        title="Projects"
        subtitle="A project groups the repos that compose one product (backend + frontend + infra)."
        actions={
          <Button variant="primary" onClick={() => setShowAdd(true)}>
            New project
          </Button>
        }
      >
        {banner && (
          <div className="repo-list__banner" role="status" aria-live="polite">
            {banner}
          </div>
        )}

        {projects.isPending && (
          <div className="repo-list__pending">
            <Spinner /> Loading projects…
          </div>
        )}

        {projects.error && (
          <p className="repo-list__error" role="alert">
            Failed to load projects: {String(projects.error)}
          </p>
        )}

        {noneConfigured && (
          <EmptyState
            title="No projects yet"
            body="Create the first one to group repos under it."
            actions={
              <Button variant="primary" onClick={() => setShowAdd(true)}>
                New project
              </Button>
            }
          />
        )}

        {rows.length > 0 && (
          <table className="repo-list__table" aria-label="Configured projects">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Description</th>
                <th scope="col">Target base URL</th>
                <th scope="col">Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <ProjectRow key={p.id} project={p} />
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {showAdd && (
        <ProjectAddModal
          onClose={() => setShowAdd(false)}
          onAdded={(name) => {
            setShowAdd(false);
            setBanner(`Created ${name}. Open it to add repos.`);
          }}
        />
      )}
    </>
  );
}

function ProjectRow({ project }: { project: ProjectRecord }) {
  return (
    <tr>
      <td>
        <Link className="repo-list__name" to={`/projects/${encodeURIComponent(project.id)}`}>
          {project.name}
        </Link>
      </td>
      <td className="repo-list__source">{project.description ?? "—"}</td>
      <td className="repo-list__source">
        {project.target_base_url ? <code>{project.target_base_url}</code> : "—"}
      </td>
      <td>
        <time className="repo-list__last-scan">
          {new Date(project.updated_at).toLocaleString()}
        </time>
      </td>
    </tr>
  );
}
