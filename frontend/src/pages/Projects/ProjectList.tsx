import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { type ProjectRecord, useProjects } from "@/api/client";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import { ProjectAddModal } from "./ProjectAddModal";

export function ProjectList() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const projects = useProjects();
  const [showAdd, setShowAdd] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const addRequested = params.get("new") === "1";
  const showAddModal = showAdd || addRequested;

  const rows = useMemo(() => projects.data ?? [], [projects.data]);
  const noneConfigured = !projects.isPending && rows.length === 0;
  const projectCount = projects.isPending
    ? "Loading projects..."
    : `${rows.length} ${rows.length === 1 ? "project" : "projects"}`;

  return (
    <>
      <div className="page-stack">
        <div className="page-toolbar">
          <p className="page-toolbar__meta">{projectCount}</p>
          <Button variant="primary" onClick={() => setShowAdd(true)}>
            New project
          </Button>
        </div>

        <Card className="table-card">
          {banner && (
            <div className="repo-list__banner" role="status" aria-live="polite">
              {banner}
            </div>
          )}

          {projects.isPending && (
            <div className="repo-list__pending">
              <Spinner /> Loading projects...
            </div>
          )}

          {projects.error && (
            <p className="repo-list__error" role="alert">
              Failed to load projects: {String(projects.error)}
            </p>
          )}

          {noneConfigured && (
            <EmptyState title="No projects yet" body="Create one project to group related repos." />
          )}

          {rows.length > 0 && (
            <table className="repo-list__table" aria-label="Configured projects">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Description</th>
                  <th scope="col">App URL</th>
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
      </div>

      {showAddModal && (
        <ProjectAddModal
          onClose={() => {
            setShowAdd(false);
            clearAddParam(params, setParams);
          }}
          onAdded={(project) => {
            setShowAdd(false);
            clearAddParam(params, setParams);
            setBanner(`Created ${project.name}.`);
            navigate(`/projects/${encodeURIComponent(project.id)}`);
          }}
        />
      )}
    </>
  );
}

function clearAddParam(params: URLSearchParams, setParams: ReturnType<typeof useSearchParams>[1]) {
  if (params.get("new") !== "1") return;
  const next = new URLSearchParams(params);
  next.delete("new");
  setParams(next, { replace: true });
}

function ProjectRow({ project }: { project: ProjectRecord }) {
  const appUrl = project.default_launch_profile?.target_urls[0] ?? project.target_base_url;
  return (
    <tr>
      <td>
        <Link className="repo-list__name" to={`/projects/${encodeURIComponent(project.id)}`}>
          {project.name}
        </Link>
      </td>
      <td className="repo-list__source">{project.description ?? "-"}</td>
      <td className="repo-list__source">{appUrl ? <code>{appUrl}</code> : "-"}</td>
      <td>
        <time className="repo-list__last-scan">
          {new Date(project.updated_at).toLocaleString()}
        </time>
      </td>
    </tr>
  );
}
