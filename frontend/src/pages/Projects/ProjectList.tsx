import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { type ProjectRecord, useProjects } from "@/api/client";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";
import { ProjectAddModal } from "./ProjectAddModal";

export function ProjectList() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const projects = useProjects();
  const { showToast } = useToast();
  const [showAdd, setShowAdd] = useState(false);
  const addRequested = params.get("new") === "1";
  const showAddModal = showAdd || addRequested;

  const rows = useMemo(() => projects.data ?? [], [projects.data]);
  const noneConfigured = !projects.isPending && rows.length === 0;
  const projectCount = projects.isPending
    ? "Loading projects..."
    : `${rows.length} ${rows.length === 1 ? "project" : "projects"}`;

  return (
    <>
      <PageShell>
        <PageHeader
          title="Projects"
          meta={projectCount}
          actions={
            <Button variant="primary" onClick={() => setShowAdd(true)}>
              New project
            </Button>
          }
        />

        <Card className="table-card">
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

          {noneConfigured && <EmptyState title="No projects yet" />}

          {rows.length > 0 && (
            <div className="table-scroll">
              <table className="repo-list__table data-table" aria-label="Configured projects">
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
            </div>
          )}
        </Card>
      </PageShell>

      {showAddModal && (
        <ProjectAddModal
          onClose={() => {
            setShowAdd(false);
            clearAddParam(params, setParams);
          }}
          onAdded={(project) => {
            setShowAdd(false);
            clearAddParam(params, setParams);
            showToast(`Created ${project.name}.`, { tone: "success" });
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
