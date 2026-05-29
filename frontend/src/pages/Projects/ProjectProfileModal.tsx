import { useMemo, useState } from "react";
import type { ProjectRecord } from "@/api/client";
import { usePatchDefaultLaunchProfile, usePatchProject } from "@/api/client";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import {
  launchProfileDraftError,
  launchProfileFromDraft,
  ProjectRuntimeProfileForm,
  profileDraftFromLaunchAndRuntime,
  type RuntimeProfileDraft,
  runtimeProfileFromDraft,
} from "./ProjectRuntimeProfileForm";

interface Props {
  project: ProjectRecord;
  onClose: () => void;
  onSaved: (project: ProjectRecord) => void;
}

export function ProjectProfileModal({ project, onClose, onSaved }: Props) {
  const patchProfile = usePatchDefaultLaunchProfile(project.id);
  const patchProject = usePatchProject();
  const initialDraft = useMemo(() => profileDraftFromProject(project), [project]);
  const [draft, setDraft] = useState<RuntimeProfileDraft>(initialDraft);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit() {
    setError(null);
    const profileError = launchProfileDraftError(draft);
    if (profileError) {
      setError(profileError);
      return;
    }
    if (!draft.target_base_url.trim()) {
      setError("Add an app URL before saving the launch profile.");
      return;
    }
    const launchProfile = launchProfileFromDraft(draft);
    const runtimeProfile = runtimeProfileFromDraft(draft);
    if (!launchProfile) {
      setError("Add an app URL before saving the launch profile.");
      return;
    }
    try {
      await patchProfile.mutateAsync(launchProfile);
      const updated = await patchProject.mutateAsync({
        id: project.id,
        patch: { runtime_profile: runtimeProfile ?? null },
      });
      onSaved(updated);
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="project-profile-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal modal--wide">
        <header className="modal__header">
          <h2 id="project-profile-title" className="modal__title">
            Launch profile
          </h2>
          <button type="button" className="modal__close" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </header>

        <div className="modal__body">
          <ProjectRuntimeProfileForm value={draft} onChange={setDraft} projectId={project.id} />
          {error && (
            <p className="repo-add__error" role="alert">
              {error}
            </p>
          )}
        </div>

        <footer className="modal__footer">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={onSubmit}
            disabled={patchProfile.isPending || patchProject.isPending}
          >
            {patchProfile.isPending || patchProject.isPending ? <Spinner /> : "Save profile"}
          </Button>
        </footer>
      </div>
    </div>
  );
}

function profileDraftFromProject(project: ProjectRecord): RuntimeProfileDraft {
  return profileDraftFromLaunchAndRuntime(
    project.default_launch_profile,
    project.runtime_profile,
    project.target_base_url ?? "",
  );
}
