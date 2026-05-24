import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { type CreateProjectRequest, type ProjectRecord, useCreateProject } from "@/api/client";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import {
  emptyRuntimeProfileDraft,
  launchProfileDraftError,
  launchProfileFromDraft,
  ProjectRuntimeProfileForm,
  type RuntimeProfileDraft,
  runtimeProfileFromDraft,
} from "./ProjectRuntimeProfileForm";

interface FormValues {
  name: string;
  description: string;
}

const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

const schema = z.object({
  name: z
    .string()
    .min(1, "Name is required")
    .max(64)
    .regex(NAME_PATTERN, "Letters, numbers, dot, dash, underscore (max 64 chars)"),
  description: z.string().max(512),
});

interface Props {
  onClose: () => void;
  onAdded: (project: ProjectRecord) => void;
}

export function ProjectAddModal({ onClose, onAdded }: Props) {
  const create = useCreateProject();
  const firstInputRef = useRef<HTMLInputElement | null>(null);
  const [profileDraft, setProfileDraft] = useState<RuntimeProfileDraft>(() =>
    emptyRuntimeProfileDraft(),
  );

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    mode: "onSubmit",
    reValidateMode: "onBlur",
    defaultValues: { name: "", description: "" },
  });
  const { register, handleSubmit, formState, setError, reset } = form;
  const nameReg = register("name");

  useEffect(() => {
    firstInputRef.current?.focus();
  }, []);

  async function onSubmit(values: FormValues) {
    const body: CreateProjectRequest = { name: values.name.trim() };
    const description = values.description.trim();
    if (description) body.description = description;
    const profileError = launchProfileDraftError(profileDraft);
    if (profileError) {
      setError("root", { type: "profile", message: profileError });
      return;
    }
    const launchProfile = launchProfileFromDraft(profileDraft);
    if (launchProfile) {
      body.default_launch_profile = launchProfile;
      if (launchProfile.target_urls[0]) body.target_base_url = launchProfile.target_urls[0];
    }
    const runtimeProfile = runtimeProfileFromDraft(profileDraft);
    if (runtimeProfile) {
      body.runtime_profile = runtimeProfile;
      if (runtimeProfile.target_base_url) body.target_base_url = runtimeProfile.target_base_url;
    }
    try {
      const row = await create.mutateAsync(body);
      reset();
      setProfileDraft(emptyRuntimeProfileDraft());
      onAdded(row);
    } catch (err) {
      setError("root", { type: "server", message: String(err) });
    }
  }

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="project-add-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal modal--wide">
        <header className="modal__header">
          <h2 id="project-add-title" className="modal__title">
            New project
          </h2>
          <button type="button" className="modal__close" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </header>

        <div className="modal__body">
          <form
            id="project-add-form"
            className="repo-add__form"
            onSubmit={handleSubmit(onSubmit)}
            noValidate
          >
            <div className="project-add-basic">
              <div className="setup-field">
                <label htmlFor="project-name">Name</label>
                <input
                  id="project-name"
                  type="text"
                  autoComplete="off"
                  placeholder="acme-app"
                  name={nameReg.name}
                  onBlur={nameReg.onBlur}
                  onChange={nameReg.onChange}
                  ref={(el) => {
                    nameReg.ref(el);
                    firstInputRef.current = el;
                  }}
                />
                <FieldError msg={formState.errors.name?.message} />
              </div>

              <div className="setup-field">
                <label htmlFor="project-description">Description</label>
                <input
                  id="project-description"
                  type="text"
                  autoComplete="off"
                  placeholder="Acme web product"
                  {...register("description")}
                />
                <FieldError msg={formState.errors.description?.message} />
              </div>
            </div>

            <ProjectRuntimeProfileForm value={profileDraft} onChange={setProfileDraft} />

            {formState.errors.root && (
              <p className="repo-add__error" role="alert">
                {formState.errors.root.message}
              </p>
            )}
          </form>
        </div>

        <footer className="modal__footer">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="project-add-form"
            variant="primary"
            disabled={create.isPending}
          >
            {create.isPending ? <Spinner /> : "Create project"}
          </Button>
        </footer>
      </div>
    </div>
  );
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return (
    <p className="repo-add__field-error" role="alert">
      {msg}
    </p>
  );
}
