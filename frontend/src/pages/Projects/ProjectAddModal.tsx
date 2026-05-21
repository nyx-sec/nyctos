import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useRef } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { type CreateProjectRequest, useCreateProject } from "@/api/client";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";

interface FormValues {
  name: string;
  description: string;
  target_base_url: string;
}

const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

const schema = z.object({
  name: z
    .string()
    .min(1, "Name is required")
    .max(64)
    .regex(NAME_PATTERN, "Letters, numbers, dot, dash, underscore (max 64 chars)"),
  description: z.string().max(512),
  target_base_url: z
    .string()
    .refine(
      (v) => v.trim().length === 0 || /^https?:\/\//.test(v.trim()),
      "Must start with http:// or https://",
    ),
});

interface Props {
  onClose: () => void;
  onAdded: (name: string) => void;
}

export function ProjectAddModal({ onClose, onAdded }: Props) {
  const create = useCreateProject();
  const firstInputRef = useRef<HTMLInputElement | null>(null);

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    mode: "onBlur",
    defaultValues: { name: "", description: "", target_base_url: "" },
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
    const target = values.target_base_url.trim();
    if (target) body.target_base_url = target;
    try {
      const row = await create.mutateAsync(body);
      reset();
      onAdded(row.name);
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
      <div className="modal">
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
              <label htmlFor="project-description">Description (optional)</label>
              <input
                id="project-description"
                type="text"
                autoComplete="off"
                placeholder="Acme web product"
                {...register("description")}
              />
              <FieldError msg={formState.errors.description?.message} />
            </div>

            <div className="setup-field">
              <label htmlFor="project-target">Target base URL (optional)</label>
              <input
                id="project-target"
                type="text"
                autoComplete="off"
                placeholder="http://localhost:3000"
                {...register("target_base_url")}
              />
              <p className="setup-hint">
                Used by the sandbox env-builder to point chains at the right origin when the project
                spans multiple repos.
              </p>
              <FieldError msg={formState.errors.target_base_url?.message} />
            </div>

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
