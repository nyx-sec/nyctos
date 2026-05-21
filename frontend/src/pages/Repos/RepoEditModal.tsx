import { useEffect, useMemo, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import {
  usePatchProjectRepo,
  type PatchRepoRequest,
  type RepoRecord,
} from "@/api/client";

type Tab = "url" | "path";

interface FormValues {
  source_url_or_path: string;
  branch: string;
  auth_ref: string;
}

const GIT_AUTH_PATTERN = /^(ssh-key|token-env|gh-app):[^:].*$/;

function buildSchema(tab: Tab) {
  const base = z.object({
    source_url_or_path: z.string().min(1, "Required"),
    branch: z.string(),
    auth_ref: z.string(),
  });
  if (tab === "url") {
    return base.refine(
      (v) =>
        v.auth_ref.trim().length === 0 || GIT_AUTH_PATTERN.test(v.auth_ref.trim()),
      {
        path: ["auth_ref"],
        message: "Format `ssh-key:/path`, `token-env:NAME`, or `gh-app:<id>`",
      },
    );
  }
  return base;
}

function initialTab(kind: string): Tab {
  return kind === "local-path" || kind === "local" ? "path" : "url";
}

interface Props {
  projectId: string;
  repo: RepoRecord;
  onClose: () => void;
  onSaved: (next: RepoRecord) => void;
}

export function RepoEditModal({ projectId, repo, onClose, onSaved }: Props) {
  const initial = useMemo<FormValues>(
    () => ({
      source_url_or_path: repo.source_url_or_path,
      branch: repo.branch ?? "",
      auth_ref: repo.auth_ref ?? "",
    }),
    [repo],
  );
  const [tab, setTab] = useState<Tab>(initialTab(repo.source_kind));
  const firstInputRef = useRef<HTMLInputElement | null>(null);
  const patch = usePatchProjectRepo(projectId);

  const resolver = useMemo(() => zodResolver(buildSchema(tab)), [tab]);

  const form = useForm<FormValues>({
    resolver,
    mode: "onBlur",
    defaultValues: initial,
  });

  const { register, handleSubmit, formState, setError } = form;

  useEffect(() => {
    firstInputRef.current?.focus();
  }, []);
  useEffect(() => {
    form.clearErrors("source_url_or_path");
    form.clearErrors("auth_ref");
  }, [tab, form]);

  async function onSubmit(values: FormValues) {
    const body = buildPatch({
      tab,
      initialKind: repo.source_kind,
      initial,
      next: values,
    });
    if (body === null) {
      onClose();
      return;
    }
    try {
      const row = await patch.mutateAsync({ name: repo.name, patch: body });
      onSaved(row);
    } catch (err) {
      setError("root", { type: "server", message: String(err) });
    }
  }

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="repo-edit-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal">
        <header className="modal__header">
          <h2 id="repo-edit-title" className="modal__title">
            Edit repository
          </h2>
          <button
            type="button"
            className="modal__close"
            aria-label="Close"
            onClick={onClose}
          >
            ×
          </button>
        </header>

        <div className="modal__body">
          <p className="setup-hint">
            Editing <code>{repo.name}</code>. Name cannot be changed once a repo
            is connected; remove and re-add to rename.
          </p>

          <div className="repo-add__tabs" role="tablist" aria-label="Source kind">
            <button
              type="button"
              role="tab"
              aria-selected={tab === "url"}
              className={`repo-add__tab${tab === "url" ? " active" : ""}`}
              onClick={() => setTab("url")}
            >
              Git URL
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === "path"}
              className={`repo-add__tab${tab === "path" ? " active" : ""}`}
              onClick={() => setTab("path")}
            >
              Local path
            </button>
          </div>

          <form
            id="repo-edit-form"
            className="repo-add__form"
            onSubmit={handleSubmit(onSubmit)}
            noValidate
          >
            {tab === "url" ? (
              <>
                <div className="setup-field">
                  <label htmlFor="repo-edit-url">Repository URL</label>
                  <input
                    id="repo-edit-url"
                    type="text"
                    autoComplete="off"
                    placeholder="https://github.com/org/billing.git"
                    {...register("source_url_or_path")}
                    ref={(el) => {
                      register("source_url_or_path").ref(el);
                      firstInputRef.current = el;
                    }}
                  />
                  <FieldError msg={formState.errors.source_url_or_path?.message} />
                </div>
                <div className="setup-field">
                  <label htmlFor="repo-edit-branch">Branch (optional)</label>
                  <input
                    id="repo-edit-branch"
                    type="text"
                    autoComplete="off"
                    placeholder="main"
                    {...register("branch")}
                  />
                </div>
                <div className="setup-field">
                  <label htmlFor="repo-edit-auth">Auth descriptor (optional)</label>
                  <input
                    id="repo-edit-auth"
                    type="text"
                    autoComplete="off"
                    placeholder="token-env:GH_TOKEN"
                    {...register("auth_ref")}
                  />
                  <p className="setup-hint">
                    Format: <code>ssh-key:/path</code>, <code>token-env:NAME</code>, or{" "}
                    <code>gh-app:&lt;id&gt;</code>. Leave empty to clear.
                  </p>
                  <FieldError msg={formState.errors.auth_ref?.message} />
                </div>
              </>
            ) : (
              <div className="setup-field">
                <label htmlFor="repo-edit-path">Filesystem path</label>
                <input
                  id="repo-edit-path"
                  type="text"
                  autoComplete="off"
                  placeholder="/Users/me/code/some-flask-app"
                  {...register("source_url_or_path")}
                  ref={(el) => {
                    register("source_url_or_path").ref(el);
                    firstInputRef.current = el;
                  }}
                />
                <FieldError msg={formState.errors.source_url_or_path?.message} />
                <p className="setup-hint">
                  The daemon snapshots the directory read-only on each scan.
                </p>
              </div>
            )}

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
            form="repo-edit-form"
            variant="primary"
            disabled={patch.isPending}
          >
            {patch.isPending ? <Spinner /> : "Save changes"}
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

interface BuildPatchArgs {
  tab: Tab;
  initialKind: string;
  initial: FormValues;
  next: FormValues;
}

/**
 * Produce the minimum PATCH body the daemon needs. Returns `null` when no
 * field changed (the caller can short-circuit the network call). Branch and
 * auth_ref use the API's tri-state grammar: `null` clears the field, a
 * string sets it, omitted leaves it untouched.
 */
export function buildPatch(args: BuildPatchArgs): PatchRepoRequest | null {
  const { tab, initialKind, initial, next } = args;
  const targetKind = tab === "url" ? "git" : "local-path";
  const body: PatchRepoRequest = {};
  let dirty = false;

  if (targetKind !== initialKind) {
    body.source_kind = targetKind;
    dirty = true;
  }
  const nextSource = next.source_url_or_path.trim();
  if (nextSource !== initial.source_url_or_path) {
    body.source_url_or_path = nextSource;
    dirty = true;
  }

  const nextBranch = next.branch.trim();
  const initialBranch = initial.branch;
  if (nextBranch !== initialBranch) {
    body.branch = nextBranch.length === 0 ? null : nextBranch;
    dirty = true;
  }

  if (tab === "url") {
    const nextAuth = next.auth_ref.trim();
    const initialAuth = initial.auth_ref;
    if (nextAuth !== initialAuth) {
      body.auth_ref = nextAuth.length === 0 ? null : nextAuth;
      dirty = true;
    }
  } else if (initial.auth_ref.length > 0) {
    body.auth_ref = null;
    dirty = true;
  }

  return dirty ? body : null;
}
