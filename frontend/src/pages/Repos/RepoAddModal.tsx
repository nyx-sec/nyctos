import { useEffect, useRef, useState } from "react";
import { useForm, type FieldErrors, type Resolver } from "react-hook-form";
import { z } from "zod";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import {
  useCreateProjectRepo,
  useTestProjectRepo,
  type CreateRepoRequest,
  type TestRepoResponse,
} from "@/api/client";

type Tab = "url" | "path";

interface FormValues {
  name: string;
  source_url_or_path: string;
  branch: string;
  auth_ref: string;
  i_own_this: boolean;
}

const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const GIT_AUTH_PATTERN = /^(ssh-key|token-env|gh-app):[^:].*$/;

function buildSchema(tab: Tab) {
  const base = z.object({
    name: z
      .string()
      .min(1, "Name is required")
      .max(64)
      .regex(
        NAME_PATTERN,
        "Letters, numbers, dot, dash, underscore (max 64 chars)",
      ),
    source_url_or_path: z.string().min(1, "Required"),
    branch: z.string().optional().default(""),
    auth_ref: z.string().optional().default(""),
    i_own_this: z
      .boolean()
      .refine((v) => v === true, "You must attest ownership before adding the repo"),
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

interface Props {
  projectId: string;
  onClose: () => void;
  onAdded: (name: string) => void;
}

export function RepoAddModal({ projectId, onClose, onAdded }: Props) {
  const [tab, setTab] = useState<Tab>("url");
  const [testResult, setTestResult] = useState<TestRepoResponse | null>(null);
  const create = useCreateProjectRepo(projectId);
  const test = useTestProjectRepo(projectId);
  const firstInputRef = useRef<HTMLInputElement | null>(null);

  const resolver: Resolver<FormValues> = async (values) => {
    const schema = buildSchema(tab);
    const result = schema.safeParse(values);
    if (result.success) {
      return { values: result.data, errors: {} };
    }
    const errors: FieldErrors<FormValues> = {};
    for (const issue of result.error.issues) {
      const key = issue.path[0] as keyof FormValues | undefined;
      if (key && !(key in errors)) {
        errors[key] = { type: "validation", message: issue.message };
      }
    }
    return { values: {}, errors };
  };

  const form = useForm<FormValues>({
    resolver,
    mode: "onBlur",
    defaultValues: {
      name: "",
      source_url_or_path: "",
      branch: "",
      auth_ref: "",
      i_own_this: false,
    },
  });

  const { register, handleSubmit, formState, getValues, setError, reset } = form;

  // Focus first field on mount + reset tab-specific state when the tab
  // changes; the URL/path inputs share the same field name so we just
  // clear validation state for it.
  useEffect(() => {
    firstInputRef.current?.focus();
  }, []);
  useEffect(() => {
    setTestResult(null);
    form.clearErrors("source_url_or_path");
    form.clearErrors("auth_ref");
  }, [tab, form]);

  async function onTestConnectivity() {
    setTestResult(null);
    const { source_url_or_path, branch } = getValues();
    if (!source_url_or_path.trim()) {
      setError("source_url_or_path", {
        type: "validation",
        message: "Required",
      });
      return;
    }
    try {
      const result = await test.mutateAsync({
        source_kind: tab === "url" ? "git" : "local-path",
        source_url_or_path: source_url_or_path.trim(),
        branch: branch.trim() || undefined,
      });
      setTestResult(result);
    } catch (err) {
      setTestResult({ ok: false, message: String(err) });
    }
  }

  async function onSubmit(values: FormValues) {
    const body: CreateRepoRequest = {
      name: values.name.trim(),
      source_kind: tab === "url" ? "git" : "local-path",
      source_url_or_path: values.source_url_or_path.trim(),
      i_own_this: values.i_own_this,
    };
    const branch = values.branch.trim();
    if (branch) body.branch = branch;
    const authRef = values.auth_ref.trim();
    if (tab === "url" && authRef) body.auth_ref = authRef;
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
      aria-labelledby="repo-add-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal">
        <header className="modal__header">
          <h2 id="repo-add-title" className="modal__title">
            Add repository
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
            id="repo-add-form"
            className="repo-add__form"
            onSubmit={handleSubmit(onSubmit)}
            noValidate
          >
            <NameField
              error={formState.errors.name?.message}
              registration={register("name")}
              firstInputRef={firstInputRef}
            />

            {tab === "url" ? (
              <>
                <div className="setup-field">
                  <label htmlFor="repo-url">Repository URL</label>
                  <input
                    id="repo-url"
                    type="text"
                    autoComplete="off"
                    placeholder="https://github.com/org/billing.git"
                    {...register("source_url_or_path")}
                  />
                  <FieldError msg={formState.errors.source_url_or_path?.message} />
                </div>
                <div className="setup-field">
                  <label htmlFor="repo-branch">Branch (optional)</label>
                  <input
                    id="repo-branch"
                    type="text"
                    autoComplete="off"
                    placeholder="main"
                    {...register("branch")}
                  />
                </div>
                <div className="setup-field">
                  <label htmlFor="repo-auth">Auth descriptor (optional)</label>
                  <input
                    id="repo-auth"
                    type="text"
                    autoComplete="off"
                    placeholder="token-env:GH_TOKEN"
                    {...register("auth_ref")}
                  />
                  <p className="setup-hint">
                    Format: <code>ssh-key:/path</code>, <code>token-env:NAME</code>, or{" "}
                    <code>gh-app:&lt;id&gt;</code>. The descriptor is stored; secrets
                    stay in the env var or keychain.
                  </p>
                  <FieldError msg={formState.errors.auth_ref?.message} />
                </div>
              </>
            ) : (
              <div className="setup-field">
                <label htmlFor="repo-path">Filesystem path</label>
                <input
                  id="repo-path"
                  type="text"
                  autoComplete="off"
                  placeholder="/Users/elipeter/code/some-flask-app"
                  {...register("source_url_or_path")}
                />
                <FieldError msg={formState.errors.source_url_or_path?.message} />
                <p className="setup-hint">
                  The daemon will snapshot the directory read-only on each scan.
                </p>
              </div>
            )}

            <label className="setup-checkbox">
              <input type="checkbox" {...register("i_own_this")} />
              <div>
                <strong>I own this repository</strong>
                <p className="setup-hint">
                  Required before the daemon will accept the entry. Attesting
                  ownership tells the agent it is safe to scan source you control.
                </p>
                <FieldError msg={formState.errors.i_own_this?.message} />
              </div>
            </label>

            <div className="repo-add__test">
              <Button
                type="button"
                variant="ghost"
                onClick={onTestConnectivity}
                disabled={test.isPending}
              >
                {test.isPending ? <Spinner /> : "Test connectivity"}
              </Button>
              {testResult && (
                <div
                  className={`repo-add__test-result${testResult.ok ? " ok" : " fail"}`}
                  role="status"
                >
                  <Badge tone={testResult.ok ? "success" : "danger"}>
                    {testResult.ok ? "OK" : "Failed"}
                  </Badge>
                  <p>{testResult.message}</p>
                  {testResult.on_disk_git_remote && (
                    <p className="setup-hint">
                      Acknowledge before adding: on-disk remote ={" "}
                      <code>{testResult.on_disk_git_remote}</code>
                    </p>
                  )}
                </div>
              )}
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
            form="repo-add-form"
            variant="primary"
            disabled={create.isPending}
          >
            {create.isPending ? <Spinner /> : "Add repo"}
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

interface NameFieldProps {
  error?: string;
  registration: ReturnType<ReturnType<typeof useForm<FormValues>>["register"]>;
  firstInputRef: React.MutableRefObject<HTMLInputElement | null>;
}

function NameField({ error, registration, firstInputRef }: NameFieldProps) {
  return (
    <div className="setup-field">
      <label htmlFor="repo-name">Name</label>
      <input
        id="repo-name"
        type="text"
        autoComplete="off"
        placeholder="billing"
        name={registration.name}
        onBlur={registration.onBlur}
        onChange={registration.onChange}
        ref={(el) => {
          registration.ref(el);
          firstInputRef.current = el;
        }}
      />
      <FieldError msg={error} />
    </div>
  );
}
