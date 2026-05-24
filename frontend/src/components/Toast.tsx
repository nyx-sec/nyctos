import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

export type ToastTone = "info" | "success" | "warning" | "danger";

export interface ToastOptions {
  tone?: ToastTone;
  durationMs?: number;
}

interface ToastRecord {
  id: string;
  message: string;
  tone: ToastTone;
  durationMs: number;
}

interface ToastContextValue {
  showToast: (message: string, options?: ToastOptions) => string;
  dismissToast: (id: string) => void;
}

const noopToastContext: ToastContextValue = {
  showToast: () => "",
  dismissToast: () => {},
};

const ToastContext = createContext<ToastContextValue>(noopToastContext);

let toastSequence = 0;

function nextToastId(): string {
  toastSequence = (toastSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `toast-${Date.now()}-${toastSequence}`;
}

function defaultDuration(tone: ToastTone): number {
  return tone === "danger" ? 7_000 : 4_000;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback((message: string, options: ToastOptions = {}) => {
    const tone = options.tone ?? "info";
    const toast: ToastRecord = {
      id: nextToastId(),
      message,
      tone,
      durationMs: options.durationMs ?? defaultDuration(tone),
    };
    setToasts((current) => [...current.slice(-4), toast]);
    return toast.id;
  }, []);

  const value = useMemo(() => ({ showToast, dismissToast }), [showToast, dismissToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastRegion toasts={toasts} onDismiss={dismissToast} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  return useContext(ToastContext);
}

function ToastRegion({
  toasts,
  onDismiss,
}: {
  toasts: ToastRecord[];
  onDismiss: (id: string) => void;
}) {
  if (toasts.length === 0) return null;

  return (
    <ol className="toast-region" aria-label="Notifications">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </ol>
  );
}

function ToastItem({ toast, onDismiss }: { toast: ToastRecord; onDismiss: (id: string) => void }) {
  useEffect(() => {
    if (toast.durationMs <= 0) return;
    const timer = window.setTimeout(() => onDismiss(toast.id), toast.durationMs);
    return () => window.clearTimeout(timer);
  }, [onDismiss, toast.durationMs, toast.id]);

  return (
    <li
      className={`toast toast--${toast.tone}`}
      role={toast.tone === "danger" ? "alert" : "status"}
    >
      <p className="toast__message">{toast.message}</p>
      <button
        type="button"
        className="toast__close"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(toast.id)}
      >
        <span aria-hidden="true">x</span>
      </button>
    </li>
  );
}
