import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, getAuthToken, useAgentEvents, useAllRepos, useTriggerScan } from "./client";

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
  }
  return { qc, Wrapper };
}

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

describe("getAuthToken", () => {
  afterEach(() => {
    delete window.__NYCTOS_BOOTSTRAP__;
  });

  it("returns undefined when no bootstrap is injected", () => {
    expect(getAuthToken()).toBeUndefined();
  });

  it("returns the token injected by nyctos-ui::inject_bootstrap", () => {
    window.__NYCTOS_BOOTSTRAP__ = { authToken: "tk_abc" };
    expect(getAuthToken()).toBe("tk_abc");
  });
});

describe("useAllRepos", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete window.__NYCTOS_BOOTSTRAP__;
  });

  it("fans out one /projects call plus one /projects/:id/repos per project", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects") {
        return jsonResponse([{ id: "alpha" }, { id: "beta" }]);
      }
      if (url === "/api/v1/projects/alpha/repos") {
        return jsonResponse([{ name: "alpha-svc" }]);
      }
      if (url === "/api/v1/projects/beta/repos") {
        return jsonResponse([{ name: "beta-svc" }, { name: "beta-worker" }]);
      }
      throw new Error(`unexpected url ${url}`);
    });

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useAllRepos(), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.map((r) => r.name)).toEqual([
      "alpha-svc",
      "beta-svc",
      "beta-worker",
    ]);
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });

  it("forwards the bootstrap bearer token on every request", async () => {
    window.__NYCTOS_BOOTSTRAP__ = { authToken: "tk_xyz" };
    const calls: Array<{ url: string; auth: string | null }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const headers = new Headers(init?.headers ?? {});
      calls.push({ url, auth: headers.get("authorization") });
      if (url === "/api/v1/projects") return jsonResponse([{ id: "p1" }]);
      return jsonResponse([]);
    });

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useAllRepos(), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.auth).toBe("Bearer tk_xyz");
    }
  });

  it("lifts the daemon's structured error body into an ApiError", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(
        { error: { code: "ProjectListFailed", message: "store unavailable" } },
        { status: 503, statusText: "Service Unavailable" },
      ),
    );

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useAllRepos(), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.isError).toBe(true));
    const err = result.current.error as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(503);
    expect(err.code).toBe("ProjectListFailed");
    expect(err.message).toBe("store unavailable");
  });
});

describe("useTriggerScan", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs to the project scan endpoint and surfaces the new run id", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ run_id: "run-1" }));

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useTriggerScan("proj-a"), { wrapper: Wrapper });

    let returned: unknown;
    await act(async () => {
      returned = await result.current.mutateAsync(undefined);
    });
    expect(returned).toEqual({ run_id: "run-1" });

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("/api/v1/projects/proj-a/scan");
    expect(init?.method).toBe("POST");
  });

  it("forwards the optional repo filter as a query param", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ run_id: "run-2" }));

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useTriggerScan("proj-b"), { wrapper: Wrapper });
    await act(async () => {
      await result.current.mutateAsync("svc with space");
    });
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe("/api/v1/projects/proj-b/scan?repo=svc%20with%20space");
  });
});

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  readyState = 0;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3;
    this.onclose?.({});
  }

  // Test helpers — not part of the real WebSocket interface.
  _emitOpen() {
    this.readyState = 1;
    this.onopen?.({});
  }
  _emitMessage(data: unknown) {
    this.onmessage?.({ data: typeof data === "string" ? data : JSON.stringify(data) });
  }
  _emitError() {
    this.onerror?.({});
  }
}

describe("useAgentEvents", () => {
  let originalWS: typeof WebSocket;
  beforeEach(() => {
    originalWS = window.WebSocket;
    (window as unknown as { WebSocket: unknown }).WebSocket =
      FakeWebSocket as unknown as typeof WebSocket;
    FakeWebSocket.instances = [];
  });
  afterEach(() => {
    (window as unknown as { WebSocket: unknown }).WebSocket = originalWS;
    delete window.__NYCTOS_BOOTSTRAP__;
  });

  it("builds the URL with run_id + bootstrap token and tracks open / message / close", async () => {
    window.__NYCTOS_BOOTSTRAP__ = { authToken: "tk_evt" };
    const seen: unknown[] = [];
    const { Wrapper } = makeWrapper();
    const { result, unmount } = renderHook(
      () => useAgentEvents({ runId: "run-7", onEvent: (e) => seen.push(e) }),
      { wrapper: Wrapper },
    );

    expect(FakeWebSocket.instances).toHaveLength(1);
    const ws = FakeWebSocket.instances[0];
    expect(ws.url).toContain("/api/v1/events?");
    expect(ws.url).toContain("run_id=run-7");
    expect(ws.url).toContain("token=tk_evt");
    expect(result.current.status).toBe("connecting");

    act(() => ws._emitOpen());
    expect(result.current.status).toBe("open");

    act(() => ws._emitMessage({ kind: "RunStarted", run_id: "run-7" }));
    expect(result.current.last).toEqual({ kind: "RunStarted", run_id: "run-7" });
    expect(seen).toEqual([{ kind: "RunStarted", run_id: "run-7" }]);

    act(() => ws._emitMessage("not json"));
    expect(result.current.last).toEqual({ kind: "RunStarted", run_id: "run-7" });

    unmount();
    expect(ws.readyState).toBe(3);
  });

  it("omits the run_id param when none is supplied", () => {
    const { Wrapper } = makeWrapper();
    renderHook(() => useAgentEvents(), { wrapper: Wrapper });
    const ws = FakeWebSocket.instances[0];
    expect(ws.url).not.toContain("run_id=");
  });
});
