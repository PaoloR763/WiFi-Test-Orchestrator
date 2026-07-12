import { afterEach, describe, expect, it, vi } from "vitest";

import { loadDashboard } from "./api";

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("loadDashboard", () => {
  it("consumes the backend through relative reverse-proxy paths", async () => {
    const fetchMock = vi.fn((path: string) => {
      if (path === "/health/ready") {
        return Promise.resolve(jsonResponse({ status: "ready", checks: {} }));
      }
      if (path === "/demo/agents") {
        return Promise.resolve(jsonResponse({ agents: [] }));
      }
      return Promise.reject(new Error("unexpected path"));
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(loadDashboard()).resolves.toEqual({
      readiness: { status: "ready", checks: {} },
      agents: [],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/health/ready",
      expect.objectContaining({ method: "GET" }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/demo/agents",
      expect.objectContaining({ method: "GET" }),
    );
  });
});
