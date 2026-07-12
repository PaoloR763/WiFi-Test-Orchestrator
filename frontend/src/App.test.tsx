import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("App", () => {
  it("shows loading while backend requests are pending", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => undefined)),
    );
    render(<App />);
    expect(screen.getByText("Loading system status…")).toBeInTheDocument();
  });

  it("shows ready state and the agent returned by the backend", async () => {
    const agent = {
      agent_id: "from-backend",
      display_name: "Agent supplied by API",
      platform: "simulated",
      process_started_at: "2026-07-11T00:00:00Z",
      last_seen_at: "2026-07-11T00:00:10Z",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((path: string) =>
        Promise.resolve(
          path === "/health/ready"
            ? jsonResponse({ status: "ready", checks: {} })
            : jsonResponse({ agents: [agent] }),
        ),
      ),
    );
    render(<App />);
    expect(await screen.findByText("System ready")).toBeInTheDocument();
    expect(screen.getByText("Agent supplied by API")).toBeInTheDocument();
    expect(screen.getByText("from-backend")).toBeInTheDocument();
  });

  it("shows an error when backend consumption fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("offline"))),
    );
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The backend status could not be loaded.",
    );
  });
});
