import { useEffect, useState } from "react";

import { type DashboardData, loadDashboard } from "./api";
import "./styles.css";

type ViewState =
  | { phase: "loading" }
  | { phase: "ready"; data: DashboardData }
  | { phase: "error" };

const REFRESH_INTERVAL_MS = 10_000;

export function App() {
  const [state, setState] = useState<ViewState>({ phase: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    const refresh = async () => {
      try {
        const data = await loadDashboard(controller.signal);
        if (!controller.signal.aborted) {
          setState({ phase: "ready", data });
        }
      } catch {
        if (!controller.signal.aborted) {
          setState({ phase: "error" });
        }
      }
    };

    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, []);

  return (
    <main>
      <header>
        <p className="eyebrow">Phase 02 development environment</p>
        <h1>WiFi Test Orchestrator</h1>
        <p className="lede">
          Portable local control surface for authorized Wi-Fi test labs.
        </p>
      </header>

      {state.phase === "loading" && (
        <section aria-live="polite">Loading system status…</section>
      )}

      {state.phase === "error" && (
        <section className="error" role="alert">
          The backend status could not be loaded.
        </section>
      )}

      {state.phase === "ready" && (
        <>
          <section className="status-card" aria-label="System status">
            <span className="status-dot" aria-hidden="true" />
            <div>
              <h2>System ready</h2>
              <p>
                Backend dependencies are available through the reverse proxy.
              </p>
            </div>
          </section>

          <section>
            <div className="section-heading">
              <h2>Development inventory</h2>
              <span>{state.data.agents.length} online</span>
            </div>
            {state.data.agents.length === 0 ? (
              <p>No simulated agents have announced their presence yet.</p>
            ) : (
              <ul className="agent-grid">
                {state.data.agents.map((agent) => (
                  <li key={agent.agent_id}>
                    <h3>{agent.display_name}</h3>
                    <dl>
                      <div>
                        <dt>ID</dt>
                        <dd>{agent.agent_id}</dd>
                      </div>
                      <div>
                        <dt>Platform</dt>
                        <dd>{agent.platform}</dd>
                      </div>
                      <div>
                        <dt>Last seen</dt>
                        <dd>{new Date(agent.last_seen_at).toLocaleString()}</dd>
                      </div>
                    </dl>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </main>
  );
}
