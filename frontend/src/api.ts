export interface ReadinessResponse {
  status: "ready" | "unavailable";
  checks: Record<string, { status: string }>;
}

export interface DemoAgent {
  agent_id: string;
  display_name: string;
  platform: "simulated";
  process_started_at: string;
  last_seen_at: string;
}

export interface DemoAgentList {
  agents: DemoAgent[];
}

export interface DashboardData {
  readiness: ReadinessResponse;
  agents: DemoAgent[];
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function loadDashboard(
  signal?: AbortSignal,
): Promise<DashboardData> {
  const [readiness, inventory] = await Promise.all([
    getJson<ReadinessResponse>("/health/ready", signal),
    getJson<DemoAgentList>("/demo/agents", signal),
  ]);
  return { readiness, agents: inventory.agents };
}
