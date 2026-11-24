export type ServiceStatus = {
  status: "ok" | "down";
  latency_ms: number;
  error?: string;
};

export type ReadyReport = {
  status: "ok" | "down";
  version: string;
  services: Record<string, ServiceStatus>;
};

export async function fetchReady(): Promise<ReadyReport> {
  const response = await fetch("/backend/health/ready", { cache: "no-store" });
  const payload = (await response.json()) as ReadyReport;
  if (!payload?.services) {
    throw new Error("Unexpected health response");
  }
  return payload;
}
