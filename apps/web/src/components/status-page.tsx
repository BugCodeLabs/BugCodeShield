"use client";

import { useCallback, useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { fetchReady, type ReadyReport } from "@/lib/health";
import { Spinner } from "@/components/ui";

const SERVICE_META: Record<string, { label: string; detail: string }> = {
  postgres: { label: "PostgreSQL", detail: "Primary database" },
  redis: { label: "Redis", detail: "Cache and job coordination" },
  rabbitmq: { label: "RabbitMQ", detail: "Scan job broker" },
  minio: { label: "MinIO", detail: "Object storage" },
};

type LoadState =
  | { kind: "loading" }
  | { kind: "ok"; report: ReadyReport; checkedAt: Date }
  | { kind: "error"; message: string; checkedAt: Date };

export function StatusPage() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  const refresh = useCallback(async () => {
    try {
      const report = await fetchReady();
      setState({ kind: "ok", report, checkedAt: new Date() });
    } catch (error) {
      setState({
        kind: "error",
        message: error instanceof Error ? error.message : "API unreachable",
        checkedAt: new Date(),
      });
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      void refresh();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const healthy = state.kind === "ok" && state.report.status === "ok";

  return (
    <main className="mx-auto flex min-h-screen max-w-5xl flex-col gap-8 px-6 py-10">
      <header className="flex flex-col gap-4 border-b border-[var(--border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.2em] text-[var(--muted)]">
            Platform
          </p>
          <h1 className="mt-1 text-3xl font-semibold">BugCode Shield</h1>
          <p className="mt-2 max-w-xl text-[var(--muted)]">
            Unified code security and quality analysis. This page confirms the
            web app can reach the API and that infrastructure services are
            healthy.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusPill ok={state.kind !== "error"} label="API" />
          <StatusPill ok={healthy} label="Stack" />
          <button
            type="button"
            onClick={() => void refresh()}
            className="inline-flex items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--card)] px-3 py-2 text-sm hover:border-[var(--muted)]"
          >
            {state.kind === "loading" && <Spinner />}
            {state.kind === "loading" ? "Checking…" : "Refresh"}
          </button>
        </div>
      </header>

      <section className="grid gap-4 sm:grid-cols-2">
        {Object.entries(SERVICE_META).map(([key, meta]) => {
          const service = state.kind === "ok" ? state.report.services[key] : undefined;
          const ok = service?.status === "ok";
          return (
            <article
              key={key}
              className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-5"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-medium">{meta.label}</h2>
                  <p className="text-sm text-[var(--muted)]">{meta.detail}</p>
                </div>
                <StatusPill ok={ok} label={ok ? "Healthy" : "Down"} />
              </div>
              <p className="mt-4 text-sm text-[var(--muted)]">
                {state.kind === "loading" && "Checking…"}
                {state.kind === "error" && "Waiting for API"}
                {service && `Latency ${service.latency_ms} ms`}
              </p>
            </article>
          );
        })}
      </section>

      <section className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-5">
        <h2 className="text-lg font-medium">Operator consoles</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Bound to localhost only. Use the credentials from your `.env` file.
        </p>
        <div className="mt-4 flex flex-wrap gap-3 text-sm">
          <a className="underline underline-offset-4" href="http://localhost:15672">
            RabbitMQ management
          </a>
          <a className="underline underline-offset-4" href="http://localhost:9001">
            MinIO console
          </a>
          <a className="underline underline-offset-4" href="http://localhost:3001/health/ready">
            API ready JSON
          </a>
        </div>
        <p className="mt-4 text-xs text-[var(--muted)]">
          {state.kind === "ok" && `API version ${state.report.version} · `}
          {state.kind !== "loading" && `Last check ${state.checkedAt.toLocaleTimeString()}`}
          {state.kind === "error" && ` · ${state.message}`}
        </p>
      </section>
    </main>
  );
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs uppercase tracking-wide",
        ok
          ? "border-[var(--ok)] text-[var(--ok)]"
          : "border-[var(--down)] text-[var(--down)]",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", ok ? "bg-[var(--ok)]" : "bg-[var(--down)]")} />
      {label}
    </span>
  );
}
