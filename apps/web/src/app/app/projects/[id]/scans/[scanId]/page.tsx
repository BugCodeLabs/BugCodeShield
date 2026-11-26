"use client";

import { api, getToken, getWsOrigin, scanSocketURL, type Finding, type Scan, type ScanLog, type UserSettings } from "@/lib/api";
import { Card, GhostButton, Input, LoadingScreen, SeverityBadge, Spinner } from "@/components/ui";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function isFinished(status?: string) {
  return status === "COMPLETED" || status === "FAILED" || status === "CANCELLED";
}

function sourceText(scan: Scan) {
  if (scan.github_repo) return `github.com/${scan.github_repo}`;
  if (scan.local_path) return scan.local_path;
  return scan.source_label || "selected source";
}

function scannerState(name: string, logs: ScanLog[]) {
  const related = logs.filter((log) => log.scanner === name);
  const last = related.at(-1)?.message || "";
  if (/collected \d+ findings/i.test(last) || /scanner failed/i.test(last)) {
    const match = last.match(/collected (\d+) findings/i);
    return { label: match ? `done · ${match[1]} issues` : "done", done: true, error: /failed/i.test(last) };
  }
  if (related.length > 0) return { label: "running", done: false, error: false };
  return { label: "waiting", done: false, error: false };
}

export default function ScanIssuesPage() {
  const params = useParams<{ id: string; scanId: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [severity, setSeverity] = useState("");
  const [scanner, setScanner] = useState("");
  const [fileFilter, setFileFilter] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [explanation, setExplanation] = useState("");
  const [explainError, setExplainError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [exporting, setExporting] = useState("");
  const [aiReady, setAiReady] = useState(false);
  const logEnd = useRef<HTMLDivElement | null>(null);
  const statusRef = useRef("");

  async function load() {
    const sc = await api.get<Scan>(`/api/v1/scans/${params.scanId}`);
    statusRef.current = sc.status;
    setScan(sc);
    const logRes = await api.get<{ logs: ScanLog[] }>(`/api/v1/scans/${params.scanId}/logs`);
    setLogs(logRes.logs);
    if (isFinished(sc.status)) {
      const res = await api.get<{ findings: Finding[] }>(`/api/v1/scans/${params.scanId}/findings`);
      setFindings(res.findings);
    } else {
      setFindings([]);
    }
    return sc;
  }

  async function cancelScan() {
    setCancelling(true);
    try {
      await api.post(`/api/v1/scans/${params.scanId}/cancel`);
      await load();
    } finally {
      setCancelling(false);
    }
  }

  useEffect(() => {
    let stop = false;
    let ws: WebSocket | null = null;
    let pollTimer = 0;
    let retryTimer = 0;
    let fallbackTimer = 0;
    let attempts = 0;
    let usingPoll = false;
    let gotSnapshot = false;
    statusRef.current = "";

    async function loadFindings() {
      const res = await api.get<{ findings: Finding[] }>(`/api/v1/scans/${params.scanId}/findings`);
      if (!stop) setFindings(res.findings);
    }

    function startPoll() {
      if (usingPoll || stop) return;
      usingPoll = true;
      if (ws) {
        ws.close();
        ws = null;
      }
      async function tick() {
        if (stop) return;
        try {
          const sc = await load();
          if (!stop && !isFinished(sc.status)) pollTimer = window.setTimeout(tick, 1200);
        } catch {
          if (!stop) pollTimer = window.setTimeout(tick, 2000);
        }
      }
      tick();
    }

    function handleMessage(raw: string) {
      let msg: {
        type?: string;
        status?: string;
        finding_count?: number;
        error_message?: string;
        scan?: Scan;
        logs?: ScanLog[];
        log?: ScanLog;
      };
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      if (msg.type === "snapshot") {
        gotSnapshot = true;
        if (msg.scan) {
          statusRef.current = msg.scan.status;
          setScan(msg.scan);
        }
        setLogs(msg.logs || []);
        if (msg.scan && isFinished(msg.scan.status)) {
          loadFindings().catch(() => undefined);
        } else {
          setFindings([]);
        }
        return;
      }
      if (msg.type === "log" && msg.log) {
        setLogs((prev) => [...prev, msg.log!]);
        return;
      }
      if (msg.type === "scan" || msg.type === "done") {
        if (msg.status) statusRef.current = msg.status;
        setScan((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            status: msg.status || prev.status,
            finding_count: msg.finding_count ?? prev.finding_count,
            error_message: msg.error_message ?? prev.error_message,
          };
        });
        if (isFinished(msg.status) || msg.type === "done") {
          loadFindings().catch(() => undefined);
        }
      }
    }

    async function connectWS() {
      const token = getToken();
      if (!token) {
        startPoll();
        return;
      }
      let origin = "";
      try {
        origin = await getWsOrigin();
      } catch {
        startPoll();
        return;
      }
      if (stop || usingPoll) return;
      const socket = new WebSocket(scanSocketURL(origin, params.scanId, token));
      ws = socket;
      socket.onopen = () => {
        attempts = 0;
      };
      socket.onmessage = (event) => handleMessage(String(event.data));
      socket.onclose = () => {
        if (stop || usingPoll) return;
        if (isFinished(statusRef.current)) return;
        attempts += 1;
        if (attempts > 3) {
          startPoll();
          return;
        }
        retryTimer = window.setTimeout(() => {
          connectWS().catch(() => startPoll());
        }, 800 * attempts);
      };
    }

    fallbackTimer = window.setTimeout(() => {
      if (!gotSnapshot && !usingPoll) startPoll();
    }, 4000);
    connectWS().catch(() => startPoll());
    api.get<UserSettings>("/api/v1/settings").then((view) => setAiReady(view.openai_api_key_set)).catch(() => undefined);
    return () => {
      stop = true;
      window.clearTimeout(pollTimer);
      window.clearTimeout(retryTimer);
      window.clearTimeout(fallbackTimer);
      if (ws) ws.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.scanId]);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ block: "end" });
  }, [logs]);

  const counts = useMemo(() => {
    const next = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) next[finding.severity] += 1;
    return next;
  }, [findings]);

  const scannerCounts = useMemo(() => {
    const next: Record<string, number> = {};
    for (const finding of findings) next[finding.scanner] = (next[finding.scanner] || 0) + 1;
    return next;
  }, [findings]);

  const files = useMemo(() => {
    const map = new Map<string, number>();
    for (const finding of findings) {
      const path = finding.file_path || "(no file)";
      map.set(path, (map.get(path) || 0) + 1);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [findings]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((finding) => {
      if (severity && finding.severity !== severity) return false;
      if (scanner && finding.scanner !== scanner) return false;
      if (fileFilter && (finding.file_path || "(no file)") !== fileFilter) return false;
      if (!q) return true;
      return (
        finding.title.toLowerCase().includes(q) ||
        finding.description.toLowerCase().includes(q) ||
        finding.rule_id.toLowerCase().includes(q) ||
        (finding.file_path || "").toLowerCase().includes(q)
      );
    });
  }, [findings, severity, scanner, fileFilter, query]);

  useEffect(() => {
    if (selected && !visible.some((item) => item.id === selected.id)) {
      setSelected(null);
    }
  }, [visible, selected]);

  async function downloadExport(format: "json" | "sarif") {
    setExporting(format);
    try {
      const token = getToken();
      const response = await fetch(`/backend/api/v1/scans/${params.scanId}/export.${format}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `bugcodeshield-scan-${params.scanId}.${format === "sarif" ? "sarif.json" : "json"}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting("");
    }
  }

  async function explain(finding: Finding) {
    setSelected(finding);
    setExplanation("");
    setExplainError("");
    setExplaining(true);
    try {
      const res = await api.post<{ explanation: string; disclaimer: string }>(`/api/v1/findings/${finding.id}/explain`);
      setExplanation(`${res.disclaimer}\n\n${res.explanation}`);
    } catch (err) {
      setExplainError(err instanceof Error ? err.message : "AI unavailable");
    } finally {
      setExplaining(false);
    }
  }

  if (!scan) {
    return <LoadingScreen label="Opening scan…" />;
  }

  const running = !isFinished(scan.status);

  if (running) {
    const active = (scan.scanners || []).find((name) => scannerState(name, logs).label === "running");
    return (
      <main className="mx-auto max-w-4xl space-y-6 px-6 py-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <Link href={`/app/projects/${params.id}`} className="text-sm text-[var(--muted)]">Back to project</Link>
            <h1 className="mt-2 text-3xl font-semibold">Scanning</h1>
            <p className="text-sm text-[var(--muted)]">
              {scan.status} · {sourceText(scan)} · {scan.scanners.join(", ")}
            </p>
          </div>
          <GhostButton type="button" loading={cancelling} onClick={() => cancelScan().catch(() => undefined)}>{cancelling ? "Cancelling…" : "Cancel"}</GhostButton>
        </div>

        <Card className="flex items-center gap-4">
          <Spinner className="h-10 w-10 shrink-0 text-[var(--accent)]" />
          <div>
            <p className="font-medium">{active ? `${active} is running` : scan.status === "PREPARING" ? "Preparing source" : "Queued"}</p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              {logs.at(-1)?.message || "Waiting for the worker. Issues appear after every scanner finishes."}
            </p>
          </div>
        </Card>

        <Card>
          <p className="mb-3 text-sm text-[var(--muted)]">Tools</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {(scan.scanners || []).map((name) => {
              const state = scannerState(name, logs);
              return (
                <div key={name} className="flex items-center justify-between rounded-lg border border-[var(--border)] px-3 py-2">
                  <span className="font-medium">{name}</span>
                  <span className={`inline-flex items-center gap-2 text-xs ${state.error ? "text-[var(--down)]" : state.done ? "text-[var(--ok)]" : "text-[var(--accent)]"}`}>
                    {state.label === "running" && <Spinner className="h-3 w-3" />}
                    {state.label}
                  </span>
                </div>
              );
            })}
          </div>
        </Card>

        <Card>
          <h2 className="text-lg font-medium">Live log</h2>
          <div className="mt-3 max-h-[50vh] overflow-auto rounded-md bg-[#0b1220] p-3 font-mono text-xs">
            {logs.map((log, index) => (
              <p key={`${log.created_at}-${index}`} className={`whitespace-pre-wrap ${log.level === "error" ? "text-[var(--down)]" : "text-[var(--muted)]"}`}>
                {log.scanner ? `[${log.scanner}] ` : ""}{log.message}
              </p>
            ))}
            {logs.length === 0 && <p className="text-[var(--muted)]">Waiting for scanner output…</p>}
            <div ref={logEnd} />
          </div>
        </Card>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-6 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <Link href={`/app/projects/${params.id}`} className="text-sm text-[var(--muted)]">Back to project</Link>
          <h1 className="mt-2 text-3xl font-semibold">Issues</h1>
          <p className="text-sm text-[var(--muted)]">
            {scan.status} · {sourceText(scan)} · {scan.scanners.join(", ")} · {scan.finding_count} stored
          </p>
        </div>
        <div className="flex gap-2">
          <GhostButton type="button" loading={exporting === "json"} onClick={() => downloadExport("json")}>{exporting === "json" ? "Exporting…" : "JSON"}</GhostButton>
          <GhostButton type="button" loading={exporting === "sarif"} onClick={() => downloadExport("sarif")}>{exporting === "sarif" ? "Exporting…" : "SARIF"}</GhostButton>
        </div>
      </div>

      {scan.status === "FAILED" && (
        <p className="rounded-md border border-[var(--down)]/40 bg-[var(--down)]/10 px-3 py-2 text-sm text-[var(--down)]">
          {scan.error_message || "Scan failed. See the log below."}
        </p>
      )}

      {scan.status === "COMPLETED" && findings.length === 0 && (
        <p className="rounded-md border border-[var(--medium)]/40 bg-[var(--medium)]/10 px-3 py-2 text-sm">
          Scan finished with 0 issues for {sourceText(scan)}. The tools only report what they find in that source.
          If you meant to scan your application, add that folder or GitHub repository on the project page and start a new scan.
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVERITIES.map((key) => (
          <button key={key} type="button" onClick={() => setSeverity(severity === key ? "" : key)}>
            <Card className={severity === key ? "border-[var(--accent)] text-center" : "text-center"}>
              <p className="text-2xl font-semibold">{counts[key]}</p>
              <p className="text-xs uppercase text-[var(--muted)]">{key}</p>
            </Card>
          </button>
        ))}
      </div>

      <Card>
        <p className="mb-3 text-sm text-[var(--muted)]">Categories</p>
        <div className="flex flex-wrap gap-2">
          <GhostButton type="button" className={!severity && !scanner && !fileFilter ? "border-[var(--accent)]" : ""} onClick={() => { setSeverity(""); setScanner(""); setFileFilter(""); }}>
            All ({findings.length})
          </GhostButton>
          {(scan.scanners || []).map((name) => (
            <GhostButton key={name} type="button" className={scanner === name ? "border-[var(--accent)]" : ""} onClick={() => setScanner(scanner === name ? "" : name)}>
              {name} ({scannerCounts[name] || 0})
            </GhostButton>
          ))}
        </div>
        <Input className="mt-4" placeholder="Search title, rule, file, description" value={query} onChange={(e) => setQuery(e.target.value)} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-[220px_1fr_1fr]">
        <Card className="max-h-[70vh] overflow-auto">
          <h2 className="text-sm font-medium">File directory</h2>
          <div className="mt-3 space-y-1">
            {files.map(([path, count]) => (
              <button
                key={path}
                type="button"
                onClick={() => setFileFilter(fileFilter === path ? "" : path)}
                className={`block w-full rounded-md px-2 py-1.5 text-left text-xs hover:bg-[#0b1220] ${fileFilter === path ? "border border-[var(--accent)]" : ""}`}
              >
                <span className="block truncate" title={path}>{path}</span>
                <span className="text-[var(--muted)]">{count === 1 ? "1 issue" : `${count} issues`}</span>
              </button>
            ))}
            {files.length === 0 && <p className="text-xs text-[var(--muted)]">No files reported issues in this scan.</p>}
          </div>
        </Card>

        <Card className="max-h-[70vh] space-y-3 overflow-auto">
          <h2 className="text-sm font-medium">Issue list</h2>
          {visible.map((finding) => (
            <button
              key={finding.id}
              type="button"
              onClick={() => { setSelected(finding); setExplanation(""); setExplainError(""); }}
              className={`w-full rounded-lg border p-3 text-left hover:border-[var(--accent)] ${selected?.id === finding.id ? "border-[var(--accent)]" : "border-[var(--border)]"}`}
            >
              <div className="flex items-center justify-between gap-3">
                <p className="font-medium">{finding.title}</p>
                <SeverityBadge severity={finding.severity} />
              </div>
              <p className="mt-1 text-xs text-[var(--muted)]">
                {finding.scanner} · {finding.file_path || "dependency"}
                {finding.start_line ? `:${finding.start_line}` : ""}
              </p>
            </button>
          ))}
          {visible.length === 0 && (
            <p className="text-sm text-[var(--muted)]">No issues for this filter.</p>
          )}
        </Card>

        <Card className="max-h-[70vh] overflow-auto">
          {!selected && <p className="text-sm text-[var(--muted)]">Select an issue to see the file, line, and code.</p>}
          {selected && (
            <div className="space-y-3">
              <SeverityBadge severity={selected.severity} />
              <h2 className="text-xl font-medium">{selected.title}</h2>
              <p className="text-sm text-[var(--muted)]">{selected.scanner} · {selected.rule_id}</p>
              <p>{selected.description}</p>
              <div className="rounded-md border border-[var(--border)] bg-[#0b1220] p-3 text-sm">
                <p className="text-xs uppercase text-[var(--muted)]">Code location</p>
                <p className="mt-1 font-medium">{selected.file_path || "No file path (dependency finding)"}</p>
                <p className="text-[var(--muted)]">
                  {selected.start_line
                    ? `Line ${selected.start_line}${selected.end_line && selected.end_line !== selected.start_line ? `–${selected.end_line}` : ""}`
                    : "No line number"}
                </p>
              </div>
              {selected.snippet && (
                <pre className="overflow-auto rounded-md bg-[#0b1220] p-3 text-xs">{selected.snippet}</pre>
              )}
              {(selected.cwe || selected.cve) && (
                <p className="text-sm text-[var(--muted)]">
                  {selected.cwe ? `CWE ${selected.cwe}` : ""}{selected.cwe && selected.cve ? " · " : ""}{selected.cve || ""}
                </p>
              )}
              {selected.remediation && <p><span className="text-[var(--muted)]">Remediation: </span>{selected.remediation}</p>}
              {!aiReady && (
                <p className="text-sm text-[var(--muted)]">
                  Save an OpenAI API key in <Link className="underline" href="/app/settings">Settings</Link> to use Ask AI on this and later scans.
                </p>
              )}
              <GhostButton type="button" loading={explaining} onClick={() => explain(selected)}>{explaining ? "Asking AI…" : "Ask AI to explain"}</GhostButton>
              {explainError && (
                <p className="text-sm text-[var(--down)]">
                  {explainError}{" "}
                  <Link className="underline" href="/app/settings">Open Settings</Link>
                </p>
              )}
              {explanation && <pre className="whitespace-pre-wrap text-sm text-[var(--muted)]">{explanation}</pre>}
            </div>
          )}
        </Card>
      </div>

      <Card>
        <h2 className="text-lg font-medium">Scanner log</h2>
        <div className="mt-3 max-h-64 space-y-2 overflow-auto font-mono text-xs">
          {logs.map((log, index) => (
            <p key={`${log.created_at}-${index}`} className={`whitespace-pre-wrap ${log.level === "error" ? "text-[var(--down)]" : "text-[var(--muted)]"}`}>
              {log.scanner ? `[${log.scanner}] ` : ""}{log.message}
            </p>
          ))}
          {logs.length === 0 && <p className="text-sm text-[var(--muted)]">No scanner output.</p>}
        </div>
      </Card>
    </main>
  );
}
