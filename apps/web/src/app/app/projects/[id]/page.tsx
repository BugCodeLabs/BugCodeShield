"use client";

import { api, type Project, type Scan, type Source, type UserSettings } from "@/lib/api";
import { Button, Card, GhostButton, InlineWait, Input, Label, LoadingScreen, ProgressBar, Select, Spinner } from "@/components/ui";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { ChangeEvent, FormEvent, useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";

type SourceKind = "zip" | "directory" | "github";

const SCANNER_OPTIONS = [
  { id: "semgrep", label: "Semgrep", detail: "Code issues" },
  { id: "trivy", label: "Trivy", detail: "Dependencies / CVEs" },
  { id: "gitleaks", label: "Gitleaks", detail: "Secrets" },
  { id: "sonarqube", label: "SonarQube", detail: "Quality, bugs, security hotspots" },
  { id: "dependency-check", label: "Dependency-Check", detail: "Optional, slower" },
];

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function sourceUrl(src: Source) {
  if (src.kind === "github" && src.github_repo) {
    return `https://github.com/${src.github_repo}${src.github_ref ? `/tree/${src.github_ref}` : ""}`;
  }
  if (src.local_path) return src.local_path;
  return src.version_label;
}

function isScanRunning(status?: string) {
  return status === "QUEUED" || status === "PREPARING" || status === "RUNNING";
}

type PickedFolder = { name: string; path?: string; children: string[] };

function folderFromFiles(files: FileList): PickedFolder {
  const first = files[0] as File & { path?: string; webkitRelativePath?: string };
  const rel = (first.webkitRelativePath || "").replaceAll("\\", "/");
  const name = rel.split("/").find(Boolean) || first.name;
  let path: string | undefined;
  const abs = (first.path || "").replaceAll("\\", "/");
  if (abs) {
    if (rel && abs.endsWith(`/${rel}`)) {
      path = abs.slice(0, abs.length - rel.length - 1);
    } else if (rel) {
      const idx = abs.lastIndexOf(`/${rel}`);
      if (idx >= 0) path = abs.slice(0, idx);
    }
  }
  const children = new Set<string>();
  for (let i = 0; i < files.length && children.size < 40; i += 1) {
    const parts = ((files[i] as File & { webkitRelativePath?: string }).webkitRelativePath || "").replaceAll("\\", "/").split("/");
    if (parts.length > 1 && parts[1]) children.add(parts[1]);
  }
  return { name, path, children: [...children] };
}

export default function ProjectPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const projectId = params.id;
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState("");
  const [kind, setKind] = useState<SourceKind | "">("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [localPath, setLocalPath] = useState("");
  const [folderName, setFolderName] = useState("");
  const [folderMatches, setFolderMatches] = useState<{ path: string; name: string }[]>([]);
  const [showPath, setShowPath] = useState(false);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const [repo, setRepo] = useState("");
  const [ref, setRef] = useState("main");
  const [token, setToken] = useState("");
  const [scanners, setScanners] = useState(["semgrep", "trivy", "gitleaks"]);
  const [progress, setProgress] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [readingFolder, setReadingFolder] = useState(false);
  const [folderHint, setFolderHint] = useState("Reading folder…");
  const [waitSeconds, setWaitSeconds] = useState(0);
  const [readySource, setReadySource] = useState<Source | null>(null);
  const [savedGitHub, setSavedGitHub] = useState<UserSettings | null>(null);
  const folderPickedRef = useRef(false);

  async function loadProject() {
    const p = await api.get<Project>(`/api/v1/projects/${projectId}`);
    setProject(p);
  }

  async function loadScans() {
    const sc = await api.get<{ scans: Scan[] }>(`/api/v1/projects/${projectId}/scans`);
    setScans(sc.scans);
    return sc.scans;
  }

  async function load() {
    await loadProject();
    return loadScans();
  }

  useEffect(() => {
    let stop = false;
    let timer = 0;

    async function refresh(initial: boolean) {
      try {
        if (initial) await loadProject();
        const list = await loadScans();
        if (stop) return;
        if (list.some((scan) => isScanRunning(scan.status))) {
          timer = window.setTimeout(() => refresh(false), 4000);
        }
      } catch (err) {
        if (stop) return;
        if (initial && err instanceof Error) setError(err.message);
        if (!initial) timer = window.setTimeout(() => refresh(false), 8000);
      }
    }

    refresh(true);
    api.get<UserSettings>("/api/v1/settings").then(setSavedGitHub).catch(() => undefined);
    return () => {
      stop = true;
      window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => {
    const input = folderInputRef.current;
    if (!input) return;
    input.setAttribute("webkitdirectory", "");
    input.setAttribute("directory", "");
    input.setAttribute("multiple", "");
    const onCancel = () => cancelFolderWait();
    input.addEventListener("cancel", onCancel);
    return () => input.removeEventListener("cancel", onCancel);
  }, [kind]);

  useEffect(() => {
    if (!readingFolder && !connecting && !busy) {
      setWaitSeconds(0);
      return;
    }
    const timer = window.setInterval(() => setWaitSeconds((n) => n + 1), 1000);
    return () => window.clearInterval(timer);
  }, [readingFolder, connecting, busy]);

  useEffect(() => {
    if (!readingFolder) return;
    function onFocus() {
      if (folderPickedRef.current) return;
      setFolderHint("Reading the folder you picked. Large projects can take a while.");
    }
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [readingFolder]);

  function resetPicker() {
    setReadySource(null);
    setFolderName("");
    setLocalPath("");
    setFolderMatches([]);
    setZipFile(null);
    setProgress(null);
    setError("");
    setReadingFolder(false);
    setFolderHint("Reading folder…");
    folderPickedRef.current = false;
  }

  function cancelFolderWait() {
    folderPickedRef.current = false;
    setReadingFolder(false);
    setConnecting(false);
    setFolderHint("Reading folder…");
  }

  function startFolderWait(hint: string) {
    folderPickedRef.current = false;
    flushSync(() => {
      setReadingFolder(true);
      setFolderHint(hint);
      setError("");
      setReadySource(null);
      setFolderMatches([]);
      setFolderName("");
      setLocalPath("");
    });
  }

  function openFolderPicker() {
    startFolderWait("Waiting for you to pick a folder…");
    const input = folderInputRef.current;
    if (!input) {
      setReadingFolder(false);
      return;
    }
    input.value = "";
    input.click();
  }

  async function uploadZip(event: FormEvent) {
    event.preventDefault();
    if (!zipFile) return;
    setError("");
    setBusy(true);
    setProgress(0);
    try {
      const body = new FormData();
      body.append("file", zipFile);
      const src = await api.upload<Source>(`/api/v1/projects/${projectId}/sources/zip`, body, setProgress);
      setReadySource(src);
      setProgress(100);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "ZIP upload failed");
      setProgress(null);
    } finally {
      setBusy(false);
    }
  }

  async function connectLocal(body: { path?: string; name?: string; children?: string[] }) {
    setError("");
    setConnecting(true);
    try {
      const src = await api.post<Source>(`/api/v1/projects/${projectId}/sources/local`, body);
      if (src.status === "choose" && src.matches?.length) {
        setFolderMatches(src.matches);
        setReadySource(null);
        return;
      }
      setFolderMatches([]);
      setFolderName(src.version_label || folderName);
      setLocalPath(src.local_path || body.path || "");
      setReadySource(src);
      load().catch(() => undefined);
    } catch (err) {
      setReadySource(null);
      setError(err instanceof Error ? err.message : "Could not use that folder");
    } finally {
      setConnecting(false);
      setReadingFolder(false);
    }
  }

  async function onFolderInput(event: ChangeEvent<HTMLInputElement>) {
    const files = event.currentTarget.files;
    if (!files || files.length === 0) {
      cancelFolderWait();
      event.currentTarget.value = "";
      return;
    }
    folderPickedRef.current = true;
    setFolderHint("Finishing folder selection…");
    const picked = folderFromFiles(files);
    setError("");
    setFolderMatches([]);
    setReadySource(null);
    setFolderName(picked.name);
    setLocalPath(picked.path || "");
    setFolderHint(`Connecting ${picked.name}…`);
    event.currentTarget.value = "";
    try {
      if (picked.path) {
        await connectLocal({ path: picked.path });
      } else {
        await connectLocal({ name: picked.name, children: picked.children });
      }
    } finally {
      setReadingFolder(false);
    }
  }

  async function submitLocalPath(event: FormEvent) {
    event.preventDefault();
    const name = localPath.split("/").filter(Boolean).at(-1) || localPath;
    setFolderName(name);
    await connectLocal({ path: localPath });
  }

  async function connectGitHub(event: FormEvent) {
    event.preventDefault();
    setError("");
    setConnecting(true);
    try {
      const src = await api.post<Source>(`/api/v1/projects/${projectId}/sources/github`, { repository: repo, ref, token });
      setReadySource(src);
      setToken("");
      await load();
    } catch (err) {
      setReadySource(null);
      setError(err instanceof Error ? err.message : "GitHub connection failed");
    } finally {
      setConnecting(false);
    }
  }

  async function startScan() {
    if (!readySource) return;
    setError("");
    setBusy(true);
    try {
      const scan = await api.post<Scan>(`/api/v1/projects/${projectId}/scans`, {
        source_id: readySource.id,
        scanners,
      });
      router.push(`/app/projects/${projectId}/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan");
      setBusy(false);
    }
  }

  function toggleScanner(name: string) {
    setScanners((current) => (current.includes(name) ? current.filter((item) => item !== name) : [...current, name]));
  }

  if (!project) return <LoadingScreen label="Loading project…" />;

  const folderVisible = Boolean(folderName || localPath || readySource?.local_path || folderMatches.length > 0);
  const folderLoading = (readingFolder || (connecting && kind === "directory")) && !folderVisible;
  const folderWait = folderLoading
    ? `${folderHint}${waitSeconds > 1 ? ` ${waitSeconds}s` : ""}${waitSeconds > 4 ? " Large projects can take a minute." : ""}`
    : connecting && kind === "directory"
      ? `Connecting ${folderName || "folder"}… ${waitSeconds > 1 ? `${waitSeconds}s` : ""}`
      : "";

  return (
    <main className="mx-auto max-w-3xl space-y-6 px-6 py-8">
      <div>
        <Link href="/app" className="text-sm text-[var(--muted)]">Projects</Link>
        <h1 className="mt-2 text-3xl font-semibold">{project.name}</h1>
        <p className="text-[var(--muted)]">{project.description}</p>
      </div>
      {error && <p className="rounded-md border border-[var(--down)]/40 bg-[var(--down)]/10 px-3 py-2 text-sm text-[var(--down)]">{error}</p>}

      <Card>
        <h2 className="text-lg font-medium">Add source code</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">Point BugCode Shield at any folder, ZIP, or GitHub repo. Only that location is scanned.</p>
        <div className="mt-4">
          <Label>How do you want to add this project?</Label>
          <Select value={kind} onChange={(e) => { setKind(e.target.value as SourceKind | ""); resetPicker(); }}>
            <option value="">Select an option…</option>
            <option value="zip">Upload a ZIP</option>
            <option value="directory">Scan a folder on this computer</option>
            <option value="github">Connect a GitHub repository</option>
          </Select>
        </div>

        {kind === "zip" && (
          <form className="mt-5 space-y-3" onSubmit={uploadZip}>
            <Label>ZIP file</Label>
            <Input type="file" accept=".zip" onChange={(e) => { setZipFile(e.target.files?.[0] ?? null); setReadySource(null); setProgress(null); }} />
            {zipFile && (
              <p className="break-all text-sm">{zipFile.name} · {formatBytes(zipFile.size)}</p>
            )}
            {busy && progress !== null && (
              <div className="space-y-2">
                <InlineWait label={progress < 100 ? `Uploading ${zipFile?.name ?? "archive"}… ${progress}%` : "Extracting on this computer…"} />
                <ProgressBar value={progress} />
              </div>
            )}
            <Button type="submit" loading={busy} disabled={!zipFile}>{busy ? (progress !== null && progress < 100 ? `Uploading ${progress}%` : "Extracting…") : "Add ZIP"}</Button>
          </form>
        )}

        {kind === "directory" && (
          <div className="mt-5 space-y-3">
            <Label>Project folder</Label>
            <input
              ref={folderInputRef}
              type="file"
              className="sr-only"
              onChange={(event) => onFolderInput(event).catch(() => undefined)}
            />
            <Button type="button" loading={readingFolder || connecting} onClick={openFolderPicker}>
              {readingFolder ? "Reading folder…" : connecting ? "Connecting…" : "Choose folder"}
            </Button>
            <div className={`rounded-lg border bg-[#0b1220] p-4 ${folderVisible && !folderLoading ? "border-[var(--accent)]" : "border-[var(--border)]"}`}>
              {folderLoading ? (
                <div className="flex flex-col items-center gap-3 py-6 text-center">
                  <Spinner className="h-8 w-8 text-[var(--accent)]" />
                  <p className="text-sm">{folderWait}</p>
                  {readingFolder && !connecting && (
                    <GhostButton type="button" onClick={cancelFolderWait}>Cancel</GhostButton>
                  )}
                </div>
              ) : folderVisible ? (
                <>
                  <p className="text-xs uppercase tracking-wide text-[var(--ok)]">Selected folder</p>
                  <p className="mt-1 text-lg font-semibold">{folderName || readySource?.version_label}</p>
                  <p className="mt-1 flex items-start gap-2 break-all text-sm text-[var(--muted)]">
                    {connecting && !readySource?.local_path && <Spinner className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />}
                    {readySource?.local_path || localPath || (connecting ? "Finding this folder on your computer…" : "")}
                  </p>
                </>
              ) : (
                <p className="text-sm text-[var(--muted)]">No folder selected yet.</p>
              )}
            </div>
            {folderMatches.length > 0 && (
              <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); connectLocal({ path: localPath }).catch(() => undefined); }}>
                <p className="text-sm">Several folders named {folderName || "this project"} were found. Pick the path to scan.</p>
                {folderMatches.map((item) => (
                  <label key={item.path} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${localPath === item.path ? "border-[var(--accent)]" : "border-[var(--border)]"}`}>
                    <input className="mt-1" type="radio" name="folder-match" checked={localPath === item.path} onChange={() => setLocalPath(item.path)} />
                    <span className="break-all text-sm">{item.path}</span>
                  </label>
                ))}
                <Button type="submit" loading={connecting} disabled={!localPath.trim()}>{connecting ? "Connecting…" : "Use this path"}</Button>
              </form>
            )}
            <GhostButton type="button" onClick={() => setShowPath((open) => !open)}>
              {showPath ? "Hide path field" : "Or paste a full path"}
            </GhostButton>
            {showPath && (
              <form className="space-y-3" onSubmit={submitLocalPath}>
                <Input
                  value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)}
                  placeholder="/home/you/projects/my-app"
                />
                <Button type="submit" loading={connecting} disabled={!localPath.trim()}>{connecting ? "Connecting…" : "Use this path"}</Button>
              </form>
            )}
          </div>
        )}

        {kind === "github" && (
          <form className="mt-5 space-y-3" onSubmit={connectGitHub}>
            <div>
              <Label>GitHub URL or owner/repo</Label>
              <Input value={repo} onChange={(e) => { setRepo(e.target.value); setReadySource(null); }} placeholder="https://github.com/owner/repository" required />
            </div>
            <div>
              <Label>Branch</Label>
              <Input value={ref} onChange={(e) => setRef(e.target.value)} />
            </div>
            <div>
              <Label>Token (private repos only)</Label>
              {savedGitHub?.github_token_set && (
                <p className="mb-2 text-sm text-[var(--ok)]">
                  Using saved GitHub token {savedGitHub.github_token_hint} from{" "}
                  <Link className="underline" href="/app/settings">Settings</Link>. Override below if needed.
                </p>
              )}
              <Input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder={savedGitHub?.github_token_set ? "Optional override" : "Or add a GitHub token in Settings"} />
              {!savedGitHub?.github_token_set && (
                <p className="mt-2 text-xs text-[var(--muted)]">
                  Save a token in <Link className="underline" href="/app/settings">Settings</Link> to reuse it on later projects.
                </p>
              )}
            </div>
            <Button type="submit" loading={connecting} disabled={!repo.trim()}>{connecting ? "Connecting GitHub…" : "Connect repository"}</Button>
            {connecting && kind === "github" && <InlineWait label={`Checking GitHub… ${waitSeconds > 1 ? `${waitSeconds}s` : ""}`} />}
            {readySource?.kind === "github" && (
              <p className="break-all rounded-lg border border-[var(--accent)] bg-[#0b1220] p-4 text-sm font-medium">
                {sourceUrl(readySource)}
              </p>
            )}
          </form>
        )}

        {readySource?.kind === "zip" && (
          <p className="mt-4 break-all rounded-lg border border-[var(--accent)] bg-[#0b1220] p-4 text-sm font-medium">
            {sourceUrl(readySource)}
          </p>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-medium">Scanner tools</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">Pick the tools, then start the scan on the location above.</p>
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {SCANNER_OPTIONS.map((item) => (
            <label key={item.id} className="flex items-start gap-3 rounded-lg border border-[var(--border)] p-3">
              <input className="mt-1" type="checkbox" checked={scanners.includes(item.id)} onChange={() => toggleScanner(item.id)} />
              <span>
                <span className="block font-medium">{item.label}</span>
                <span className="text-xs text-[var(--muted)]">{item.detail}</span>
              </span>
            </label>
          ))}
        </div>
        <Button className="mt-5" type="button" loading={busy} disabled={!readySource || scanners.length === 0} onClick={() => startScan()}>
          {busy ? "Starting scan…" : "Start scan"}
        </Button>
        {busy && <div className="mt-3"><InlineWait label="Starting scan…" /></div>}
        {readySource
          ? <p className="mt-2 break-all text-xs text-[var(--muted)]">{sourceUrl(readySource)}</p>
          : <p className="mt-2 text-xs text-[var(--muted)]">Choose a folder, ZIP, or GitHub repository first.</p>}
      </Card>

      {scans.length > 0 && (
        <Card>
          <h2 className="text-lg font-medium">Previous scans</h2>
          <div className="mt-3 space-y-3">
            {scans.map((scan) => (
              <Link key={scan.id} href={`/app/projects/${projectId}/scans/${scan.id}`} className="block border-b border-[var(--border)] pb-3">
                <p className="font-medium">{scan.status}</p>
                <p className="text-xs text-[var(--muted)]">{scan.finding_count} issues · {scan.source_label || scan.scanners.join(", ")} · {scan.scanners.join(", ")}</p>
              </Link>
            ))}
          </div>
        </Card>
      )}
    </main>
  );
}
