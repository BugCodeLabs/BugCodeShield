const TOKEN_KEY = "bugcodeshield_token";

export function getToken() {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

let cachedWsOrigin: string | null = null;

export async function getWsOrigin(): Promise<string> {
  if (cachedWsOrigin) return cachedWsOrigin;
  try {
    const response = await fetch("/api/runtime", { cache: "no-store" });
    const data = (await response.json()) as { wsOrigin?: string };
    if (data.wsOrigin) {
      cachedWsOrigin = data.wsOrigin;
      return cachedWsOrigin;
    }
  } catch {
    // Browser talks to the API host directly; the Next.js /backend proxy cannot upgrade WebSockets.
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  cachedWsOrigin = `${proto}//${window.location.hostname}:3001`;
  return cachedWsOrigin;
}

export function scanSocketURL(origin: string, scanId: string, token: string) {
  const base = origin.replace(/\/$/, "");
  const url = new URL(`${base}/api/v1/scans/${encodeURIComponent(scanId)}/ws`);
  url.searchParams.set("token", token);
  return url.toString();
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`/backend${path}`, { ...init, headers, cache: "no-store" });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body ?? {}) }),
  upload: <T>(path: string, body: FormData, onProgress?: (percent: number) => void) =>
    uploadWithProgress<T>(path, body, onProgress),
};

function uploadWithProgress<T>(path: string, body: FormData, onProgress?: (percent: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/backend${path}`);
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    };
    xhr.onload = () => {
      let data: { error?: string } = {};
      try {
        data = xhr.responseText ? JSON.parse(xhr.responseText) : {};
      } catch {
        reject(new Error("Upload failed"));
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(data.error || `Request failed (${xhr.status})`));
        return;
      }
      resolve(data as T);
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    xhr.send(body);
  });
}

export type User = { id: string; email: string; name: string; created_at?: string };
export type UserSettings = {
  github_token_set: boolean;
  github_token_hint?: string;
  openai_api_key_set: boolean;
  openai_api_key_hint?: string;
  openai_base_url: string;
  openai_model: string;
};
export type Organization = { id: string; name: string; slug: string; role: string };
export type Project = {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  created_at: string;
};
export type Source = {
  id: string;
  kind: string;
  version_label: string;
  github_repo?: string;
  github_ref?: string;
  commit_sha?: string;
  local_path?: string;
  file_count: number;
  byte_size: number;
  created_at: string;
  status?: string;
  message?: string;
  matches?: { path: string; name: string }[];
};
export type Scan = {
  id: string;
  status: string;
  scanners: string[];
  error_message?: string;
  finding_count: number;
  created_at: string;
  finished_at?: string;
  source_kind?: string;
  source_label?: string;
  github_repo?: string;
  local_path?: string;
};
export type ScanLog = {
  scanner?: string;
  level: string;
  message: string;
  created_at: string;
};
export type Finding = {
  id: string;
  scanner: string;
  rule_id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category?: string;
  cwe?: string;
  cve?: string;
  file_path?: string;
  start_line?: number;
  end_line?: number;
  snippet?: string;
  remediation?: string;
};
