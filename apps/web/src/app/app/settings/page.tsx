"use client";

import { api, type UserSettings } from "@/lib/api";
import { Button, Card, GhostButton, Input, Label, LoadingScreen } from "@/components/ui";
import { FormEvent, useEffect, useState } from "react";

const emptySettings: UserSettings = {
  github_token_set: false,
  openai_api_key_set: false,
  openai_base_url: "",
  openai_model: "",
};

export default function SettingsPage() {
  const [settings, setSettings] = useState<UserSettings>(emptySettings);
  const [githubToken, setGithubToken] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [openaiBase, setOpenaiBase] = useState("");
  const [openaiModel, setOpenaiModel] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState("");

  function apply(view: UserSettings) {
    setSettings(view);
    setOpenaiBase(view.openai_base_url);
    setOpenaiModel(view.openai_model);
    setGithubToken("");
    setOpenaiKey("");
  }

  useEffect(() => {
    api.get<UserSettings>("/api/v1/settings")
      .then(apply)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function onSave(event: FormEvent) {
    event.preventDefault();
    setError("");
    setSaved("");
    setSaving(true);
    try {
      const body: Record<string, string> = {
        openai_base_url: openaiBase,
        openai_model: openaiModel,
      };
      if (githubToken.trim()) body.github_token = githubToken.trim();
      if (openaiKey.trim()) body.openai_api_key = openaiKey.trim();
      const view = await api.put<UserSettings>("/api/v1/settings", body);
      apply(view);
      setSaved("Settings saved. These credentials stay on this instance and are reused for GitHub and Ask AI.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save settings");
    } finally {
      setSaving(false);
    }
  }

  async function clearToken(kind: "github" | "openai") {
    setError("");
    setSaved("");
    setClearing(kind);
    try {
      const view = await api.put<UserSettings>("/api/v1/settings", kind === "github"
        ? { clear_github_token: true }
        : { clear_openai_api_key: true });
      apply(view);
      setSaved(kind === "github" ? "GitHub token removed." : "OpenAI key removed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove credential");
    } finally {
      setClearing("");
    }
  }

  if (loading) return <LoadingScreen label="Loading settings…" />;

  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-8">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Save tokens once. BugCode Shield encrypts them and uses them later for private GitHub repos and Ask AI.
        </p>
      </div>
      {error && <p className="rounded-md border border-[var(--down)]/40 bg-[var(--down)]/10 px-3 py-2 text-sm text-[var(--down)]">{error}</p>}
      {saved && <p className="rounded-md border border-[var(--ok)]/40 bg-[var(--ok)]/10 px-3 py-2 text-sm text-[var(--ok)]">{saved}</p>}

      <form className="space-y-6" onSubmit={onSave}>
        <Card>
          <h2 className="text-lg font-medium">GitHub</h2>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Personal access token with repo read access. Used when you connect a private repository.
          </p>
          <div className="mt-4 space-y-3">
            <Label>GitHub token</Label>
            {settings.github_token_set && (
              <p className="text-sm text-[var(--ok)]">Saved token {settings.github_token_hint}. Leave blank to keep it.</p>
            )}
            <Input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder={settings.github_token_set ? "Enter a new token to replace it" : "ghp_…"}
              autoComplete="off"
            />
            {settings.github_token_set && (
              <GhostButton type="button" loading={clearing === "github"} onClick={() => clearToken("github")}>
                {clearing === "github" ? "Removing…" : "Remove GitHub token"}
              </GhostButton>
            )}
          </div>
        </Card>

        <Card>
          <h2 className="text-lg font-medium">OpenAI / AI assistant</h2>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Required for Ask AI on each finding. Compatible OpenAI-style endpoints also work if you set a base URL.
          </p>
          <div className="mt-4 space-y-3">
            <div>
              <Label>API key</Label>
              {settings.openai_api_key_set && (
                <p className="mb-2 text-sm text-[var(--ok)]">Saved key {settings.openai_api_key_hint}. Leave blank to keep it.</p>
              )}
              <Input
                type="password"
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                placeholder={settings.openai_api_key_set ? "Enter a new key to replace it" : "sk-…"}
                autoComplete="off"
              />
            </div>
            <div>
              <Label>Model</Label>
              <Input value={openaiModel} onChange={(e) => setOpenaiModel(e.target.value)} placeholder="gpt-4o-mini" />
            </div>
            <div>
              <Label>API base URL (optional)</Label>
              <Input value={openaiBase} onChange={(e) => setOpenaiBase(e.target.value)} placeholder="https://api.openai.com/v1" />
            </div>
            {settings.openai_api_key_set && (
              <GhostButton type="button" loading={clearing === "openai"} onClick={() => clearToken("openai")}>
                {clearing === "openai" ? "Removing…" : "Remove OpenAI key"}
              </GhostButton>
            )}
          </div>
        </Card>

        <Button type="submit" loading={saving}>{saving ? "Saving…" : "Save settings"}</Button>
      </form>
    </main>
  );
}
