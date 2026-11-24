"use client";

import { api, type Organization, type User } from "@/lib/api";
import { Button, Card, Input, Label, LoadingScreen } from "@/components/ui";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

export default function ProfilePage() {
  const [user, setUser] = useState<User | null>(null);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    Promise.all([
      api.get<User>("/api/v1/auth/me"),
      api.get<{ organizations: Organization[] }>("/api/v1/orgs"),
    ])
      .then(([me, orgRes]) => {
        setUser(me);
        setName(me.name);
        setOrgs(orgRes.organizations);
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function onSave(event: FormEvent) {
    event.preventDefault();
    setError("");
    setSaved("");
    setSaving(true);
    try {
      const updated = await api.patch<User>("/api/v1/auth/me", { name });
      setUser(updated);
      setName(updated.name);
      setSaved("Profile saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save profile");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <LoadingScreen label="Loading profile…" />;
  if (!user) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-8">
        <p className="text-sm text-[var(--down)]">{error || "Could not load profile."}</p>
      </main>
    );
  }

  const joined = user.created_at
    ? new Date(user.created_at).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })
    : "—";

  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-8">
      <div>
        <h1 className="text-2xl font-semibold">Profile</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">Your account on this BugCode Shield instance.</p>
      </div>

      <Card>
        <form className="space-y-4" onSubmit={onSave}>
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} required minLength={2} />
          </div>
          <div>
            <Label>Email</Label>
            <Input value={user.email} readOnly />
          </div>
          <div>
            <Label>Member since</Label>
            <p className="text-sm">{joined}</p>
          </div>
          {error && <p className="text-sm text-[var(--down)]">{error}</p>}
          {saved && <p className="text-sm text-[var(--ok)]">{saved}</p>}
          <Button type="submit" loading={saving}>{saving ? "Saving…" : "Save profile"}</Button>
        </form>
      </Card>

      <Card>
        <h2 className="text-lg font-medium">Workspace</h2>
        <div className="mt-3 space-y-3">
          {orgs.length === 0 && <p className="text-sm text-[var(--muted)]">No workspace found.</p>}
          {orgs.map((org) => (
            <div key={org.id} className="rounded-lg border border-[var(--border)] bg-[#0b1220] p-4">
              <p className="font-medium">{org.name}</p>
              <p className="text-sm text-[var(--muted)]">{org.role} · {org.slug}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 text-sm text-[var(--muted)]">
          Tokens for GitHub and Ask AI live in{" "}
          <Link className="underline" href="/app/settings">Settings</Link>.
        </p>
      </Card>
    </main>
  );
}
