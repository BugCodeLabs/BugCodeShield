"use client";

import { api, type Organization, type Project } from "@/lib/api";
import { Button, Card, Input, Label, LoadingScreen } from "@/components/ui";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

export default function ProjectsPage() {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  async function load() {
    const orgRes = await api.get<{ organizations: Organization[] }>("/api/v1/orgs");
    setOrgs(orgRes.organizations);
    const projectRes = await api.get<{ projects: Project[] }>("/api/v1/projects");
    setProjects(projectRes.projects);
  }

  useEffect(() => {
    load()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    if (!orgs[0]) return;
    setError("");
    setCreating(true);
    try {
      await api.post(`/api/v1/orgs/${orgs[0].id}/projects`, { name, description });
      setName("");
      setDescription("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setCreating(false);
    }
  }

  if (loading) return <LoadingScreen label="Loading projects…" />;

  return (
    <main className="mx-auto grid max-w-5xl gap-6 px-6 py-8 lg:grid-cols-[1fr_280px]">
      <section className="space-y-4">
        <h1 className="text-2xl font-semibold">Projects</h1>
        {projects.length === 0 && (
          <p className="text-[var(--muted)]">
            No projects yet. Create one to start scanning.
          </p>
        )}
        {projects.map((project) => (
          <Link key={project.id} href={`/app/projects/${project.id}`}>
            <Card className="mb-3 hover:border-[var(--accent)]">
              <h2 className="text-lg font-medium">{project.name}</h2>
              <p className="text-sm text-[var(--muted)]">{project.description || "No description"}</p>
            </Card>
          </Link>
        ))}
      </section>
      <Card>
        <h2 className="text-lg font-medium">New project</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">Created in {orgs[0]?.name ?? "your organization"}.</p>
        <form className="mt-4 space-y-3" onSubmit={onCreate}>
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div>
            <Label>Description</Label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          {error && <p className="text-sm text-[var(--down)]">{error}</p>}
          <Button type="submit" loading={creating}>{creating ? "Creating…" : "Create"}</Button>
        </form>
      </Card>
    </main>
  );
}
