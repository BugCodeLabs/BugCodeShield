"use client";

import { api, setToken, type User } from "@/lib/api";
import { Button, Card, Input, Label } from "@/components/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const result = await api.post<{ token: string; user: User }>("/api/v1/auth/login", { email, password });
      setToken(result.token);
      router.push("/app");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-md items-center px-6">
      <Card className="w-full">
        <h1 className="text-2xl font-semibold">Sign in to BugCode Shield</h1>
        <p className="mt-2 text-sm text-[var(--muted)]">Use the account you registered on this instance.</p>
        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          <div>
            <Label>Email</Label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div>
            <Label>Password</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          {error && <p className="text-sm text-[var(--down)]">{error}</p>}
          <Button type="submit" loading={pending}>{pending ? "Signing in…" : "Sign in"}</Button>
        </form>
        <p className="mt-4 text-sm text-[var(--muted)]">
          No account? <Link className="underline" href="/register">Create one</Link>
        </p>
      </Card>
    </main>
  );
}
