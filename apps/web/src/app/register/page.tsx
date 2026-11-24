"use client";

import { api, setToken, type User } from "@/lib/api";
import { Button, Card, Input, Label, LoadingScreen } from "@/components/ui";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useState } from "react";

function RegisterForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [name, setName] = useState("");
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const result = await api.post<{ token: string; user: User }>("/api/v1/auth/register", { name, email, password });
      setToken(result.token);
      router.push("/app");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-md items-center px-6">
      <Card className="w-full">
        <h1 className="text-2xl font-semibold">Create a BugCode Shield account</h1>
        <p className="mt-2 text-sm text-[var(--muted)]">This creates your user and a default organization.</p>
        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} required minLength={2} />
          </div>
          <div>
            <Label>Email</Label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div>
            <Label>Password</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
          </div>
          {error && <p className="text-sm text-[var(--down)]">{error}</p>}
          <Button type="submit" loading={pending}>{pending ? "Creating…" : "Create account"}</Button>
        </form>
        <p className="mt-4 text-sm text-[var(--muted)]">
          Already registered? <Link className="underline" href="/login">Sign in</Link>
        </p>
      </Card>
    </main>
  );
}

export default function RegisterPage() {
  return (
    <Suspense fallback={<LoadingScreen label="Loading…" />}>
      <RegisterForm />
    </Suspense>
  );
}
