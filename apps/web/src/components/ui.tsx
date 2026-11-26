import { cn } from "@/lib/cn";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn("inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent", className)}
      aria-hidden
    />
  );
}

export function LoadingScreen({ label }: { label: string }) {
  return (
    <main className="mx-auto flex min-h-[40vh] flex-col items-center justify-center gap-3 px-6 text-center">
      <Spinner className="h-10 w-10 text-[var(--accent)]" />
      <p className="text-[var(--muted)]">{label}</p>
    </main>
  );
}

export function InlineWait({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-[var(--accent)] bg-[#0b1220] p-4">
      <Spinner className="h-6 w-6 shrink-0 text-[var(--accent)]" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("rounded-xl border border-[var(--border)] bg-[var(--card)] p-5", className)}>{children}</div>;
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean };

export function Button({ className, loading, children, disabled, ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-slate-950 disabled:opacity-50",
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
}

export function GhostButton({ className, loading, children, disabled, ...props }: ButtonProps) {
  return (
    <button
      className={cn("inline-flex items-center justify-center gap-2 rounded-md border border-[var(--border)] px-3 py-2 text-sm hover:border-[var(--muted)] disabled:opacity-50", className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "w-full rounded-md border border-[var(--border)] bg-[#0b1220] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <label className="mb-1 block text-sm text-[var(--muted)]">{children}</label>;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "w-full rounded-md border border-[var(--border)] bg-[#0b1220] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]",
        className,
      )}
      {...props}
    />
  );
}

export function ProgressBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div className="h-2 overflow-hidden rounded-full bg-[#0b1220]">
      <div className="h-full bg-[var(--accent)] transition-[width]" style={{ width: `${pct}%` }} />
    </div>
  );
}

export function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="rounded-full border border-[var(--accent)] px-2 py-0.5 text-xs text-[var(--accent)]">
      {category}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const color: Record<string, string> = {
    critical: "text-[var(--critical)] border-[var(--critical)]",
    high: "text-[var(--high)] border-[var(--high)]",
    medium: "text-[var(--medium)] border-[var(--medium)]",
    low: "text-[var(--low)] border-[var(--low)]",
    info: "text-[var(--info)] border-[var(--info)]",
  };
  return (
    <span className={cn("rounded-full border px-2 py-0.5 text-xs uppercase", color[severity] ?? color.info)}>
      {severity}
    </span>
  );
}
