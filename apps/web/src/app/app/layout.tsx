"use client";

import { api, getToken, setToken, type User } from "@/lib/api";
import { LoadingScreen } from "@/components/ui";
import { cn } from "@/lib/cn";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

function NavLink({ href, label, pathname }: { href: string; label: string; pathname: string }) {
  const active = href === "/app"
    ? pathname === "/app" || pathname.startsWith("/app/projects")
    : pathname === href || pathname.startsWith(`${href}/`);
  return (
    <Link href={href} className={cn("hover:text-[var(--foreground)]", active && "text-[var(--foreground)]")}>
      {label}
    </Link>
  );
}

function ProfileGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <circle cx="12" cy="8" r="3.4" stroke="currentColor" strokeWidth="1.75" />
      <path d="M5.2 19.4c1-3.4 3.4-5.15 6.8-5.15s5.8 1.75 6.8 5.15" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

function UserMenu({ user }: { user: User }) {
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const onAccountPage = pathname.startsWith("/app/profile") || pathname.startsWith("/app/settings");

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "flex h-9 w-9 items-center justify-center rounded-full border text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--foreground)]",
          (open || onAccountPage) ? "border-[var(--accent)] text-[var(--foreground)]" : "border-[var(--border)]",
        )}
      >
        <ProfileGlyph className="h-5 w-5" />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-20 mt-2 w-64 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--card)] shadow-lg"
        >
          <div className="border-b border-[var(--border)] px-4 py-3">
            <p className="truncate text-sm font-medium text-[var(--foreground)]">{user.name}</p>
            <p className="truncate text-xs text-[var(--muted)]">{user.email}</p>
          </div>
          <Link
            role="menuitem"
            href="/app/profile"
            className={cn(
              "block px-4 py-2.5 text-sm hover:bg-[#0b1220]",
              pathname.startsWith("/app/profile") && "text-[var(--accent)]",
            )}
          >
            Profile
          </Link>
          <Link
            role="menuitem"
            href="/app/settings"
            className={cn(
              "block px-4 py-2.5 text-sm hover:bg-[#0b1220]",
              pathname.startsWith("/app/settings") && "text-[var(--accent)]",
            )}
          >
            Settings
          </Link>
          <button
            type="button"
            role="menuitem"
            className="block w-full border-t border-[var(--border)] px-4 py-2.5 text-left text-sm text-[var(--muted)] hover:bg-[#0b1220] hover:text-[var(--foreground)]"
            onClick={() => {
              setToken(null);
              router.push("/login");
            }}
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    api.get<User>("/api/v1/auth/me").then(setUser).catch(() => {
      setToken(null);
      router.replace("/login");
    });
  }, [router, pathname]);

  if (!user) {
    return <LoadingScreen label="Loading…" />;
  }

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-[var(--border)] px-6 py-4">
        <Link href="/app" className="text-lg font-semibold">BugCode Shield</Link>
        <nav className="flex items-center gap-5 text-sm text-[var(--muted)]">
          <NavLink href="/app" label="Projects" pathname={pathname} />
          <NavLink href="/app/status" label="Infrastructure" pathname={pathname} />
          <UserMenu user={user} />
        </nav>
      </header>
      {children}
    </div>
  );
}
