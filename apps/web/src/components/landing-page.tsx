"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <path
        d="M16 3.2 6.5 7.2v7.3c0 6.2 4.1 11.8 9.5 13.3 5.4-1.5 9.5-7.1 9.5-13.3V7.2L16 3.2Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M16 10.2v11.2M11.2 14.4h9.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function Scene() {
  return (
    <svg viewBox="0 0 720 520" className="h-full w-full" aria-hidden>
      <defs>
        <radialGradient id="planet" cx="50%" cy="38%" r="62%">
          <stop offset="0%" stopColor="#7ef0ff" />
          <stop offset="35%" stopColor="#22d3ee" />
          <stop offset="100%" stopColor="#075985" />
        </radialGradient>
        <linearGradient id="beam" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#67e8f9" stopOpacity="0" />
        </linearGradient>
        <pattern id="grid" width="28" height="16" patternUnits="userSpaceOnUse">
          <path d="M0 16 L14 0 L28 16" fill="none" stroke="#38bdf8" strokeOpacity="0.28" strokeWidth="0.7" />
        </pattern>
      </defs>
      <path d="M0 360 Q120 300 240 340 T480 320 T720 360 V520 H0Z" fill="url(#grid)" />
      <path d="M0 400 Q180 330 360 390 T720 370 V520 H0Z" fill="#07101f" fillOpacity="0.55" />
      <path d="M0 400 Q180 330 360 390 T720 370 V520 H0Z" fill="none" stroke="#38bdf8" strokeOpacity="0.35" />
      <circle cx="590" cy="92" r="58" fill="url(#planet)" />
      <circle cx="590" cy="92" r="78" fill="none" stroke="#67e8f9" strokeOpacity="0.25" />
      <circle cx="572" cy="78" r="10" fill="#ecfeff" fillOpacity="0.35" />
      <line x1="548" y1="130" x2="318" y2="310" stroke="url(#beam)" strokeWidth="2" />
      <line x1="575" y1="145" x2="338" y2="318" stroke="url(#beam)" strokeWidth="1.4" />
      <line x1="610" y1="148" x2="430" y2="340" stroke="url(#beam)" strokeWidth="1.2" />
      <g fill="#0b1a33" stroke="#38bdf8" strokeOpacity="0.7" strokeWidth="1">
        <rect x="430" y="348" width="42" height="42" transform="rotate(-12 451 369)" />
        <rect x="500" y="368" width="34" height="34" transform="rotate(18 517 385)" />
        <rect x="620" y="330" width="46" height="46" transform="rotate(-8 643 353)" />
      </g>
      <g fill="#0a1628" stroke="#7dd3fc" strokeWidth="1.4">
        <circle cx="332" cy="268" r="16" />
        <path d="M316 288c4-22 28-22 32 0v46h-32z" />
        <path d="M322 300 h-18 v28 h18z" />
        <path d="M358 300 h16 v26 h-16z" />
        <path d="M318 348 h28 v8 h-28z" />
      </g>
    </svg>
  );
}

const solutions = [
  {
    title: "Code check",
    tools: "Semgrep · SonarQube",
    text: "Static analysis of your source for insecure patterns, unsafe APIs, OWASP issues, bugs, and code smells — with file and line in the dashboard.",
  },
  {
    title: "Vulnerability check",
    tools: "Trivy · Dependency-Check",
    text: "Find known CVEs in dependencies, lockfiles, and the filesystem. Optional OWASP Dependency-Check adds a slower, deeper SCA pass.",
  },
  {
    title: "Security hotspot check",
    tools: "SonarQube",
    text: "Flag sensitive code paths (crypto, auth, injection sinks) that need a human review, not only confirmed vulnerabilities.",
  },
  {
    title: "Secret leak check",
    tools: "Gitleaks · Trivy",
    text: "Detect API keys, tokens, and credentials in files. Values are redacted in logs and findings before they reach the UI.",
  },
  {
    title: "Misconfiguration check",
    tools: "Trivy",
    text: "Scan IaC and config files for unsafe defaults, exposed services, and other misconfig next to the CVE results.",
  },
  {
    title: "Dependency check",
    tools: "Trivy · Dependency-Check",
    text: "Inventory packages and report vulnerable versions, plus a fix version when the scanner knows one.",
  },
  {
    title: "Quality and reliability check",
    tools: "SonarQube",
    text: "Bugs and maintainability findings from Community Build, imported into the same issue list as security results.",
  },
  {
    title: "One review surface",
    tools: "Dashboard",
    text: "Live scanner logs, severity filters, JSON/SARIF export, and optional Ask AI. You pick which tools run on each scan.",
  },
];

const scanners = [
  {
    name: "Semgrep",
    tag: "Code issues",
    title: "Catch insecure code as it is written",
    body: "SAST rules for OWASP, secrets, and language packs. File, line, and snippet in one view.",
    checks: ["Code check", "OWASP SAST"],
    stat: "SAST",
    tone: "from-cyan-400/20 to-sky-950/40 border-cyan-400/30",
  },
  {
    name: "Trivy",
    tag: "CVEs & config",
    title: "Find reachable vulnerabilities and misconfig",
    body: "Filesystem, dependencies, and IaC in one pass. Results land next to Semgrep findings.",
    checks: ["Vulnerability check", "Dependency check", "Misconfiguration check"],
    stat: "SCA",
    tone: "from-orange-400/20 to-amber-950/40 border-orange-400/30",
  },
  {
    name: "Gitleaks",
    tag: "Secrets",
    title: "Stop leaked keys before they ship",
    body: "Token and credential detection with redacted logs. Saved GitHub tokens stay encrypted.",
    checks: ["Secret leak check"],
    stat: "Secrets",
    tone: "from-violet-400/20 to-indigo-950/40 border-violet-400/30",
  },
  {
    name: "SonarQube",
    tag: "Quality + SAST",
    title: "Bugs, smells, and security hotspots",
    body: "Community Build analysis lands in the same issues list. Optional, like Dependency-Check.",
    checks: ["Security hotspot check", "Code check", "Quality check"],
    stat: "Quality",
    tone: "from-emerald-400/20 to-teal-950/40 border-emerald-400/30",
  },
];

const steps = [
  { n: "01", title: "Point at source", text: "Scan a folder on this computer, upload a ZIP, or connect GitHub. Code stays in place." },
  { n: "02", title: "Pick scanners", text: "Semgrep, Trivy, Gitleaks, plus optional SonarQube and Dependency-Check. Run only what you need." },
  { n: "03", title: "Watch live logs", text: "The scan page shows each tool starting, running, and finishing before issues appear." },
  { n: "04", title: "Review issues", text: "Severity, file tree, code location, export, and Ask AI from Settings." },
];

export function LandingPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");

  function onStart(event: FormEvent) {
    event.preventDefault();
    const next = email.trim() ? `/register?email=${encodeURIComponent(email.trim())}` : "/register";
    router.push(next);
  }

  return (
    <div className="landing relative min-h-screen overflow-x-hidden">
      <div className="landing-stars pointer-events-none absolute inset-0" />
      <div className="pointer-events-none absolute -right-24 top-10 h-[28rem] w-[28rem] rounded-full bg-cyan-400/10 blur-3xl" />

      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
        <Link href="/" className="flex items-center gap-2 text-[var(--foreground)]">
          <ShieldMark className="h-8 w-8 text-cyan-300" />
          <span className="text-lg font-semibold tracking-tight">BugCode Shield</span>
        </Link>
        <nav className="hidden items-center gap-8 text-sm text-[var(--muted)] md:flex">
          <a href="#solutions" className="hover:text-[var(--foreground)]">Solutions</a>
          <a href="#scanners" className="hover:text-[var(--foreground)]">Scanners</a>
          <Link href="/guide" className="hover:text-[var(--foreground)]">How to use</Link>
          <Link href="/status" className="hover:text-[var(--foreground)]">Infrastructure</Link>
        </nav>
        <div className="flex items-center gap-3 text-sm">
          <Link href="/login" className="hidden px-3 py-2 text-[var(--muted)] hover:text-[var(--foreground)] sm:inline">
            Sign in
          </Link>
          <Link href="/register" className="rounded-full bg-cyan-400 px-4 py-2 font-medium text-slate-950 hover:bg-cyan-300">
            Get started
          </Link>
        </div>
      </header>

      <section className="relative z-10 mx-auto grid max-w-6xl items-center gap-6 px-6 pb-8 pt-10 md:grid-cols-[1.05fr_0.95fr] md:pb-4 md:pt-16">
        <div>
          <p className="text-sm uppercase tracking-[0.22em] text-cyan-300/80">Local-first code security</p>
          <h1 className="mt-4 max-w-xl text-4xl font-semibold leading-[1.08] tracking-tight text-white sm:text-6xl">
            BugCode Shield
          </h1>
          <p className="mt-3 text-xl font-medium text-slate-200 sm:text-2xl">The all-in-one security scanner</p>
          <p className="mt-5 max-w-lg text-base leading-relaxed text-slate-300 sm:text-lg">
            Code check, vulnerability check, security hotspot check, secret leak check, and more — from Semgrep, Trivy, Gitleaks, and optional SonarQube in one dashboard. Point it at a folder, ZIP, or GitHub repo; the project is scanned in place.
          </p>
          <form className="mt-8 flex max-w-md flex-col gap-3 sm:flex-row" onSubmit={onStart}>
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="Email"
              className="h-12 flex-1 rounded-full border border-white/15 bg-white/5 px-5 text-sm text-white outline-none placeholder:text-slate-400 focus:border-cyan-300"
            />
            <button type="submit" className="h-12 rounded-full bg-cyan-400 px-6 text-sm font-semibold text-slate-950 hover:bg-cyan-300">
              Get started
            </button>
          </form>
          <div className="mt-4 flex flex-wrap items-center gap-4 text-sm">
            <Link href="/register" className="font-medium text-cyan-300 hover:text-cyan-200">
              Create a free account →
            </Link>
            <Link href="/login" className="rounded-lg border border-white/15 px-4 py-2 text-slate-200 hover:border-cyan-300/50">
              Sign in
            </Link>
          </div>
          <p className="mt-6 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
            <span>Go API + Next.js</span>
            <span>Isolated Docker scanners</span>
            <span>Folder · ZIP · GitHub</span>
          </p>
        </div>
        <div className="relative h-[320px] sm:h-[420px] md:h-[500px]">
          <Scene />
        </div>
      </section>

      <section id="solutions" className="relative z-10 mx-auto max-w-6xl px-6 pb-16">
        <p className="text-sm uppercase tracking-[0.22em] text-cyan-300/80">Solutions</p>
        <h2 className="mt-3 max-w-3xl text-3xl font-semibold text-white sm:text-4xl">What this site checks</h2>
        <p className="mt-3 max-w-2xl text-slate-300">
          Each check is backed by the scanners above. You enable the tools you want; findings land in one issues list.
        </p>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {solutions.map((item) => (
            <article key={item.title} className="rounded-2xl border border-white/10 bg-[#0b1220]/80 p-5">
              <h3 className="text-lg font-medium text-white">{item.title}</h3>
              <p className="mt-2 text-xs font-medium uppercase tracking-wider text-cyan-300/80">{item.tools}</p>
              <p className="mt-3 text-sm leading-relaxed text-slate-400">{item.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="scanners" className="relative z-10 mx-auto max-w-6xl px-6 pb-20">
        <p className="mb-6 text-sm uppercase tracking-[0.22em] text-cyan-300/80">Scanners</p>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {scanners.map((item) => (
            <article
              key={item.name}
              className={`rounded-2xl border bg-gradient-to-br p-6 ${item.tone}`}
            >
              <p className="text-xs font-semibold uppercase tracking-wider text-white/70">{item.tag}</p>
              <h2 className="mt-4 text-2xl font-semibold text-white">{item.title}</h2>
              <p className="mt-3 text-sm leading-relaxed text-slate-300">{item.body}</p>
              <ul className="mt-4 space-y-1 text-xs text-white/75">
                {item.checks.map((check) => (
                  <li key={check}>· {check}</li>
                ))}
              </ul>
              <div className="mt-8 flex items-end justify-between">
                <p className="text-4xl font-semibold text-white">{item.stat}</p>
                <p className="text-sm font-medium text-white/80">{item.name}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="how" className="relative z-10 border-t border-white/10 bg-black/20">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <p className="text-sm uppercase tracking-[0.22em] text-cyan-300/80">Workflow</p>
          <h2 className="mt-3 text-3xl font-semibold text-white sm:text-4xl">From folder to findings</h2>
          <p className="mt-3 max-w-2xl text-slate-300">
            Same flow every time: add source, start scan, watch logs, then open issues. No scanner CLI on your laptop.
          </p>
          <Link href="/guide" className="mt-4 inline-block text-sm font-medium text-cyan-300 hover:text-cyan-200">
            Full user guide →
          </Link>
          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {steps.map((step) => (
              <article key={step.n} className="rounded-2xl border border-white/10 bg-[#0b1220]/80 p-5">
                <p className="text-xs font-semibold text-cyan-300">{step.n}</p>
                <h3 className="mt-3 text-lg font-medium text-white">{step.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{step.text}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <footer className="relative z-10 border-t border-white/10">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-6 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>BugCode Shield · local security scanning</p>
          <div className="flex gap-5">
            <Link href="/#solutions" className="hover:text-slate-200">Solutions</Link>
            <Link href="/guide" className="hover:text-slate-200">How to use</Link>
            <Link href="/login" className="hover:text-slate-200">Sign in</Link>
            <Link href="/register" className="hover:text-slate-200">Get started</Link>
            <Link href="/status" className="hover:text-slate-200">Infrastructure</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
