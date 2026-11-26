import Link from "next/link";

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

const steps = [
  { n: "1", title: "Create an account", href: "/register", text: "Name, email, password (8+ characters). You get a default workspace." },
  { n: "2", title: "Create a project", href: "/app", text: "Give it a name. A project is only a label until you attach source." },
  { n: "3", title: "Point at your code", href: "/app", text: "Folder on this PC, a ZIP, or a GitHub repo. Only that location is scanned." },
  { n: "4", title: "Pick scanners", href: "/app", text: "Semgrep, Trivy, Gitleaks. SonarQube and Dependency-Check are optional." },
  { n: "5", title: "Watch the scan", href: "/app", text: "Live logs, then issues. Nothing is listed until every tool finishes." },
  { n: "6", title: "Review and export", href: "/app", text: "Group by hotspot, vulnerability, infrastructure, secret leak, duplication, and quality. Export JSON or SARIF. Ask AI if you saved a key." },
];

const sources = [
  {
    title: "Folder on this computer",
    tag: "Usual path",
    body: "Choose folder, wait until the name is visible, then start. The tree is not uploaded. Scanners mount the path read-only. It must sit under your home directory.",
  },
  {
    title: "ZIP",
    tag: "Archive",
    body: "Select a .zip and wait through upload and extract. Use this when the project is not already on this machine as a folder.",
  },
  {
    title: "GitHub",
    tag: "Remote",
    body: "Paste owner/repo or the URL and the branch. Public repos need no token. Private repos need a token here or in Settings.",
  },
];

const screens = [
  { title: "Register / sign in", detail: "Creates your user. Sign in later from the same browser." },
  { title: "Projects", detail: "List plus New project. Click a card to open it." },
  { title: "Project", detail: "Add source, tick scanners, Start scan. Previous scans are listed below." },
  { title: "Scanning", detail: "QUEUED → PREPARING → RUNNING. Cancel if the folder is wrong." },
  { title: "Issues", detail: "Severity counts, file tree, snippet, JSON/SARIF, Ask AI." },
  { title: "Settings", detail: "Profile icon → Settings. GitHub token and OpenAI key, encrypted." },
];

export default function GuidePage() {
  return (
    <div className="landing relative min-h-screen overflow-x-hidden">
      <div className="landing-stars pointer-events-none absolute inset-0" />

      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
        <Link href="/" className="flex items-center gap-2 text-[var(--foreground)]">
          <ShieldMark className="h-8 w-8 text-cyan-300" />
          <span className="text-lg font-semibold tracking-tight">BugCode Shield</span>
        </Link>
        <nav className="hidden items-center gap-8 text-sm text-[var(--muted)] md:flex">
          <Link href="/guide" className="text-[var(--foreground)]">How to use</Link>
          <Link href="/#scanners" className="hover:text-[var(--foreground)]">Scanners</Link>
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

      <main className="relative z-10 mx-auto max-w-6xl px-6 pb-20 pt-10">
        <p className="text-sm uppercase tracking-[0.22em] text-cyan-300/80">User flow</p>
        <h1 className="mt-3 max-w-2xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          How to scan your project
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-relaxed text-slate-300 sm:text-lg">
          Create an account, attach a folder, ZIP, or GitHub repo, run the scanners, then open issues.
          Your application is not executed on this machine.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link href="/register" className="rounded-full bg-cyan-400 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300">
            Create an account
          </Link>
          <Link href="/app" className="rounded-full border border-white/15 px-5 py-2.5 text-sm text-slate-200 hover:border-cyan-300/50">
            Go to projects
          </Link>
        </div>

        <ol className="mt-16 grid gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-label="User flow from account to issues">
          {steps.map((step, index) => (
            <li
              key={step.n}
              className="relative rounded-2xl border border-white/10 bg-[#0b1220]/80 p-5"
            >
              <p className="text-xs font-semibold text-cyan-300">Step {step.n}</p>
              <h2 className="mt-2 text-lg font-medium text-white">
                <Link href={step.href} className="hover:text-cyan-200">{step.title}</Link>
              </h2>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{step.text}</p>
              {index < steps.length - 1 && (
                <p className="mt-4 text-xs text-cyan-300/70">Next → {steps[index + 1].title}</p>
              )}
            </li>
          ))}
        </ol>

        <section className="mt-20" aria-labelledby="source-heading">
          <h2 id="source-heading" className="text-3xl font-semibold text-white">Add your code</h2>
          <p className="mt-3 max-w-2xl text-slate-300">
            On the project page, pick one source. Folders stay on disk. ZIP is extracted locally. GitHub is cloned by the worker.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {sources.map((item) => (
              <article key={item.title} className="rounded-2xl border border-white/10 bg-[#0b1220]/80 p-6">
                <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300/80">{item.tag}</p>
                <h3 className="mt-3 text-xl font-medium text-white">{item.title}</h3>
                <p className="mt-3 text-sm leading-relaxed text-slate-400">{item.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="mt-20" aria-labelledby="screens-heading">
          <h2 id="screens-heading" className="text-3xl font-semibold text-white">What each screen is for</h2>
          <ol className="mt-8 overflow-hidden rounded-2xl border border-white/10">
            {screens.map((item, index) => (
              <li
                key={item.title}
                className="grid gap-2 border-b border-white/10 bg-[#0b1220]/70 px-5 py-4 last:border-b-0 sm:grid-cols-[9rem_1fr] sm:items-baseline"
              >
                <p className="text-sm font-medium text-cyan-300">{index + 1}. {item.title}</p>
                <p className="text-sm text-slate-300">{item.detail}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="mt-20" aria-labelledby="review-heading">
          <h2 id="review-heading" className="text-3xl font-semibold text-white">After the scan</h2>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <article className="rounded-2xl border border-white/10 bg-[#0b1220]/80 p-6">
              <h3 className="text-lg font-medium text-white">Issues dashboard</h3>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-400">
                <li>Click a severity count to filter.</li>
                <li>Use the file directory to jump to one path.</li>
                <li>Open an issue for file, line, snippet, and remediation.</li>
                <li>Export JSON or SARIF from the top of the page.</li>
              </ul>
            </article>
            <article className="rounded-2xl border border-white/10 bg-[#0b1220]/80 p-6">
              <h3 className="text-lg font-medium text-white">Settings and Ask AI</h3>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-400">
                <li>Profile icon → Settings.</li>
                <li>GitHub token for private repositories.</li>
                <li>OpenAI key to explain a finding. Code is never changed for you.</li>
                <li>Saved secrets are encrypted; the UI only shows a hint.</li>
              </ul>
            </article>
          </div>
        </section>

        <p className="mt-16 max-w-2xl text-sm text-slate-400">
          First try: scan <code className="text-cyan-200">testdata/vulnerable-sample</code> in this repo so you see findings.
          If a scan reports 0 issues, you likely pointed at the wrong folder — add the application path and start a new scan.
        </p>
      </main>

      <footer className="relative z-10 border-t border-white/10">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-6 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>BugCode Shield · local security scanning</p>
          <div className="flex gap-5">
            <Link href="/" className="hover:text-slate-200">Home</Link>
            <Link href="/register" className="hover:text-slate-200">Get started</Link>
            <Link href="/status" className="hover:text-slate-200">Infrastructure</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
