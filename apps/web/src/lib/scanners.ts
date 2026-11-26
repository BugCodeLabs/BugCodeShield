export type ScannerGuide = {
  id: string;
  label: string;
  purpose: string;
  scans: string;
  bestFor: string;
};

export const SCANNER_GUIDE: ScannerGuide[] = [
  {
    id: "semgrep",
    label: "Semgrep",
    purpose: "Application Security scanning (SAST)",
    scans: "Your custom source code",
    bestFor: "Security vulnerabilities and custom coding rules",
  },
  {
    id: "trivy",
    label: "Trivy",
    purpose: "Infrastructure & supply chain security",
    scans: "Dependencies, containers, and infrastructure as code",
    bestFor: "Known vulnerabilities (CVEs) in third-party packages and cloud configs",
  },
  {
    id: "gitleaks",
    label: "Gitleaks",
    purpose: "Secret leak detection",
    scans: "Source files and Git history",
    bestFor: "API keys, tokens, and passwords committed in the repository",
  },
  {
    id: "sonarqube",
    label: "SonarQube",
    purpose: "Code quality & maintainability",
    scans: "Your custom source code",
    bestFor: "Bugs, code smells, security hotspots, and quality gates",
  },
  {
    id: "dependency-check",
    label: "Dependency-Check",
    purpose: "Software composition analysis (SCA)",
    scans: "Third-party libraries and lockfiles",
    bestFor: "Known CVEs in application dependencies",
  },
];

const byId = new Map(SCANNER_GUIDE.map((item) => [item.id, item]));

export function scannerGuide(id: string): ScannerGuide {
  return (
    byId.get(id) || {
      id,
      label: id,
      purpose: "Security scanning",
      scans: "Project source",
      bestFor: "Issues reported by this tool",
    }
  );
}

export type IssueCategory = {
  id: string;
  label: string;
  scanners: string;
};

export const ISSUE_CATEGORIES: IssueCategory[] = [
  { id: "security_hotspot", label: "Security hotspot", scanners: "SonarQube" },
  { id: "vulnerability", label: "Vulnerability", scanners: "Semgrep, SonarQube, Trivy, Dependency-Check" },
  { id: "infrastructure", label: "Infrastructure issue", scanners: "Trivy" },
  { id: "secret_leak", label: "Secret leak detection", scanners: "Gitleaks, Trivy" },
  { id: "duplication", label: "Duplication", scanners: "SonarQube" },
  { id: "code_quality", label: "Code quality", scanners: "SonarQube" },
];

const categoryById = new Map(ISSUE_CATEGORIES.map((item) => [item.id, item]));

export function issueCategory(id?: string): IssueCategory {
  return (
    categoryById.get(id || "") || {
      id: id || "vulnerability",
      label: "Vulnerability",
      scanners: "Scanner",
    }
  );
}
