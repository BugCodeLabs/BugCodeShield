# Security policy

BugCode Shield is a local security scanner. Treat reports that could let someone read another tenant's source, steal tokens, or escape a scanner container as in-scope.

## Report a vulnerability

Do **not** open a public GitHub issue for a security bug.

1. Use GitHub private reporting: [Report a vulnerability](https://github.com/BugCodeLabs/BugCodeShield/security/advisories/new)
2. Include steps to reproduce on a local `docker compose` stack, affected version or commit, and impact.

We will acknowledge the report and work on a fix before any public disclosure.

## Out of scope

- Findings produced by Semgrep, Trivy, Gitleaks, SonarQube, or Dependency-Check against sample or user code
- Default local credentials in `.env.example` on a single-user machine
- Issues that require the reporter to already have a valid login on the same local instance

## Safe disclosure content

Do not attach exploit payloads, exploit PoCs, or attack runbooks. Describe the weakness and the trusted fix. Redact tokens and customer source.
