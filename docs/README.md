# Developer documentation

Start here if you are joining BugCode Shield.

People **using** the product (scan their own project): [User guide](./user-guide.md) or http://localhost:3000/guide.

| Doc | What it covers |
| --- | --- |
| [User guide](./user-guide.md) | Account → project → source → scan → issues |
| [Requirements overview](./requirements-overview.md) | Product goals, constraints, and what is in / out of scope |
| [Architecture](./architecture.md) | Processes, packages, networks, and where to change code |
| [Data flow](./data-flow.md) | Request path, scan pipeline, and source kinds |
| [Database design](./database-design.md) | Tables and scan lifecycle |
| [API documentation](./api-documentation.md) | HTTP endpoints |
| [Scanner integration](./scanner-integration.md) | Semgrep, Trivy, Gitleaks, SonarQube, Docker isolation |
| [Security architecture](./security-architecture.md) | Auth, secrets, scanner sandbox |
| [Docker guide](./docker-guide.md) | Compose services and ports |
| [Development setup](./development-setup.md) | First run, native API/web, tests |
| [Contributing](../CONTRIBUTING.md) | How to land a change |
| [License](../LICENSE) | Apache License 2.0 |
| [Security policy](../SECURITY.md) | Private vulnerability reports |
| [Code of conduct](../CODE_OF_CONDUCT.md) | Community standards |
| [Implementation roadmap](./implementation-roadmap.md) | Phase status |

Day-one path:

1. Read [requirements](./requirements-overview.md) and [architecture](./architecture.md).
2. Follow [development setup](./development-setup.md) until http://localhost:3000 loads.
3. Walk [user guide](./user-guide.md) / http://localhost:3000/guide, then scan `testdata/vulnerable-sample`.
4. Read [data flow](./data-flow.md) while watching `docker compose logs -f worker`.
5. Use [CONTRIBUTING](../CONTRIBUTING.md) before opening a pull request.
