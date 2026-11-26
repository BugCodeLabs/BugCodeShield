# BugCode Shield web app

Next.js 15 UI for BugCode Shield. This package is not published to npm; run it as part of the monorepo.

Licensed under the Apache License, Version 2.0. See [`../../LICENSE`](../../LICENSE).

Development: from the repository root follow [`../../docs/development-setup.md`](../../docs/development-setup.md), or:

```bash
cd apps/web
npm ci
npm run dev
```

The production Compose service builds this app and proxies `/backend` to the Go API.
