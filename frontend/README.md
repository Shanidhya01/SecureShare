# SecureShare — Frontend

This is the Next.js (App Router) client for SecureShare. For project-wide documentation — architecture, security model, deployment, environment variables, and testing — see the docs in the repository root:

- [README.md](../README.md) — overview, architecture diagrams, feature list, project structure
- [SECURITY.md](../SECURITY.md) — security model and threat model
- [DEPLOYMENT.md](../DEPLOYMENT.md) — local development and production deployment
- [ENVIRONMENT_VARIABLES.md](../ENVIRONMENT_VARIABLES.md) — required/optional configuration
- [SECURITY_TESTING.md](../SECURITY_TESTING.md) — manual test procedures

## Quick start

```bash
npm install
cp .env.example .env.local   # set NEXT_PUBLIC_API
npm run dev
# → http://localhost:3000
```

See [DEPLOYMENT.md](../DEPLOYMENT.md#frontend) for full setup instructions, including production deployment to Vercel.
