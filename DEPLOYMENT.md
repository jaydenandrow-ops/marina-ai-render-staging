# MARINA AI — Render Free synthetic staging package

This repository is a curated deployment copy. It contains application source and static assets only. It excludes `.env`, SQLite databases, virtual environments, tests, reports, logs, generated images, uploads, and ZERO GENESIS research artifacts.

## Staging safeguards

- The Render web service is internet-addressable. Do not deploy until a long random staging Basic Auth password is set. `staging_app.py` requires Basic Auth on every route except `/healthz`.
- Cloud inference, image generation, research execution, account deletion, and cleanup are forced off by the entrypoint.
- The entrypoint rejects missing/non-PostgreSQL database configuration. SQLite fallback is forbidden.
- Database connections must pass the existing `sslmode=verify-full` validator and use a mounted CA file. The internal Render DB URL is not compatible with the app’s current verify-full requirement; configure the external Render DB URL and its CA bundle.
- `GENESIS_TRUSTED_PROXY_CIDRS` must be populated with verified proxy peer CIDRs. Do not use `0.0.0.0/0` or `*`. Render does not document a fixed inbound proxy CIDR set in the material reviewed here, so this remains an operator verification gate.
- The app remains production-startup read-only and will refuse an uninitialized database. Do not add migrations to the web start command.

Render Free is for synthetic testing only. Free web filesystems are ephemeral. Free Postgres expires 30 days after creation and does not provide backups. There is no persistent disk on Free web services, no shell/SSH access, no one-off jobs, and pre-deploy commands are unavailable for Free services. Therefore this manifest is not suitable for production or user data.

## Required environment variable names

Configure the following names in Render. This document intentionally contains no secret values:

`GENESIS_ENV`, `GENESIS_BIND_HOST`, `PORT`, `GENESIS_DATABASE_URL`, `PGSSLROOTCERT`, `GENESIS_ALLOWED_HOSTS`, `GENESIS_CANONICAL_ORIGIN`, `GENESIS_CORS_ALLOWED_ORIGINS`, `GENESIS_TRUSTED_PROXY_CIDRS`, `CLOUD_ABUSE_HMAC_SECRET`, `SECURITY_EVENT_HMAC_SECRET`, `EMAIL_AUTH_THROTTLE_SECRET`, `STAGING_BASIC_AUTH_USERNAME`, `STAGING_BASIC_AUTH_PASSWORD`, `CLOUD_PROVIDER_ENABLED`, `IMAGE_GENERATION_ENABLED`, `IMAGE_ACCOUNT_AUTHORIZATION_ENABLED`, `GENESIS_RESEARCH_ENABLED`, `ACCOUNT_DELETION_ENABLED`, `RETENTION_CLEANUP_ENABLED`, `RETENTION_STORAGE_CLEANUP_ENABLED`.

`GENESIS_DATABASE_URL` must be the external Render Postgres URL with `sslmode=verify-full`; `PGSSLROOTCERT` must point to the mounted CA secret file. `GENESIS_ALLOWED_HOSTS`, canonical origin, and CORS origin must match the actual Render hostname exactly. The proxy CIDRs must be established from trusted Render-side evidence before the service can pass request checks.

## GitHub preparation and push

The deployment directory is a local Git repository at `render-staging-deploy`. Review its files and verify the ignore rules before publishing. Create a **private** empty GitHub repository for synthetic staging, then from PowerShell:

```powershell
Set-Location 'C:\Users\Windows 10\Desktop\GENESIS_AI_PUBLIC\render-staging-deploy'
git remote add origin https://github.com/<YOUR-ORG-OR-USER>/<PRIVATE-REPO>.git
git push -u origin main
```

Do not add `.env`, databases, generated uploads, secrets, or real user data. GitHub authentication should use the operator’s normal credential manager; never put a token in the remote URL.

## Render dashboard steps

1. In Render, choose **New → Blueprint Instance** and connect the private GitHub repository.
2. Review the Blueprint resource plan: one Free web service and one Free PostgreSQL database. No resource is created by this local package.
3. Before applying, confirm this is a disposable synthetic database and accept the Free database’s 30-day expiry/no-backup limitation.
4. Complete all `sync: false` fields. Set the exact actual Render hostname/origin values, verified trusted proxy CIDRs, external PostgreSQL URL with `sslmode=verify-full`, and staging Basic Auth credentials.
5. Add a Render secret file named `render-postgres-ca.pem` and set `PGSSLROOTCERT` to `/etc/secrets/render-postgres-ca.pem` as declared in the Blueprint.
6. Keep all safety flags at `0`; do not configure OpenAI, SMTP, Google, image generation, or research credentials in this phase.
7. The database must be initialized separately using the approved migration procedure before the web service can pass its read-only startup check. Free Render has no service shell or one-off migration job, and no migration is run by this web entrypoint. Stop if the separate migration path, TLS verification, or proxy identity cannot be verified.
8. Only after the staging site is reachable behind Basic Auth should the operator perform browser checks. Do not share the URL/password or enable public registration/chat.

No GitHub push, Render resource creation, migration, or deployment was performed by this task.
