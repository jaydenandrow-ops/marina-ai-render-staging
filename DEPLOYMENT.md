# MARINA AI — Render Free synthetic staging package

This repository is a curated deployment copy. It contains application source, static assets, and a small standard-library startup-validation test. It excludes `.env`, SQLite databases, virtual environments, other test suites, reports, logs, generated images, uploads, and ZERO GENESIS research artifacts. The Docker build excludes the validation test.

## Staging safeguards

- The Render web service is internet-addressable. Do not deploy until a long random staging Basic Auth password is set. `staging_app.py` requires Basic Auth on every route except `/healthz`.
- Cloud inference, image generation, research execution, account deletion, and cleanup are forced off by the entrypoint.
- The entrypoint rejects missing/non-PostgreSQL database configuration. SQLite fallback is forbidden.
- The `sslmode=require` exception is limited to this curated Render staging bundle and requires `GENESIS_RENDER_STAGING=1`, the exact internal hostname, database name, and database user. Render documents that its internal PostgreSQL certificates are self-signed and do not support `verify-ca` or `verify-full`; `require` encrypts the connection and prevents plaintext fallback but does not verify certificate identity. The normal production validator remains `sslmode=verify-full`; no global downgrade is made. [Render PostgreSQL TLS guidance](https://render.com/docs/postgresql-creating-connecting)
- The app and database must be in the same Render workspace/account and Ohio region for the internal URL. The startup identity probe requires the configured host, `marina_staging` database/user, PostgreSQL 18, UTF8, TLS active, port 5432 on that exact target, and private client/server addresses. It never logs the URL or returned identity values.
- Render does not publish a verified stable inbound proxy CIDR list for this Free service. The staging bundle therefore does not trust forwarded headers: Uvicorn starts with proxy-header processing disabled, and the application ignores `Forwarded` and all `X-Forwarded-*` values. It uses the validated request `Host`, the configured canonical HTTPS origin for external scheme/security decisions, and the socket peer address for IP-based controls. This is conservative: requests sharing a Render proxy peer also share IP-based anonymous quotas, which can cause false throttling. Normal production still requires explicitly configured trusted proxy CIDRs and retains strict forwarded-header validation.
- Normal startup remains read-only and refuses an uninitialized database. A separate explicit staging-only initialization switch is off by default. If temporarily enabled, the entrypoint first verifies database identity/TLS and schema state, initializes only an empty public schema, verifies readiness, then starts Uvicorn. An already-current schema is a no-op; partial, unknown, or failed schemas stop startup. No reset/drop/delete/import operation exists in this procedure.

## Startup diagnostics

The entrypoint writes one-line `render_startup` records to standard output/error. A configuration rejection includes a fixed `check` identifier, the relevant environment-variable name, and a safe reason; it never prints environment values. Checks cover environment mode, bind host, assigned port, staging scope, expected DB identity fields, URL TLS mode, host/origin/CORS policy, trusted proxy CIDRs, required secrets, staging Basic Auth, disabled feature flags, and initialization authorization. The connected database identity, TLS state, private peer/server addresses, PostgreSQL major version and encoding are verified before migration or normal server handoff. Schema readiness is checked by the explicit initializer when authorized, or by the app lifespan during normal startup.

Run the committed offline launcher regressions from this directory with `python -B -m unittest test_render_entrypoint -v`.

Render Free is for synthetic testing only. Free web filesystems are ephemeral. Free Postgres expires 30 days after creation and does not provide backups. There is no persistent disk on Free web services, no shell/SSH access, no one-off jobs, and pre-deploy commands are unavailable for Free services. Therefore this manifest is not suitable for production or user data.

## Required environment variable names

Required names are listed below; Render assigns `PORT` automatically. The names and non-secret expected values are shown; no credentials or connection URL values are included:

Required: `GENESIS_ENV`, `GENESIS_BIND_HOST`, `PORT`, `GENESIS_RENDER_STAGING`, `GENESIS_RENDER_IGNORE_FORWARDED_HEADERS`, `GENESIS_DATABASE_URL`, `GENESIS_RENDER_DATABASE_HOST`, `GENESIS_RENDER_DATABASE_NAME`, `GENESIS_RENDER_DATABASE_USER`, `MARINA_STAGING_INITIALIZE_ON_START`, `GENESIS_ALLOWED_HOSTS`, `GENESIS_CANONICAL_ORIGIN`, `GENESIS_CORS_ALLOWED_ORIGINS`, `CLOUD_ABUSE_HMAC_SECRET`, `SECURITY_EVENT_HMAC_SECRET`, `EMAIL_AUTH_THROTTLE_SECRET`, `STAGING_BASIC_AUTH_USERNAME`, `STAGING_BASIC_AUTH_PASSWORD`, `CLOUD_PROVIDER_ENABLED`, `IMAGE_GENERATION_ENABLED`, `IMAGE_ACCOUNT_AUTHORIZATION_ENABLED`, `GENESIS_RESEARCH_ENABLED`, `ACCOUNT_DELETION_ENABLED`, `RETENTION_CLEANUP_ENABLED`, `RETENTION_STORAGE_CLEANUP_ENABLED`.

Expected values: `GENESIS_ENV=production`, `GENESIS_BIND_HOST=0.0.0.0`, `GENESIS_RENDER_STAGING=1`, `GENESIS_RENDER_IGNORE_FORWARDED_HEADERS=1`, `GENESIS_RENDER_DATABASE_NAME=marina_staging`, `MARINA_STAGING_INITIALIZE_ON_START=0`, and all unsafe feature flags `0`. Leave `GENESIS_TRUSTED_PROXY_CIDRS` unset or empty; any value is rejected for this Render staging bundle. Set `GENESIS_RENDER_DATABASE_USER` to the exact database user shown in Render's connection details; it is not assumed from the database name. `GENESIS_RENDER_DATABASE_HOST` is the hostname only, copied from the database's **Internal Database URL**. `GENESIS_DATABASE_URL` is that same full internal URL with exactly one `sslmode=require` query parameter. Do not use an external URL for this policy. `GENESIS_ALLOWED_HOSTS`, canonical origin, and CORS origin must match the actual Render web hostname exactly.

### Configure the internal database URL securely

1. Open the existing `marina-staging-db` service in Render, confirm PostgreSQL 18 and Ohio, then open **Connect** and select **Internal Database URL**.
2. In the `marina-ai-render-staging` web service, open **Environment**. Add/update `GENESIS_DATABASE_URL` there; paste the internal URL only into this protected field. Add `?sslmode=require` if the URL has no query string, or `&sslmode=require` if it already has one. Ensure there is exactly one `sslmode=require` parameter. Never paste the URL into chat, a ticket, a build command, or Git.
3. Set `GENESIS_RENDER_DATABASE_HOST` to the hostname portion only (no scheme, user, password, path, or port), `GENESIS_RENDER_DATABASE_NAME` to `marina_staging`, and `GENESIS_RENDER_DATABASE_USER` to the exact user shown in Render's connection details. The application cross-checks all three against the connected server before any schema change. Set `GENESIS_RENDER_IGNORE_FORWARDED_HEADERS=1` and leave `GENESIS_TRUSTED_PROXY_CIDRS` empty/unset. The Uvicorn launch command includes `--no-proxy-headers`; the application does not use forwarded values for host, HTTPS detection, authentication, cookies, security events, or rate-limit identity. The actual socket peer is the rate-limit IP identity, so shared proxy peers may share anonymous IP quotas. Remove legacy `PGSSLROOTCERT` and any `PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGSERVICE`, `PGSERVICEFILE`, `PGSSLMODE`, `PGSSLCERT`, or `PGSSLKEY` overrides; the startup gate rejects them so they cannot alter the reviewed connection target/TLS mode.
4. Set the remaining required values in Render Environment. Use Render-generated values for the HMAC secrets and a long random Basic Auth password. Do not add an OpenAI key, Google credentials, SMTP credentials, or image-generation settings for this synthetic staging step.
5. Save. Render hides environment values in its dashboard; inspect only variable names and sanitized startup log records. The internal URL is reachable only by same-workspace/account services in the same region. [Render connection instructions](https://render.com/docs/postgresql-creating-connecting)

`sslmode=require` does not authenticate the server certificate. It is permitted only when the explicit Render staging flag is set and actual connection metadata confirms the intended private target. Other deployments continue to require `sslmode=verify-full`.

### Fresh staging schema initialization

Render Free has no web-service shell or one-off migration job, so initialization is an explicit, temporary startup action on the already Basic-Auth-protected staging service. It is **not** enabled in normal startup and no migration runs by default.

1. Confirm the database is the newly created, empty `marina-staging-db`; confirm the web service and DB are both in Ohio and in the same Render workspace/account. No user or production data may be in it.
2. Confirm all required environment checks pass, especially the exact internal DB host/name/user, TLS `require`, Basic Auth, allowed host/origin/CORS, verified proxy CIDRs, and disabled feature flags.
3. In the web service’s **Environment**, temporarily set `MARINA_STAGING_INITIALIZE_ON_START=1` and add `MARINA_STAGING_INITIALIZATION_CONFIRMATION=INITIALIZE_EMPTY_MARINA_STAGING_DB`. This exact confirmation is an explicit staging-only authorization; it is not a credential. Save and manually deploy the current commit. The entrypoint queries the connected identity and `pg_stat_ssl`, requires a private peer/server address, PostgreSQL 18 and UTF8, then checks schema state. It applies the existing versioned `migrate_fresh()` only for `empty_fresh`; for `verified_current` it performs read-only readiness verification. It refuses existing unversioned tables, checksum problems, partial/upgradeable schemas, identity mismatches, or any migration error and does not start the web app on failure.
4. Verify sanitized logs show `database_identity status=pass`, `fresh_schema status=pass`, then `application_handoff`. A successful schema migration is idempotent on the next start: the verified-current case is read-only and does not invoke migrations again.
5. Immediately set `MARINA_STAGING_INITIALIZE_ON_START=0`, remove `MARINA_STAGING_INITIALIZATION_CONFIRMATION`, save, and manually deploy again. Normal startup will only run the existing read-only schema readiness checks.
6. If any step fails, do not drop/reset tables or rerun with changed identities. Keep registration/chat behind Basic Auth and send the sanitized `render_startup check=...` record for diagnosis.

No live Render database connection or migration was performed by this change. The init switch remains off by default.

### Verification commands

Run from the deployment repository before pushing:

```powershell
python -B -m unittest test_render_entrypoint -v
python -m pip check
python -c "from pathlib import Path; fs=list(Path('.').rglob('*.py')); [compile(p.read_text(encoding='utf-8-sig'), str(p), 'exec') for p in fs]; print(f'compiled {len(fs)} Python files')"
```

During the authorized initialization deploy, inspect Render **Logs** and require sanitized entries for `database_identity status=pass`, `fresh_schema status=pass result=initialized` (or `already_current`), and `application_handoff`. The normal deploy after removing the temporary authorization must pass the app's read-only `verify_ready()` startup gate. Then verify the Render health route without credentials:

```powershell
curl.exe --fail --show-error --silent "https://<RENDER_HOST>/healthz"
```

Expected body: `{"status":"ok","mode":"synthetic-staging"}`. Replace only `<RENDER_HOST>` with the hostname shown in the Render dashboard. This generic endpoint does not expose database identity or secrets; reaching it means the ASGI application lifespan, including schema readiness, completed successfully.

## GitHub preparation and push

The deployment directory is a local Git repository at `render-staging-deploy`. Review its files and verify the ignore rules before publishing. Create a **private** empty GitHub repository for synthetic staging, then from PowerShell:

```powershell
Set-Location 'C:\Users\Windows 10\Desktop\GENESIS_AI_PUBLIC\render-staging-deploy'
git remote add origin https://github.com/<YOUR-ORG-OR-USER>/<PRIVATE-REPO>.git
git push -u origin main
```

Do not add `.env`, databases, generated uploads, secrets, or real user data. GitHub authentication should use the operator’s normal credential manager; never put a token in the remote URL.

## Render dashboard deployment steps

1. Push the private curated repository (see above) and open the existing `marina-ai-render-staging` service. Use the Dockerfile command `python render_entrypoint.py`; do not override it with an unguarded migration command.
2. Confirm its region is Ohio, then configure the environment as described above. Keep `MARINA_STAGING_INITIALIZE_ON_START=0` until deliberately performing the one-time initialization procedure.
3. Manually deploy the commit. With initialization disabled, an empty database must fail the app’s read-only readiness check; this is expected until the explicit procedure is authorized and run.
4. Perform the one-time authorized initialization, then disable its two temporary variables and manually redeploy.
5. Only after browser, vulnerability, HTTPS, storage, and backup release gates pass should any public registration/chat be considered. The current service remains synthetic-only and Basic-Auth-protected.

No GitHub push, Render resource creation, migration, or deployment was performed by this task.



