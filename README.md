# Digital Evidence Vault

A chain-of-custody file storage system for digital forensics: every uploaded file is
SHA-256 fingerprinted and AES-256-GCM encrypted at rest (with **per-case envelope
encryption** - see below), and **every action in the system (login, upload, download,
integrity check, access denial) is written to a hash-chained, tamper-evident audit
log** - the same core idea blockchains use. If anyone edits or deletes a past log row
directly in the database, the chain breaks and `/api/audit/verify-chain` will detect
exactly where.

Built with Java 21 + Spring Boot 3 to demonstrate: REST API design, Spring Security
with stateless JWT auth (including revocation and rate limiting), JPA/Hibernate,
applied cryptography (AES-GCM envelope encryption, RSA signatures, SHA-256, TOTP MFA),
and forensic/audit system design.

## How the security/forensics pieces work

| Concept | Where | Why it matters forensically |
|---|---|---|
| SHA-256 fingerprint | `HashService`, computed at upload | Proves later whether a file is byte-identical to what was originally seized/uploaded |
| Per-case envelope encryption (AES-256-GCM) | `EncryptionService`, `CaseService` | Every case gets its own random data key (DEK), itself encrypted by a server-wide master key. Compromising one case's key never exposes another case's evidence. The GCM auth tag also makes silent ciphertext tampering impossible - decryption fails loudly instead |
| RSA digital signatures | `SignatureService` | Every upload is signed with the uploader's private key, proving WHO certified the file, independent of the hash |
| Hash-chained audit log | `AuditLogService` | Every log entry embeds the hash of the previous entry. Alter or delete any past entry and every hash after it stops matching |
| Audit chain export | `/api/audit/export` | Downloads the full chain as JSON so it can be independently re-verified OUTSIDE this app - you don't have to trust this codebase's own verifier |
| JWT auth + revocation | `JwtUtil`, `TokenBlacklistService` | Stateless JWTs, but each token has a `jti` that can be individually revoked on logout - a leaked/stolen token isn't valid forever even before its natural expiry |
| Two-factor auth (TOTP) | `TotpService`, `AuthService.login()` | Optional 6-digit authenticator-app code required on top of password, recommended for ADMIN accounts |
| Case-level access control | `CaseService.assertAccess()` | Investigators only see/act on cases they created or were assigned to. Admins see everything. Unauthorized attempts are themselves audit-logged |
| Rate limiting | `RateLimitFilter` | Sliding-window limits on login/register/upload/download blunt brute-force and enumeration attacks |
| Per-user storage quota | `EvidenceService.enforceQuota()` | Caps total bytes any single user can upload |
| BCrypt passwords, account lockout | `AuthService` | Passwords never stored in plaintext; 5 failed attempts locks the account for 15 minutes |
| Role-based access (`ADMIN`/`INVESTIGATOR`) | `SecurityConfig` | Only admins can view/verify/export the raw audit trail. Public registration can **never** create an ADMIN account - see Bootstrap admin, below |

## Project layout

```
src/main/java/com/evidencevault/
  model/        JPA entities (User, Case, EvidenceFile, AuditLogEntry, RevokedToken)
  repository/   Spring Data repositories
  service/      Business logic (encryption, hashing, audit chain, evidence, TOTP, ClamAV client)
  controller/   REST endpoints
  security/     JWT filter/util + rate limiter
  config/       Spring Security config, admin bootstrap, demo data seeder
  dto/          Request/response records
  exception/    Global error handling
```

## Run locally (no Docker)

Requires JDK 21 and Maven.

```bash
# 1. Generate two secrets
export JWT_SECRET_BASE64=$(openssl rand -base64 32)
export EVIDENCE_MASTER_KEY_BASE64=$(openssl rand -base64 32)

# 2. REQUIRED: bootstrap the first admin account (see "Bootstrap admin" section below)
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!

# 3. Run (uses embedded H2 file DB by default, no Postgres needed)
cd evidence-vault
mvn spring-boot:run
```

The API is now at `http://localhost:8080`.

## Bootstrap admin (read this before your first run)

Public self-registration (`POST /api/auth/register`) **can never create an ADMIN
account** - it always creates `INVESTIGATOR`, regardless of what's sent in the
request body. This is intentional: only ADMIN can view/verify/export the audit
chain, and previously the app let anyone register as ADMIN directly, which
defeated that access control entirely.

Because of that, the very first admin has to come from somewhere else:
`AdminBootstrapSeeder` creates exactly one ADMIN account on startup, **only if no
admin exists yet**, using `BOOTSTRAP_ADMIN_USERNAME` / `_EMAIL` / `_PASSWORD`. If
you leave those unset, the app still starts, but nobody can reach admin-only
endpoints until you either set them and restart, or insert an admin row directly
into the database.

Once you have one admin, use it to promote anyone else:
```bash
curl -X POST $BASE/api/auth/users/promote -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"username":"someone"}'
```

## Two-factor authentication (TOTP)

Any user can enable it from Settings (or via API):
```bash
# 1. Start setup (returns a Base32 secret + otpauth:// URI)
curl -X POST $BASE/api/auth/mfa/setup -H "Authorization: Bearer $TOKEN"

# 2. Enter the secret into an authenticator app (Google Authenticator, Authy, etc.),
#    then confirm with the 6-digit code it produces:
curl -X POST $BASE/api/auth/mfa/confirm -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"code":"123456"}'
```
From then on, `/api/auth/login` requires a `totpCode` field once the password is
correct - the API responds `401 {"error":"MFA_REQUIRED"}` if it's missing, which
the frontend uses to reveal the code field rather than treating it as a failure.

## Malware scanning (optional, needs external ClamAV)

Uploads can be scanned with ClamAV before encryption. This is **disabled by
default** (`CLAMAV_ENABLED=false`) because it requires a `clamd` daemon running
somewhere reachable - that's genuine external infrastructure this app can't set up
for you. `ClamAvScanService` talks to it directly over TCP using clamd's INSTREAM
protocol (no extra client library needed).

**Via Docker Compose** (a `clamav` service is already defined in `docker-compose.yml`):
```bash
docker compose up -d clamav
docker compose logs -f clamav   # wait for "Listening on TCP" - first boot downloads
                                  # ~500MB of virus definitions, can take several minutes
# once healthy, enable scanning for the app:
# set CLAMAV_ENABLED=true in your .env, then:
docker compose up -d app
```

**Directly on a Linux host (e.g. your Kali VM):**
```bash
sudo apt update && sudo apt install -y clamav clamav-daemon
sudo freshclam
sudo systemctl enable --now clamav-daemon
# by default clamd listens on a Unix socket, not TCP - to reach it from elsewhere,
# edit /etc/clamav/clamd.conf: add "TCPSocket 3310" and "TCPAddr 0.0.0.0", then:
sudo systemctl restart clamav-daemon
echo PING | nc localhost 3310   # should reply PONG
```
Then set `CLAMAV_ENABLED=true`, `CLAMAV_HOST`, `CLAMAV_PORT` for the app.

If scanning is enabled but the daemon becomes unreachable, uploads **fail closed**
(rejected, not silently allowed through) - see `ClamAvScanService` for details.

## Run with Docker Compose (Postgres + optional ClamAV)

```bash
cp .env.example .env
# edit .env: fill JWT_SECRET_BASE64, EVIDENCE_MASTER_KEY_BASE64, and
# BOOTSTRAP_ADMIN_USERNAME/EMAIL/PASSWORD (see "Bootstrap admin" above)

docker compose up --build
```

## Try it out (curl)

```bash
BASE=http://localhost:8080

# Register an investigator (role is always INVESTIGATOR regardless of any "role" field sent)
curl -s -X POST $BASE/api/auth/register -H "Content-Type: application/json" -d '{
  "username":"jdoe","email":"jdoe@example.com","password":"correcthorsebattery"
}'

# Login, capture token
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"jdoe","password":"correcthorsebattery"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Create a case (creator is automatically assigned access)
CASE_ID=$(curl -s -X POST $BASE/api/cases -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
  "caseNumber":"CASE-2026-001","title":"Suspicious login incident","description":"Investigating unauthorized access"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# Upload evidence (rejected with a clear message if it would exceed your storage quota,
# or if ClamAV is enabled and flags it as malware)
echo "sample log contents" > sample.txt
EVIDENCE_ID=$(curl -s -X POST $BASE/api/cases/$CASE_ID/evidence -H "Authorization: Bearer $TOKEN" -F "file=@sample.txt" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# Verify integrity
curl -s -X POST $BASE/api/evidence/$EVIDENCE_ID/verify -H "Authorization: Bearer $TOKEN"

# Download it back
curl -s $BASE/api/evidence/$EVIDENCE_ID/download -H "Authorization: Bearer $TOKEN" -o downloaded.txt

# Grant another investigator access to this case
curl -s -X POST $BASE/api/cases/$CASE_ID/assign -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"username":"another_investigator"}'

# Log out (revokes this specific token immediately, rather than waiting for expiry)
curl -s -X POST $BASE/api/auth/logout -H "Authorization: Bearer $TOKEN"

# --- Admin actions (use the bootstrap admin, or one you've promoted) ---
ADMIN_TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"'"$BOOTSTRAP_ADMIN_USERNAME"'","password":"'"$BOOTSTRAP_ADMIN_PASSWORD"'"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s $BASE/api/audit/chain -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -X POST $BASE/api/audit/verify-chain -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s $BASE/api/audit/export -H "Authorization: Bearer $ADMIN_TOKEN" -o audit-export.json
```

To see tamper detection in action: manually edit a row's `details` column directly
in the database, then call `/api/audit/verify-chain` again - it will report exactly
which sequence number broke. To verify the chain **without trusting this app's own
verifier**, download `/api/audit/export` and recompute each entry's hash yourself:
`entryHash[i]` should equal `SHA-256(sequenceNumber + timestamp + actorUsername +
action + caseId + evidenceId + details + previousHash)`, and `previousHash[i+1]`
should equal `entryHash[i]`.

## Configuration reference

All of these have sane defaults except the two encryption secrets and the bootstrap
admin credentials (see `.env.example` for the full list with comments):

| Env var | Default | Purpose |
|---|---|---|
| `JWT_SECRET_BASE64` | *(required)* | Signing key for JWTs |
| `EVIDENCE_MASTER_KEY_BASE64` | *(required)* | Wraps every case's per-case data key |
| `EVIDENCE_PREVIOUS_MASTER_KEYS_BASE64` | *(unset)* | Comma-separated retired master keys, kept only during a rotation window - see "Per-case encryption key rotation" |
| `BOOTSTRAP_ADMIN_USERNAME/_EMAIL/_PASSWORD` | *(unset)* | Creates the first ADMIN on startup - see above |
| `SEED_DEMO_DATA` | `true` | Seeds one demo case + evidence on first run so the app isn't empty; set `false` for a real deployment |
| `EVIDENCE_USER_QUOTA_BYTES` | 5 GB | Per-user upload quota |
| `CLAMAV_ENABLED` / `_HOST` / `_PORT` | `false` / `localhost` / `3310` | Optional malware scanning - see above |
| `RATE_LIMIT_BACKEND` | `memory` | `memory` (per-instance) or `redis` (shared across instances) - see "Distributed rate limiting" |
| `REDIS_HOST` / `_PORT` / `_PASSWORD` | `localhost` / `6379` / *(unset)* | Only used when `RATE_LIMIT_BACKEND=redis` |

## Deploying it live (free options)

### Option A: Render.com (easiest)

1. Push this project to a GitHub repo.
2. On Render: **New +** → **Web Service** → connect the repo.
3. Render auto-detects the `Dockerfile`. Set:
   - **Environment**: Docker
4. Add environment variables (Render dashboard → Environment):
   - `JWT_SECRET_BASE64` = output of `openssl rand -base64 32`
   - `EVIDENCE_MASTER_KEY_BASE64` = output of `openssl rand -base64 32`
   - `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`
   - `SEED_DEMO_DATA=false` (a real deployment shouldn't ship demo data)
   - `DATABASE_URL`, `DATABASE_USERNAME`, `DATABASE_PASSWORD`, `DATABASE_DRIVER=org.postgresql.Driver`
     (create a free Render Postgres instance first - Render gives you these values)
5. Deploy. Render gives you a public HTTPS URL automatically.

### Option B: Railway.app

1. Push to GitHub, then **New Project → Deploy from GitHub repo** on Railway.
2. Railway detects the Dockerfile automatically.
3. Add a Postgres plugin from Railway's marketplace - it injects `DATABASE_URL` etc. automatically (you may need to map Railway's `PGHOST/PGPORT/...` vars into the `DATABASE_URL` format Spring expects, or just set `DATABASE_URL=jdbc:postgresql://...` manually using the values Railway shows you).
4. Add the env vars from the Configuration reference table above as project variables.
5. Deploy - Railway gives you a public URL.

### Option C: Fly.io

```bash
fly launch          # detects Dockerfile, creates fly.toml
fly secrets set JWT_SECRET_BASE64=$(openssl rand -base64 32)
fly secrets set EVIDENCE_MASTER_KEY_BASE64=$(openssl rand -base64 32)
fly secrets set BOOTSTRAP_ADMIN_USERNAME=admin BOOTSTRAP_ADMIN_EMAIL=admin@example.com BOOTSTRAP_ADMIN_PASSWORD=...
fly postgres create # attach a free Postgres, then fly secrets set DATABASE_URL=...
fly deploy
```

**Important**: whichever platform you use, the evidence file storage
(`EVIDENCE_STORAGE_DIR`) needs a **persistent volume** - otherwise uploaded files
disappear on every redeploy. Render/Railway/Fly all support attaching a persistent
disk to a service; mount it at `/app/data` and set `EVIDENCE_STORAGE_DIR=/app/data/evidence-blobs`.

## What's now implemented (previously listed as future ideas)

Everything that used to be in this README's "not yet implemented" and "ideas
to extend" sections has been built. Kept here as a reference for what each
one does and how to use it.

### Case freeze (close + revoke all sessions)

`POST /api/cases/{caseId}/freeze` (case creator or admin only) closes the case
and immediately invalidates every currently-logged-in session for the creator
and every assigned investigator - not just future requests, but tokens that
were already issued and haven't expired yet. This is done by stamping a
`tokensValidAfter` watermark on each affected `User` row; `JwtAuthFilter`
rejects any token whose `issuedAt` predates that watermark, in addition to the
existing per-token (`jti`) blacklist checked on logout. The freeze itself is
audit-logged (`CASE_FROZEN`) with the list of usernames whose sessions were
revoked.

```bash
curl -s -X POST $BASE/api/cases/$CASE_ID/freeze -H "Authorization: Bearer $TOKEN"
# every other token already issued to anyone with access to this case now
# fails auth immediately, even though it hasn't naturally expired
```

### MFA backup/recovery codes

Confirming MFA setup now also returns ten single-use backup codes
(`XXXX-XXXX` format), shown exactly once - only their BCrypt hashes are ever
stored, same as passwords:

```bash
curl -s -X POST $BASE/api/auth/mfa/confirm -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"code":"123456"}'
# => {"backupCodes":["7F3K-9QXR", "..." (10 total)]}
```

If the authenticator device is lost, log in with `backupCode` instead of
`totpCode`:
```bash
curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"jdoe","password":"correcthorsebattery","backupCode":"7F3K-9QXR"
}'
```
Each code works once and is removed from the account the moment it's used.
Regenerate the whole set at any time (invalidates every old code):
```bash
curl -s -X POST $BASE/api/auth/mfa/backup-codes/regenerate -H "Authorization: Bearer $TOKEN"
```

### Structured evidence search

Beyond the existing free-text `GET /api/evidence/search?q=...`, there's now a
filterable version. All params are optional and combine with AND:

```bash
curl -s -G "$BASE/api/evidence/search/advanced" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=malware" \
  --data-urlencode "caseId=$CASE_ID" \
  --data-urlencode "uploadedBy=jdoe" \
  --data-urlencode "status=WITNESSED" \
  --data-urlencode "uploadedAfter=2026-01-01T00:00:00Z" \
  --data-urlencode "uploadedBefore=2026-12-31T23:59:59Z"
```
Results are still scoped to cases the caller can access, same as plain search.

### Per-case encryption key rotation

`POST /api/cases/{caseId}/rotate-key` (case creator or admin only) re-wraps a
case's data encryption key (DEK) under the current server master key, without
touching or re-encrypting any of the case's evidence files - only the small
wrapped-key blob on the `Case` row changes. Supports a rotation window via an
optional `EVIDENCE_PREVIOUS_MASTER_KEYS_BASE64` env var (comma-separated
retired keys): `EncryptionService.unwrapKey()` tries the current master key
first, then falls back through the retired ones, so cases don't break the
moment you roll `EVIDENCE_MASTER_KEY_BASE64` to a new value - you just need to
call `rotate-key` on each case sometime before you drop the old key from that
env var for good.

```bash
curl -s -X POST $BASE/api/cases/$CASE_ID/rotate-key -H "Authorization: Bearer $TOKEN"
```

### Distributed rate limiting (optional Redis backend)

`RateLimitFilter` now delegates its counting to a pluggable `RateLimitStore`.
Default is still the original in-memory, per-instance implementation - zero
extra infrastructure needed. Set `RATE_LIMIT_BACKEND=redis` (plus
`REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`) to switch to `RedisRateLimitStore`,
which shares counts across every app instance via a fixed-window `INCR` +
`EXPIRE` in Redis - the right choice once you're running more than one
instance behind a load balancer. If Redis becomes unreachable while this
backend is active, the limiter fails **open** (requests pass through) rather
than taking the whole app down with it - the per-account lockout in
`AuthService` still stands as a second line of defense.

```bash
docker compose up -d redis   # if you add a redis service to docker-compose.yml
export RATE_LIMIT_BACKEND=redis REDIS_HOST=localhost REDIS_PORT=6379
```

### Live audit feed (Server-Sent Events)

`GET /api/audit/stream` (ADMIN-only, same as the rest of `/api/audit/**`)
opens a long-lived SSE connection and pushes each new `AuditLogEntry` the
instant `AuditLogService.record()` appends it - no more polling
`/api/audit/chain` on a timer for a live dashboard.

```bash
curl -N -H "Authorization: Bearer $ADMIN_TOKEN" $BASE/api/audit/stream
# stays open; prints a new "audit-entry" event as each action happens elsewhere
```
In a browser, note that the standard `EventSource` API can't attach custom
headers, so a frontend would need either a fetch-based SSE client or a
short-lived signed URL/query-param token for this endpoint specifically -
worth keeping in mind if you wire this into the dashboard.

Like `RateLimitFilter`'s default backend, subscribers are tracked in-memory
per instance: in a multi-instance deployment behind a load balancer, an admin
only sees events recorded by whichever instance their SSE connection landed
on.

## Notes on CSRF

CSRF protection is deliberately disabled (`SecurityConfig`). This is standard
practice for a stateless, token-based (Bearer JWT) JSON API rather than an
oversight: CSRF exploits a browser's automatic cookie handling, and this API
never relies on cookies for auth - every request must explicitly carry an
`Authorization: Bearer <token>` header, which a forged cross-site request can't
attach.

