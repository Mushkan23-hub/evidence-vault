
## Running it locally (no Docker)

You'll need JDK 21 and Maven.

```bash
# generate two secrets first
export JWT_SECRET_BASE64=$(openssl rand -base64 32)
export EVIDENCE_MASTER_KEY_BASE64=$(openssl rand -base64 32)

# and set up the first admin account — required, see below
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!

cd evidence-vault
mvn spring-boot:run
```

It'll come up on `http://localhost:8080` — uses an embedded H2 file DB by
default so you don't need Postgres running just to poke around.

## Bootstrapping the first admin

Public registration (`POST /api/auth/register`) will only ever create an
`INVESTIGATOR`, no matter what role you try to pass in the body. I didn't
have this restriction originally, and yeah, that meant anyone could just
self-register as admin, which kind of defeats the point of locking down the
audit trail. Fixed now.

The only legit way to get an admin account is `AdminBootstrapSeeder`, which
runs on startup and creates exactly one admin if none exists, using the
`BOOTSTRAP_ADMIN_*` env vars from above. If you don't set them, the app
still boots fine, you just won't be able to hit any admin-only endpoint
until you set them and restart (or manually insert an admin row, if you're
into that).

Once you've got one admin, you can promote other users:
```bash
curl -X POST $BASE/api/auth/users/promote -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"username":"someone"}'
```

## Two-factor auth (TOTP)

```bash
# kicks off setup, returns a Base32 secret + otpauth:// URI
curl -X POST $BASE/api/auth/mfa/setup -H "Authorization: Bearer $TOKEN"

# scan that into an authenticator app, then confirm with the 6-digit code
curl -X POST $BASE/api/auth/mfa/confirm -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"code":"123456"}'
```

Once that's confirmed, login requires a `totpCode` after the password
checks out. The API responds with `401 {"error":"MFA_REQUIRED"}` if it's
missing, which the frontend uses as the signal to pop the code field.

Confirming setup also gives you back ten single-use backup codes
(`XXXX-XXXX` format), shown exactly once — they're stored server-side only
as BCrypt hashes, so don't lose them:
```bash
# lost your authenticator app? use a backup code instead of totpCode
curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"jdoe","password":"correcthorsebattery","backupCode":"7F3K-9QXR"
}'
# or regenerate the whole set (this invalidates the old ones)
curl -s -X POST $BASE/api/auth/mfa/backup-codes/regenerate -H "Authorization: Bearer $TOKEN"
```

## Malware scanning (optional — needs a real ClamAV instance)

Off by default (`CLAMAV_ENABLED=false`) because it needs an actual `clamd`
daemon somewhere, and I didn't want that to be a hard requirement just to
try the project out. `ClamAvScanService` talks to it directly over TCP
using clamd's INSTREAM protocol — no client library, just raw sockets.

**Via Docker Compose:**
```bash
docker compose up -d clamav
docker compose logs -f clamav   # wait for "Listening on TCP" on first boot,
                                  # it pulls ~500MB of virus defs so this takes a bit
# then flip CLAMAV_ENABLED=true in .env and:
docker compose up -d app
```

**Directly on a Linux host:**
```bash
sudo apt update && sudo apt install -y clamav clamav-daemon
sudo freshclam
sudo systemctl enable --now clamav-daemon
# clamd listens on a unix socket by default — to reach it remotely, edit
# /etc/clamav/clamd.conf and add "TCPSocket 3310" + "TCPAddr 0.0.0.0", then:
sudo systemctl restart clamav-daemon
echo PING | nc localhost 3310   # should get PONG back
```
Then set `CLAMAV_ENABLED=true` along with `CLAMAV_HOST` / `CLAMAV_PORT`.

Worth noting: if scanning's turned on but the daemon can't be reached,
uploads fail closed. They get rejected rather than silently let through —
check `ClamAvScanService` if you want to see how that's handled.

## Running with Docker Compose (Postgres + optional ClamAV)

```bash
cp .env.example .env
# fill in JWT_SECRET_BASE64, EVIDENCE_MASTER_KEY_BASE64, BOOTSTRAP_ADMIN_*

docker compose up --build
```

## Trying it out with curl

```bash
BASE=http://localhost:8080

# register — comes back as INVESTIGATOR no matter what "role" you send
curl -s -X POST $BASE/api/auth/register -H "Content-Type: application/json" -d '{
  "username":"jdoe","email":"jdoe@example.com","password":"correcthorsebattery"
}'

# log in and grab the token
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"jdoe","password":"correcthorsebattery"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# create a case — the creator gets access automatically
CASE_ID=$(curl -s -X POST $BASE/api/cases -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
  "caseNumber":"CASE-2026-001","title":"Suspicious login incident","description":"Investigating unauthorized access"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# upload some evidence — gets rejected if it'd blow your quota, or if ClamAV flags it
echo "sample log contents" > sample.txt
EVIDENCE_ID=$(curl -s -X POST $BASE/api/cases/$CASE_ID/evidence -H "Authorization: Bearer $TOKEN" -F "file=@sample.txt" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# check its integrity
curl -s -X POST $BASE/api/evidence/$EVIDENCE_ID/verify -H "Authorization: Bearer $TOKEN"

# pull it back down
curl -s $BASE/api/evidence/$EVIDENCE_ID/download -H "Authorization: Bearer $TOKEN" -o downloaded.txt

# give another investigator access to the case
curl -s -X POST $BASE/api/cases/$CASE_ID/assign -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"username":"another_investigator"}'

# log out — revokes the token immediately instead of waiting on expiry
curl -s -X POST $BASE/api/auth/logout -H "Authorization: Bearer $TOKEN"

# --- admin stuff ---
ADMIN_TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{
  "username":"'"$BOOTSTRAP_ADMIN_USERNAME"'","password":"'"$BOOTSTRAP_ADMIN_PASSWORD"'"
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s $BASE/api/audit/chain -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -X POST $BASE/api/audit/verify-chain -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s $BASE/api/audit/export -H "Authorization: Bearer $ADMIN_TOKEN" -o audit-export.json
```

If you want to actually watch the tamper detection fire: go edit a row's
`details` column directly in the DB, then hit `/api/audit/verify-chain`
again. It'll tell you exactly which sequence number broke. And if you don't
want to trust this app's own verifier, pull `/api/audit/export` and
recompute the hashes yourself — `entryHash[i]` should equal
`SHA-256(sequenceNumber + timestamp + actorUsername + action + caseId +
evidenceId + details + previousHash)`, and `previousHash[i+1]` should equal
`entryHash[i]`.

## Configuration reference

Everything below has a sane default except the two encryption secrets and
the bootstrap admin credentials (the full list, with comments, lives in
`.env.example`):

| Env var | Default | Purpose |
|---|---|---|
| `JWT_SECRET_BASE64` | *(required)* | Signing key for JWTs |
| `EVIDENCE_MASTER_KEY_BASE64` | *(required)* | Wraps every case's per-case data key |
| `EVIDENCE_PREVIOUS_MASTER_KEYS_BASE64` | *(unset)* | Comma-separated retired master keys, used during key rotation |
| `BOOTSTRAP_ADMIN_USERNAME/_EMAIL/_PASSWORD` | *(unset)* | Creates the first admin on startup |
| `SEED_DEMO_DATA` | `true` | Seeds a demo case + evidence file. Set `false` once you're not just poking around |
| `EVIDENCE_USER_QUOTA_BYTES` | 5 GB | Per-user upload quota |
| `CLAMAV_ENABLED` / `_HOST` / `_PORT` | `false` / `localhost` / `3310` | Optional malware scanning |
| `RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` (shared across instances) |
| `REDIS_HOST` / `_PORT` / `_PASSWORD` | `localhost` / `6379` / *(unset)* | Only matters if `RATE_LIMIT_BACKEND=redis` |

## Deploying somewhere real (free tiers)

### Render.com — probably the easiest option

1. Push the repo to GitHub.
2. In Render: **New +** → **Web Service** → connect the repo.
3. It'll auto-detect the Dockerfile, set the environment to Docker.
4. Add these env vars under the Environment tab:
   - `JWT_SECRET_BASE64` / `EVIDENCE_MASTER_KEY_BASE64` — generate fresh values with `openssl rand -base64 32`, don't reuse
   - `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`
   - `SEED_DEMO_DATA=false`
   - `DATABASE_URL`, `DATABASE_USERNAME`, `DATABASE_PASSWORD`, `DATABASE_DRIVER=org.postgresql.Driver` — spin up a free Render Postgres first and it'll hand you these
5. Deploy, and you'll get a public HTTPS URL out of it.

### Railway.app

1. Push to GitHub, then **New Project → Deploy from GitHub repo**.
2. Railway picks up the Dockerfile on its own.
3. Add a Postgres plugin, it'll inject `DATABASE_URL` and friends (you might need to remap Railway's `PGHOST`/`PGPORT`/etc into what Spring expects).
4. Same env vars as above.
5. Deploy.

### Fly.io

```bash
fly launch          # picks up the Dockerfile, generates fly.toml
fly secrets set JWT_SECRET_BASE64=$(openssl rand -base64 32)
fly secrets set EVIDENCE_MASTER_KEY_BASE64=$(openssl rand -base64 32)
fly secrets set BOOTSTRAP_ADMIN_USERNAME=admin BOOTSTRAP_ADMIN_EMAIL=admin@example.com BOOTSTRAP_ADMIN_PASSWORD=...
fly postgres create # attach a free Postgres, then fly secrets set DATABASE_URL=...
fly deploy
```

Regardless of which of these you pick: `EVIDENCE_STORAGE_DIR` needs to sit
on a persistent volume or your uploads disappear the moment you redeploy.
All three platforms support attaching a disk — mount it at `/app/data` and
point `EVIDENCE_STORAGE_DIR=/app/data/evidence-blobs`.

## Case freeze

`POST /api/cases/{caseId}/freeze` (creator or admin only) closes a case
and immediately kills every active session belonging to the creator and
any assigned investigators, including tokens that were already issued and
haven't technically expired yet. It works by stamping a `tokensValidAfter`
watermark on each affected `User` row, and `JwtAuthFilter` rejects any
token issued before that watermark, on top of the regular per-token
blacklist. Gets logged as `CASE_FROZEN` along with the list of usernames
whose sessions got revoked.

```bash
curl -s -X POST $BASE/api/cases/$CASE_ID/freeze -H "Authorization: Bearer $TOKEN"
```

## Structured evidence search

There's also a filterable search beyond the plain `GET
/api/evidence/search?q=...`. All the params are optional and combine with
AND:

```bash
curl -s -G "$BASE/api/evidence/search/advanced" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=malware" \
  --data-urlencode "caseId=$CASE_ID" \
  --data-urlencode "uploadedBy=jdoe" \
  --data-urlencode "status=WITNESSED" \
  --data-urlencode "uploadedAfter=2026-01-01T00:00:00Z" \
  --data-urlencode "uploadedBefore=2026-12-31T23:59:59Z"
```
Still scoped to whatever cases the caller has access to, same as the plain
search.

## Per-case key rotation

`POST /api/cases/{caseId}/rotate-key` (creator or admin) re-wraps a case's
DEK under whatever the current master key is, without touching any of the
actual evidence files — just the small wrapped-key blob on the `Case` row
changes. There's a rotation window supported via
`EVIDENCE_PREVIOUS_MASTER_KEYS_BASE64` (comma-separated list of retired
keys): `EncryptionService.unwrapKey()` tries the current key first and
falls back through the retired ones, so cases don't just break the second
you roll `EVIDENCE_MASTER_KEY_BASE64`. Just call `rotate-key` on each case
before you actually drop the old key for good.

```bash
curl -s -X POST $BASE/api/cases/$CASE_ID/rotate-key -H "Authorization: Bearer $TOKEN"
```

## Distributed rate limiting

`RateLimitFilter` just delegates the actual counting to a pluggable
`RateLimitStore`. Default is in-memory and per-instance, no extra infra
needed. Set `RATE_LIMIT_BACKEND=redis` (plus `REDIS_HOST`/`REDIS_PORT`/
`REDIS_PASSWORD`) to switch to `RedisRateLimitStore`, which shares counts
across instances using a fixed-window `INCR` + `EXPIRE`. If Redis drops
while this is active, the limiter fails open — requests just pass through
rather than taking the whole app down. The per-account lockout in
`AuthService` is still there underneath as a backstop either way.

```bash
docker compose up -d redis
export RATE_LIMIT_BACKEND=redis REDIS_HOST=localhost REDIS_PORT=6379
```

## Live audit feed (SSE)

`GET /api/audit/stream` (admin only) opens an SSE connection and pushes
every new `AuditLogEntry` the moment it's written, so you're not polling
`/api/audit/chain` on a timer.

```bash
curl -N -H "Authorization: Bearer $ADMIN_TOKEN" $BASE/api/audit/stream
```
Small catch: the browser's native `EventSource` API can't attach custom
headers, so a real frontend would need a fetch-based SSE client, or a
short-lived signed URL just for this endpoint. Also worth flagging —
subscribers are tracked per-instance, same as the default rate limiter, so
in a multi-instance deployment an admin only sees events from whichever
instance their connection happened to land on.

## Why CSRF is turned off

This was a deliberate call, not something I forgot (see `SecurityConfig`
if you want to check). CSRF attacks rely on a browser automatically
attaching cookies to a request. This API never uses cookies for auth —
every request needs an explicit `Authorization: Bearer <token>` header,
and that's not something a forged cross-site request can attach on its
own.
