# Security Notes - Evidence Vault

Evidence Vault stores sensitive case evidence, so it is designed around confidentiality, integrity and traceability.
Update the "Status" column only after you have applied and verified each item.

## Assets
- Evidence files (encrypted at rest) and the per-case data keys that encrypt them
- User credentials, TOTP secrets and backup codes (backup codes stored only as BCrypt hashes)
- The hash-chained audit log
- Server secrets: JWT signing key, evidence master key, database password

## Actors and trust boundaries
Anonymous visitor -> authenticated INVESTIGATOR (only on cases they created or were assigned) -> ADMIN (audit access).
All request data (body, parameters, uploaded files) is untrusted until validated.
Out of scope: an attacker with direct access to the server, its environment variables or the database host.

## Application threats and mitigations
| Threat | Mitigation | Where |
| ------ | ---------- | ----- |
| Self-registering as admin (privilege escalation / mass assignment) | Public registration always creates INVESTIGATOR; the only admin comes from `AdminBootstrapSeeder` | `AuthService`, seeder |
| Access to another user's case or evidence | Case-scoped authorization on every case and evidence route | services / controllers |
| Stolen or replayed JWT | Per-token blacklist on logout, `tokensValidAfter` watermark on case freeze | `JwtAuthFilter` |
| Brute-force login | Per-account lockout plus rate limiting (memory or Redis) | `AuthService`, `RateLimitFilter` |
| Weak second factor | TOTP with single-use backup codes stored as BCrypt hashes | MFA endpoints |
| Evidence disclosure from storage | Per-case data key encrypts files; keys wrapped by a master key; rotation without re-encrypting files | `EncryptionService` |
| Malicious uploads | Optional ClamAV scanning that fails closed; per-user quota | `ClamAvScanService` |
| Audit log tampering | SHA-256 hash chain; `/api/audit/verify-chain`; JSON export so anyone can recompute independently | audit service |
| CSRF | Not applicable: the API authenticates with `Authorization: Bearer` headers, never cookies | `SecurityConfig` |
| Secret leakage | Secrets only in environment variables; `.env` git-ignored; `.env.example` holds placeholders | config |

## Deployment review (self-audit of docker-compose and Dockerfile)
| Finding | Risk | Fix | Status |
| ------- | ---- | --- | ------ |
| Postgres published on host port 5432 with a default password | Anyone who can reach the host could log in to the database | No published port; `POSTGRES_PASSWORD` required | [ ] Fixed |
| Redis published on 6379 without a password | Unauthenticated access; rate-limit counters could be tampered with | Not published; started with `requirepass` | [ ] Fixed |
| ClamAV port 3310 published (clamd has no authentication) | Anyone could use the scanner or overload it | Not published | [ ] Fixed |
| `SEED_DEMO_DATA` defaulted to true | Demo data and a demo user would exist in real deployments | Default false | [ ] Fixed |
| Secrets optional in compose (empty string passed on) | App could start misconfigured | Required variables (`${VAR:?message}`) | [ ] Fixed |
| App started before the database was ready | Crash loops on first boot | Postgres healthcheck + `depends_on: service_healthy` | [ ] Fixed |
| Optional services started by default (500 MB ClamAV download) | Slow, surprising first run | Compose profiles: `clamav`, `redis` | [ ] Fixed |
| Container privileges | Larger blast radius if the app is compromised | Non-root user (already), `no-new-privileges`, `cap_drop: ALL`, memory-aware JVM flags | [ ] Fixed |
| Container health | Platform cannot tell a hung app from a healthy one | `HEALTHCHECK` in the Dockerfile | [ ] Fixed |

## Dependency status
- Spring Boot **3.3.4** no longer receives open-source security patches (every 3.x line is now out of OSS support).
- Plan: step 1 move to 3.5.16, the final free 3.x release, behind the integration tests; step 2 migrate to Spring Boot 4.1.
  Record the date and result here when done: [ ]
- `pdfbox`, `jjwt` and other versions are watched by Dependabot.

## Known limitations (deliberate, documented, with the fix)
1. **Master key lives in an environment variable.** Fine for a demo. Production should use a KMS or HashiCorp Vault and a rotation policy.
2. **JWT storage on the client.** If a frontend keeps tokens in `localStorage`, XSS can steal them. Prefer short expiry plus a refresh flow, or `HttpOnly` cookies with CSRF protection.
3. **Rate limiter and SSE feed are per-instance by default.** Multi-instance deployments need `RATE_LIMIT_BACKEND=redis`; the live audit feed only shows events from the instance the admin is connected to.
4. **Rate limiter fails open if Redis is unreachable, while malware scanning fails closed.** Deliberate: availability for throttling, safety for uploads. The per-account lockout stays as a backstop.
5. **Account lockout can be abused to lock out a victim.** Mitigate with per-IP throttling and CAPTCHA or delayed unlock.
6. **Audit chain hash format.** If fields are concatenated without delimiters, different field combinations can share one hash input, and an unkeyed chain can be recomputed by someone with database write access. See `docs/AuditHasher.java` for a length-prefixed, HMAC-keyed version.
7. **Evidence is decrypted in server memory while being served.**
8. **With `CLAMAV_ENABLED=false`, uploads are not scanned.**

## Testing
- `mvn test` runs `EvidenceVaultSecurityTest` (privilege escalation, token tampering, logout revocation, case isolation).
- `scripts/security_smoke_test.sh` runs the same style of checks against a running instance.
- CI (`.github/workflows/ci.yml`) runs the tests and builds the Docker image on every push.

## Reporting a vulnerability
Please open a GitHub issue titled "Security" without exploit details, or contact the maintainer through the profile page.
