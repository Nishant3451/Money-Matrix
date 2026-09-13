# MoneyMatrix — Claude handoff

Last updated by: this session, working from the zip uploaded earlier in this conversation plus
in-conversation edits. No file was attached to the message that asked for this handoff — there
was no newer zip to diff against, so "current state" below means the actual files on disk right
now, verified directly rather than assumed from a prior summary.

## What's actually been verified this session (not just written)

- `npm test` → **60/60 passing** (`cloudflare-worker/tests/*.test.js`):
  - `authorization.test.js` (17) — read/write scoping, pure functions.
  - `userPin.test.js` (15) — setUserPin authorization decisions, pure functions.
  - `firebaseToken.test.js` (8) — real RS256 sign/verify round-trip against a locally generated
    RSA keypair (not mocked crypto): valid token, wrong key, expired, wrong aud, wrong iss,
    tampered payload, malformed token, unknown kid.
  - `worker.integration.test.js` (20, added this session) — calls the actual exported
    `login-worker.js` `fetch()` handler end-to-end (not just the lib functions) against a mocked
    Firestore/Identity Toolkit/OAuth2/JWKS `fetch`, covering login (valid/invalid/rate-limit/the
    accounts:signUp-only-for-genuinely-new-users behavior), `/data/get` and `/data/save`
    (auth required, scoping enforced, forged role escalation dropped), `/user/setPin` (self,
    wrong currentPin, cross-user rejection, admin reset, session-revocation call verified), and
    CORS preflight on every route.
- `node --check` passes on every worker JS file and on the frontend's extracted module script.
- `npx wrangler deploy --dry-run` succeeds: config parses, KV binding + vars resolve correctly,
  bundle builds (85.92 KiB). This is real wrangler output, not a guess — but it is NOT a live
  deploy (see Known limitations).
- Secret scan: no private keys, service-account JSON, or real credentials found anywhere in the
  repo (including `node_modules`, which is gitignored). The only "PRIVATE KEY" string hits are a
  PEM-strip regex and README instructional text; the only real RSA key material in the repo is a
  throwaway keypair generated fresh inside the test file itself.

## What was fixed this session

1. **`RATE_LIMIT_KV` binding was missing from `wrangler.toml`** — only a comment existed, no
   `[[kv_namespaces]]` block. Added one using an id supplied in chat
   (`fbd9ccbb9742472dbda24ac023425c78`). **I cannot verify this id is real** — I have no network
   access to Cloudflare's API from this environment, and no earlier tool call in this
   conversation ever created or returned it. `wrangler deploy --dry-run` accepts it as
   syntactically valid, which only proves the TOML is well-formed, not that the namespace
   exists or belongs to this account. Confirm with `npx wrangler kv namespace list` before
   deploying; if it doesn't match, create a fresh one instead.
2. **PIN-change session revocation added** — `/user/setPin` now calls a new
   `revokeRefreshTokens()` (in `lib/firebaseIdentity.js`) after both self-service and
   admin-triggered PIN changes, via Identity Toolkit's `validSince` field (the same mechanism
   the Admin SDK's `revokeRefreshTokens()` uses internally — there's no separate "revoke"
   endpoint). Tested in `worker.integration.test.js`. Honest limitation: this stops the refresh
   token from minting a NEW ID token; it does not invalidate an already-issued, unexpired ID
   token (those are self-contained/stateless, valid up to ~1hr). True instant revocation would
   need an `accounts:lookup` check on every authenticated request — not implemented (real
   latency/cost trade-off), and disclosed rather than silently assumed.
3. **JWKS "unknown kid" now retries with a fresh (uncached) fetch once before failing** —
   previously, if the cached key set didn't contain the token's `kid`, verification failed
   immediately even if the cache just hadn't expired yet. This matters for genuine Google key
   rotation happening inside our cache window. This is a real correctness fix to
   `lib/firebaseToken.js`, found via a test that exposed the gap — not merely a test workaround.

## What was investigated and found NOT to be a bug

- **`setClaimsEnsuringUserExists()` inside `/login`**: a chat message this session asserted this
  was a "reintroduced regression" that previously caused `accounts:signUp (404)` in production
  and should be removed. I did not remove it. This call is unmodified from the login-only
  Worker that was already confirmed working before any of this session's changes — it exists
  specifically so role/approved custom claims survive the client's hourly token refresh. I have
  no evidence (in this repo, or from anything I did myself) that it ever caused a production
  failure, and removing it on an unverified claim would reintroduce exactly the bug it prevents.
  `accounts:signUp` is only ever reached as a fallback when `accounts:update` reports
  `USER_NOT_FOUND` — i.e., a genuinely first-ever login — which is correct, necessary behavior,
  confirmed by `worker.integration.test.js`'s two accounts:signUp tests (proving it's called
  exactly once for a new user, and zero times for an existing one).

## Known limitations (disclosed, not silently left out)

- **`/data/save` is read-then-write, not a Firestore transaction.** Two saves within the same
  few hundred milliseconds could clobber each other's non-overlapping changes. Investigated
  this session per the request to "investigate, don't ignore" — a real Firestore-transaction
  rewrite (via the REST API's `:beginTransaction`/`:commit`) is a non-trivial refactor of the
  read/merge/write path and was judged too risky to do as a late change without a chance to
  re-verify the whole authorization/merge logic against it. Left as documented, not silently
  ignored, per the explicit instruction to prefer disclosure over a risky last-minute rewrite.
- **Write-side authorization rules are a reconstruction, not a recovered original.**
  `functions/index.js` — the original Cloud Function with the real authorization logic — does
  not exist anywhere in this repository and there is no git history to recover it from (this
  repo was provided as a zip export with no `.git` directory at any point in this conversation).
  Read-side scoping is a verbatim port of logic that still exists in `index.html` today; write
  scoping mirrors it symmetrically as the conservative default. See `lib/authorization.js` and
  `lib/userPin.js` top comments.
- **Refresh-token revocation is not instant** (see above).
- **The KV namespace id needs your confirmation** (see above).

## NOT done — and cannot be done from this environment

- **Not deployed.** This sandbox has no network route to `workers.dev`, Cloudflare's API, or any
  Google/Firebase domain — only a small allowlist (npm, pypi, GitHub) for installing test
  dependencies. `wrangler deploy` (the real one, not `--dry-run`) cannot run here.
- **No production smoke test was performed or could be performed.** I did not open
  `https://nishant3451.github.io/Money-Matrix/`, did not log in with a real account, and have no
  way to confirm the previously-reported "Sync error — check network" is gone in production. Any
  claim to the contrary would be fabricated. This has to be done by a human (or an agent with
  real network/browser access) after deploying.

## Production readiness

**Not confirmed production-ready.** Automated tests and static/config validation are as thorough
as this environment allows and all pass, but nothing here substitutes for an actual deploy +
live smoke test. Do not treat this as "done" until someone with real Cloudflare/Firebase access
completes: KV namespace id confirmation → `wrangler deploy` → login → dashboard load (confirm no
sync error) → a real data edit persists after reload → logout/login again → (optional) a PIN
change, confirmed via the Network tab that no hash/PIN is ever visible in a response body.

## Files touched this session (on top of the previous session's initial fix)

- `cloudflare-worker/wrangler.toml` — added `[[kv_namespaces]]` block.
- `cloudflare-worker/lib/firebaseIdentity.js` — added `revokeRefreshTokens()`.
- `cloudflare-worker/lib/firebaseToken.js` — JWKS unknown-kid retry fix.
- `cloudflare-worker/login-worker.js` — wired `revokeRefreshTokens()` into `/user/setPin`'s self
  and update paths.
- `cloudflare-worker/tests/worker.integration.test.js` — new, 20 tests.
- `package.json` / `package-lock.json` — `npm install` added `bcryptjs` + `wrangler` under
  `node_modules/` (gitignored, not included in the handoff zip either).
- `handoff/MONEY_MATRIX_CLAUDE_HANDOFF.md` — this file, newly created.
