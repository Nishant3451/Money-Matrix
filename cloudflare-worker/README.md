# MoneyMatrix backend worker

Replaces ALL FOUR of the original Firebase callable functions — `login`, `getAppData`,
`saveAppData`, and `setUserPin` — none of which can ever actually deploy on the Spark (free)
plan; Cloud Functions require the Blaze plan regardless of how little you'd use. `login` was
moved here first; this Worker now also serves the other three, which is what fixes the
post-login "Sync error — check network" you'd see in production (those calls were silently
failing the whole time, for the exact same Spark-plan reason `login` was).

## Endpoints

| Path             | Replaces (old callable) | Auth required                              |
|-------------------|--------------------------|--------------------------------------------|
| `POST /login` (or `/`) | `login`            | none (username+PIN in body)                |
| `POST /data/get`  | `getAppData`             | `Authorization: Bearer <Firebase ID token>` |
| `POST /data/save` | `saveAppData`            | `Authorization: Bearer <Firebase ID token>` |
| `POST /user/setPin` | `setUserPin`           | `Authorization: Bearer <Firebase ID token>` |

The ID token is what `signInWithCustomToken()` gives the client *after* logging in — not the
custom token `/login` returns. `index.html`'s `callWorkerApi()` handles fetching/refreshing it.

## No new setup needed

The three new endpoints reuse the exact same `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`,
`FIREBASE_PRIVATE_KEY`, and `ALLOWED_ORIGIN` this Worker already had configured for `login` —
nothing new to create or paste in. If you've already deployed the login-only version of this
Worker, `npx wrangler deploy` from this directory picks up the new code with no config changes.

One config value DID change in code (not something you need to edit): CORS now also allows the
`Authorization` request header (`Access-Control-Allow-Headers`), since the new endpoints require
it. `ALLOWED_ORIGIN` itself is unaffected.

It does **not** touch Firestore rules or the app's data model.

## 1. Get a Firebase service account key

1. Firebase console → your project (`money-metrix-9f1da`) → ⚙️ Project settings → **Service accounts**.
2. Click **Generate new private key** → confirm. A JSON file downloads.
3. Open it. You need two fields from it: `client_email` and `private_key`.

This key is as powerful as the Admin SDK — treat it like a password. Never commit it, never put
it in `merged.html`, never paste it anywhere but the `wrangler secret put` prompts below.

## 2. Install Wrangler and log in

```
cd cloudflare-worker
npm install
npx wrangler login
```

This opens a browser to connect Wrangler to your (free) Cloudflare account.

## 3. Create the KV namespace (rate limiting storage)

```
npx wrangler kv namespace create RATE_LIMIT_KV
```

It prints something like:
```
[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "abcd1234..."
```

Copy that `id` value into `wrangler.toml`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`.

## 4. Set the two secrets

```
npx wrangler secret put FIREBASE_CLIENT_EMAIL
# paste the client_email value from the JSON, press enter

npx wrangler secret put FIREBASE_PRIVATE_KEY
# paste the ENTIRE private_key value from the JSON, including
# -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- lines, press enter
```

`FIREBASE_PROJECT_ID` and `ALLOWED_ORIGIN` are already set as plain (non-secret) vars in
`wrangler.toml` — edit that file directly if either ever needs to change.

## 5. Deploy

```
npx wrangler deploy
```

This prints your Worker's URL, e.g.:
```
https://moneymatrix-login.<your-subdomain>.workers.dev
```

That URL is what `merged.html` calls (see "Frontend change" below — it's already pointed at a
`LOGIN_ENDPOINT` constant near the top of the login code, so you only need to paste this URL in
one place).

## Frontend change

In `merged.html`, the `login` callable call was replaced with a `fetch()` to this Worker. Find:

```js
const LOGIN_ENDPOINT = "https://moneymatrix-login.YOUR-SUBDOMAIN.workers.dev";
```

and replace `YOUR-SUBDOMAIN` with your actual Cloudflare Workers subdomain from step 5, then
redeploy `merged.html` to GitHub Pages as usual.

## Manual verification (do this after deploying — not run automatically)

I don't have network access in the environment that wrote this code, so none of the following
were tested against your actual live Firebase/Cloudflare accounts. Please check all of these
before considering this done:

1. **CORS preflight**: open `https://nishant3451.github.io/Money-Matrix/`, open DevTools →
   Network, attempt a login. The `OPTIONS` request to your `workers.dev` URL should return
   `204`, not `404`.
2. **Correct login succeeds**: log in with a real username/PIN pair you know is correct → should
   reach the dashboard as before.
3. **Wrong PIN fails**: should show "Invalid username or PIN.", same as before.
4. **Unknown username fails**: same generic message, not a different one.
5. **Rate limiting**: 5 wrong attempts in a row on the same username should trigger "Too many
   attempts — please wait and try again."
6. **Claims survive token refresh**: stay logged in for over an hour and confirm you're not
   silently logged out or losing permissions (this is what `setClaimsEnsuringUserExists` in the
   worker is for).
7. **`wrangler tail`** while testing lets you watch for any `login worker error:` log lines,
   which indicate something in the Firestore/Identity Toolkit REST calls didn't match what I
   expected — most likely cause would be a typo in the pasted service account values.

## Manual verification — the new /data and /user endpoints (also not run live)

The pure authorization/scoping logic (`cloudflare-worker/lib/`) has 40 automated tests (`npm
test`) that DID run, including a real signature-verification round-trip against a locally
generated RSA keypair — see the top of `lib/authorization.js` for what's proven vs. assumed.
What has NOT been run against your live Firebase/Cloudflare accounts:

1. After deploying, log in normally — the dashboard should load real data instead of showing
   "Sync error — check network".
2. `wrangler tail` while a login + first load happens — watch for `data/get error:` /
   `data/save error:` / `user/setPin error:` log lines.
3. Log in as a downline-scoped (non-admin, linked) user — confirm they see only their own
   supervisor subtree, and that editing a record in their scope saves correctly.
4. Try (via curl/Postman, not the UI) a `/data/save` request with a forged `role: "superadmin"`
   or `users` array in the body while authenticated as a non-admin — confirm the server's own
   data wins, not the forged payload (this is exactly what the automated tests check with a
   mocked Firestore document — worth confirming once against the real one too).
5. Confirm a non-admin's `/user/setPin` call for someone else's account is rejected (403), and
   that their own PIN change still works with the correct `currentPin`.

## Known limitations (disclosed, not hidden)

**`/data/save` is a read-then-write, not a Firestore transaction.** Two saves landing within the
same few hundred milliseconds (two devices signed in as the same account, or a save racing a
`setUserPin`-triggered users-list update) could clobber each other's non-overlapping changes.
Same category of trade-off as the KV rate-limiting note below — a real gap, called out rather
than silently shipped as fully solved. A Firestore transaction (via the REST API's
`:commit`/`:beginTransaction` endpoints) would close this if it matters for your usage pattern.

**The write-scope authorization rules in `lib/authorization.js` and `lib/userPin.js` are a
reconstruction, not a recovered original.** `functions/index.js` — the original Cloud Function
that had the real, previously-working authorization logic — does not exist anywhere in this
repository, and this repo has no git history to recover it from. The READ-side scoping (who
sees what) is a verbatim port of logic that still exists in `index.html` today
(`getDownlineSupervisorIds`/`getScopedMembers` etc.), so that part is solid. The WRITE-side rules
(who can change what) are new code built to mirror the read-side scope symmetrically, which is a
conservative, defensible default — but if your original `saveAppData` had different write rules
in some corner case, this won't match it exactly. Worth a careful read of `lib/authorization.js`
and `lib/userPin.js`'s top comments before trusting this with real user-management operations.

Rate limiting here uses Cloudflare KV, which is eventually consistent and has no cross-key
transactions — unlike the original Firestore-transaction version. Under a very tight burst of
genuinely simultaneous requests, slightly more than 5 attempts could land before the lockout
catches up. It's still a real server-side cap the client can't bypass; it just isn't quite as
tight as the original under extreme parallelism. If this matters for your threat model, the
Firestore-transaction version (i.e., actually deploying `login` as a Cloud Function on Blaze) is
the stronger option — but that requires the billing plan you said you want to avoid.
