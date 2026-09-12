# MoneyMatrix login worker

Replaces the Firebase `login` callable function, which cannot be deployed at all on the Spark
(free) plan — Cloud Functions require the Blaze plan regardless of how little you'd actually use.
This Worker does the exact same job (verify username + PIN server-side, mint a Firebase custom
auth token) on Cloudflare's free tier instead. It does **not** touch `setUserPin`, `saveAppData`,
`getAppData`, Firestore rules, or the app's data. Everything else stays exactly as it is.

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

## Known limitation (disclosed, not hidden)

Rate limiting here uses Cloudflare KV, which is eventually consistent and has no cross-key
transactions — unlike the original Firestore-transaction version. Under a very tight burst of
genuinely simultaneous requests, slightly more than 5 attempts could land before the lockout
catches up. It's still a real server-side cap the client can't bypass; it just isn't quite as
tight as the original under extreme parallelism. If this matters for your threat model, the
Firestore-transaction version (i.e., actually deploying `login` as a Cloud Function on Blaze) is
the stronger option — but that requires the billing plan you said you want to avoid.
