// ============================================================================================
// MoneyMatrix login endpoint — Cloudflare Worker replacement for the Firebase `login` callable.
//
// WHY THIS EXISTS: deploying ANY Firebase Cloud Function (including the existing `login` in
// functions/index.js) requires the project to be on the Blaze (pay-as-you-go) plan — Cloud
// Functions cannot be deployed at all on Spark, even for usage that would stay entirely within
// the free quota. That is the root cause of the production 404/CORS failure: the `login`
// function was never actually deployable on money-metrix-9f1da while it stays on Spark. See
// the diagnosis conversation for the reasoning; this file is the fix, not a random rewrite.
//
// This Worker is the ONLY thing that changes. It does not touch setUserPin / saveAppData /
// getAppData, firestore.rules, or the app's data model. It reproduces the exact behavior of
// exports.login from functions/index.js:
//   1. Same input validation (username + pin required).
//   2. Same server-side rate limiting shape (5 attempts, exponential backoff, per-username AND
//      per-IP), see the KV-based caveat below — this is the one place the port is NOT a
//      byte-for-byte equivalent, and that difference is called out rather than hidden.
//   3. Same Firestore documents (moneymatrix/appData, moneymatrix/credentials), read via the
//      Firestore REST API using a service-account-signed OAuth2 token instead of the Admin SDK
//      (the Admin SDK needs a Node server; the REST API is what it calls under the hood).
//   4. Same bcrypt compare against a fixed dummy hash when the user/credential doesn't exist,
//      preserving the timing-safety property.
//   5. Same success response shape: { token, user: { id, username, role, linkedId } }, where
//      `token` is a Firebase custom auth token the client hands to signInWithCustomToken() —
//      exactly as merged.html already does. No frontend change needed beyond calling this URL
//      instead of the callable (see cloudflare-worker/README.md).
//   6. Same claims-persistence step (setCustomUserClaims-equivalent) so the role/approved
//      claims survive the client's automatic hourly token refresh, not just the first token.
//
// WHAT IS GENUINELY DIFFERENT (disclosed, not hidden):
//   - Rate limiting uses Cloudflare KV instead of a Firestore transaction. KV is NOT strongly
//     consistent and has no cross-key transaction — under a very tight burst of truly parallel
//     requests, a few more than 5 attempts could land before the lockout catches up, more so
//     than the original Firestore-transaction version. It is still a real, server-side,
//     un-bypassable-by-the-client cap; it just isn't as tight under extreme parallelism as the
//     Firestore version. Flagged explicitly, same as the original file flags its own
//     TOCTOU-adjacent caveats.
//   - This file has NOT been executed against live Firestore, live Google OAuth2 token
//     endpoints, or live Identity Toolkit endpoints from this environment (no network access
//     here). The request/response shapes below are built to the documented Google Identity
//     Toolkit / Firestore REST API contracts and mirror what the Firebase Admin SDK does
//     internally, but treat this as implemented-with-high-confidence, not verified — smoke-test
//     the four flows in the README's "manual verification" section right after deploying.
// ============================================================================================

import bcrypt from "bcryptjs";

const MAX_PIN_LENGTH = 16;
const BCRYPT_ROUNDS = 10;
const MAX_ATTEMPTS_BEFORE_LOCK = 5;
const BASE_LOCK_SECONDS = 30;
const MAX_LOCK_SECONDS = 15 * 60;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const CUSTOM_TOKEN_AUDIENCE =
  "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const OAUTH_SCOPE =
  "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit";

// Precomputed once per isolate (mirrors the original file's module-scope DUMMY_HASH) — a real
// bcrypt.compare against this fixed hash is what makes "no such account" take the same time as
// "wrong PIN".
const DUMMY_HASH = '$2a$12$WYqt7KhvBYA/n3dNGZsuaOwQYOS9PIP8RXWA0F1RUxJHP64bK8lhG';

// In-isolate cache for the Google OAuth2 access token, so a burst of requests hitting the same
// warm isolate doesn't re-mint a fresh token every time. Best-effort only — a cold isolate
// always fetches a fresh one. Never persisted to KV (no reason to let a bearer token outlive
// the isolate that fetched it).
let cachedAccessToken = null; // { token, expiresAt }

// -------------------------------------------------------------------------------------------
// Small standalone helpers (no Node APIs — everything here must run in a Workers V8 isolate).
// -------------------------------------------------------------------------------------------

function base64UrlFromBytes(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlFromString(str) {
  return base64UrlFromBytes(new TextEncoder().encode(str));
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importServiceAccountKey(pemPrivateKey) {
  const der = pemToDer(pemPrivateKey);
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// Signs a compact RS256 JWT. `header`/`payload` are plain objects; `key` is a CryptoKey from
// importServiceAccountKey(). Used both for the Google OAuth2 JWT-bearer assertion and for
// minting the Firebase custom token itself — both are just RS256 JWTs signed by the same
// service-account private key, per Google's documented custom-token format.
async function signJwtRS256(header, payload, key) {
  const encHeader = base64UrlFromString(JSON.stringify(header));
  const encPayload = base64UrlFromString(JSON.stringify(payload));
  const signingInput = `${encHeader}.${encPayload}`;
  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${base64UrlFromBytes(new Uint8Array(sig))}`;
}

async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Converts one Firestore REST "Value" object into a plain JS value. Only the shapes this app
// actually stores are handled; anything else falls back to `null` rather than throwing, so an
// unexpected field can't take the whole login down.
function decodeFirestoreValue(value) {
  if (!value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return value.doubleValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("nullValue" in value) return null;
  if ("mapValue" in value) return decodeFirestoreFields(value.mapValue.fields || {});
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(decodeFirestoreValue);
  return null;
}
function decodeFirestoreFields(fields) {
  const out = {};
  for (const key of Object.keys(fields || {})) out[key] = decodeFirestoreValue(fields[key]);
  return out;
}

// -------------------------------------------------------------------------------------------
// Google OAuth2 (service-account JWT-bearer flow) — this is what lets a Worker, which cannot
// run the Firebase Admin SDK, still call Firestore/Identity Toolkit with admin privileges.
// -------------------------------------------------------------------------------------------

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedAccessToken && cachedAccessToken.expiresAt - 60 > now) {
    return cachedAccessToken.token;
  }
  const key = await importServiceAccountKey(env.FIREBASE_PRIVATE_KEY);
  const assertion = await signJwtRS256(
    { alg: "RS256", typ: "JWT" },
    {
      iss: env.FIREBASE_CLIENT_EMAIL,
      scope: OAUTH_SCOPE,
      aud: GOOGLE_TOKEN_ENDPOINT,
      iat: now,
      exp: now + 3600,
    },
    key
  );
  const resp = await fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  if (!resp.ok) {
    throw new Error(`Google OAuth2 token exchange failed (${resp.status})`);
  }
  const json = await resp.json();
  cachedAccessToken = { token: json.access_token, expiresAt: now + (json.expires_in || 3600) };
  return cachedAccessToken.token;
}

async function firestoreGetDoc(env, accessToken, docPath) {
  const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${docPath}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (resp.status === 404) return {}; // doc doesn't exist yet — same as snap.exists === false
  if (!resp.ok) throw new Error(`Firestore read failed for ${docPath} (${resp.status})`);
  const json = await resp.json();
  return decodeFirestoreFields(json.fields || {});
}

// Mirrors readAppData() in functions/index.js: the whole app state lives in one string field
// called `json` on moneymatrix/appData, not as top-level document fields.
async function readAppData(env, accessToken) {
  const doc = await firestoreGetDoc(env, accessToken, "moneymatrix/appData");
  try {
    return JSON.parse(doc.json || "{}");
  } catch (e) {
    return {};
  }
}

// -------------------------------------------------------------------------------------------
// Firebase custom-token minting + custom-claims persistence — both admin-only operations that
// the Admin SDK normally does locally / via Identity Toolkit. Done here by hand since there is
// no Admin SDK available outside a Node process.
// -------------------------------------------------------------------------------------------

async function mintFirebaseCustomToken(env, uid, claims) {
  const key = await importServiceAccountKey(env.FIREBASE_PRIVATE_KEY);
  const now = Math.floor(Date.now() / 1000);
  return signJwtRS256(
    { alg: "RS256", typ: "JWT" },
    {
      iss: env.FIREBASE_CLIENT_EMAIL,
      sub: env.FIREBASE_CLIENT_EMAIL,
      aud: CUSTOM_TOKEN_AUDIENCE,
      iat: now,
      exp: now + 3600,
      uid,
      claims,
    },
    key
  );
}

// Mirrors setClaimsEnsuringUserExists() in functions/index.js: sets custom claims on the
// Identity Platform user record so they survive the client's automatic hourly token refresh
// (a one-time custom token's claims do NOT — see the long comment on this in the original
// file). Creates the Auth user record first if this is genuinely their first-ever login.
async function setClaimsEnsuringUserExists(env, accessToken, uid, claims) {
  const base = `https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}`;
  const updateResp = await fetch(`${base}/accounts:update`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify(claims) }),
  });
  if (updateResp.ok) return;

  const errBody = await updateResp.json().catch(() => ({}));
  const isNotFound = errBody?.error?.message?.includes("USER_NOT_FOUND");
  if (!isNotFound) {
    throw new Error(`accounts:update failed (${updateResp.status}): ${JSON.stringify(errBody)}`);
  }

  const createResp = await fetch(`${base}/accounts:signUp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: uid }),
  });
  if (!createResp.ok) {
    const createErr = await createResp.json().catch(() => ({}));
    // uid may already exist despite the race above (two first-logins at once) — that's fine,
    // fall through to the retry below either way.
    if (!createErr?.error?.message?.includes("DUPLICATE_LOCAL_ID")) {
      throw new Error(`accounts:signUp failed (${createResp.status}): ${JSON.stringify(createErr)}`);
    }
  }

  const retryResp = await fetch(`${base}/accounts:update`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify(claims) }),
  });
  if (!retryResp.ok) {
    const retryErr = await retryResp.json().catch(() => ({}));
    throw new Error(`accounts:update retry failed (${retryResp.status}): ${JSON.stringify(retryErr)}`);
  }
}

// -------------------------------------------------------------------------------------------
// Rate limiting — same window/backoff MATH as functions/index.js's nextFailedAttemptState(),
// ported unchanged. Storage backend (KV vs. a Firestore transaction) is the disclosed
// difference — see the file-level comment at the top.
// -------------------------------------------------------------------------------------------

function nextFailedAttemptState(state, now) {
  let next = state ? { ...state } : { count: 0, windowStart: now, lockedUntil: 0 };
  if (now - next.windowStart > ATTEMPT_WINDOW_MS) {
    next = { count: 0, windowStart: now, lockedUntil: 0 };
  }
  next.count += 1;
  if (next.count >= MAX_ATTEMPTS_BEFORE_LOCK) {
    const lockSeconds = Math.min(
      BASE_LOCK_SECONDS * Math.pow(2, next.count - MAX_ATTEMPTS_BEFORE_LOCK),
      MAX_LOCK_SECONDS
    );
    next.lockedUntil = now + lockSeconds * 1000;
  }
  return next;
}

async function kvKey(kind, value) {
  return `rl:${kind}:${await sha256Hex(String(value))}`;
}

async function reserveLoginAttempt(env, usernameKey, ip) {
  const userKvKey = await kvKey("user", usernameKey);
  const ipKvKey = await kvKey("ip", ip);
  const [userState, ipState] = await Promise.all([
    env.RATE_LIMIT_KV.get(userKvKey, "json"),
    env.RATE_LIMIT_KV.get(ipKvKey, "json"),
  ]);
  const now = Date.now();
  const userLocked = !!(userState && userState.lockedUntil > now);
  const ipLocked = !!(ipState && ipState.lockedUntil > now);
  if (userLocked || ipLocked) return { locked: true };

  const nextUserState = nextFailedAttemptState(userState, now);
  const nextIpState = nextFailedAttemptState(ipState, now);
  const ttlSeconds = Math.ceil(ATTEMPT_WINDOW_MS / 1000) + MAX_LOCK_SECONDS;
  await Promise.all([
    env.RATE_LIMIT_KV.put(userKvKey, JSON.stringify(nextUserState), { expirationTtl: ttlSeconds }),
    env.RATE_LIMIT_KV.put(ipKvKey, JSON.stringify(nextIpState), { expirationTtl: ttlSeconds }),
  ]);
  return { locked: false };
}

async function finalizeLoginAttempt(env, usernameKey, ip, success) {
  if (!success) return;
  const now = Date.now();
  const resetState = { count: 0, windowStart: now, lockedUntil: 0 };
  const userKvKey = await kvKey("user", usernameKey);
  const ipKvKey = await kvKey("ip", ip);
  await Promise.all([
    env.RATE_LIMIT_KV.put(userKvKey, JSON.stringify(resetState)),
    env.RATE_LIMIT_KV.put(ipKvKey, JSON.stringify(resetState)),
  ]);
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing
// -------------------------------------------------------------------------------------------

function corsHeaders(env, request) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim());
  const headers = { Vary: "Origin" };
  if (origin && allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type";
    headers["Access-Control-Max-Age"] = "86400";
  }
  return headers;
}

function jsonResponse(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// Every error the client sees is this generic shape — never "no such user", never a stack
// trace, never which internal step failed. Same "don't leak which check failed" property the
// original HttpsError-based errors had.
function authError(message, status, headers) {
  return jsonResponse({ error: { message } }, status, headers);
}

export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(env, request);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return authError("Method not allowed", 405, cors);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return authError("Username and PIN are required", 400, cors);
    }

    const username = String(body?.username || "").trim();
    const pin = String(body?.pin || "").trim();
    if (!username || !pin) {
      return authError("Username and PIN are required", 400, cors);
    }
    if (pin.length > MAX_PIN_LENGTH) {
      return authError("Invalid username or PIN", 400, cors);
    }

    const usernameKey = username.toLowerCase();
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    try {
      const { locked } = await reserveLoginAttempt(env, usernameKey, ip);
      if (locked) {
        return authError("Too many attempts — please wait and try again.", 429, cors);
      }

      const accessToken = await getGoogleAccessToken(env);
      const [appData, credsDoc] = await Promise.all([
        readAppData(env, accessToken),
        firestoreGetDoc(env, accessToken, "moneymatrix/credentials"),
      ]);

      const users = appData.users || [];
      const user = users.find((u) => (u.username || "").toLowerCase() === usernameKey);
      const entry = user ? credsDoc[user.id] || null : null;

      const hashToCheck = entry && entry.pinHash ? entry.pinHash : DUMMY_HASH;
      const compareOk = await bcrypt.compare(pin, hashToCheck);
      const ok = compareOk && !!user && !!(entry && entry.pinHash);

      await finalizeLoginAttempt(env, usernameKey, ip, ok);

      if (!ok) {
        return authError("Invalid username or PIN", 401, cors);
      }

      const role = entry.role || user.role || "user";
      const claims = { approved: true, role };

      await setClaimsEnsuringUserExists(env, accessToken, user.id, claims);
      const token = await mintFirebaseCustomToken(env, user.id, claims);

      return jsonResponse(
        {
          token,
          user: { id: user.id, username: user.username, role, linkedId: user.linkedId || null },
        },
        200,
        cors
      );
    } catch (e) {
      console.error("login worker error:", e && e.stack ? e.stack : e);
      return authError("Invalid username or PIN", 401, cors);
    }
  },
};
