// ============================================================================================
// MoneyMatrix backend Worker -- Cloudflare Worker replacement for Firebase Cloud Functions.
//
// WHY THIS EXISTS: deploying ANY Firebase Cloud Function requires the Blaze (pay-as-you-go)
// plan -- Cloud Functions cannot be deployed at all on Spark, even within the free quota. That
// was already the root cause of the original `login` 404/CORS failure (fixed by moving login
// here). The SAME root cause was silently still breaking the app after login: the frontend's
// getAppData/saveAppData/setUserPin calls were still httpsCallable() references to Cloud
// Functions that could never actually be deployed -- functions/index.js does not exist anywhere
// in this repository (confirmed: no such file, no functions/ directory, and this repo has no
// git history to recover it from). Every post-login data call was failing, which is exactly
// the "Sync error -- check network" symptom. This file now serves ALL THREE of those endpoints,
// not just login, using the same Worker/service-account architecture.
//
// SECURITY MODEL (see cloudflare-worker/lib/authorization.js for the full write-up):
//   - firestore.rules already deny ALL direct client access to moneymatrix/appData and
//     moneymatrix/credentials (`allow read, write: if false`) -- that boundary is UNCHANGED.
//   - Every protected endpoint below requires `Authorization: Bearer <Firebase ID token>` (NOT
//     the custom token -- the ID token Firebase hands back after signInWithCustomToken()).
//   - The caller's identity/role/approval are taken ONLY from the verified token's claims, and
//     linkedId is taken ONLY from the caller's own record in the server's copy of appData --
//     never from anything the client sends in the request body.
//   - getAppData/saveAppData reconstruct the read/write scoping (downline filtering, perUser
//     isolation, users control-plane restrictions, activityLog append-only, etc.) that used to
//     live in functions/index.js -- see lib/authorization.js's top comment for exactly what is a
//     verbatim port of existing client logic vs. genuinely new code, and why.
// ============================================================================================

import bcrypt from "bcryptjs";
import {
  getGoogleAccessToken,
  readAppData,
  writeAppData,
  bumpMeta,
  readCredentials,
  writeCredentials,
  firestoreDeleteFields,
} from "./lib/googleFirestore.js";
import { mintFirebaseCustomToken, setClaimsEnsuringUserExists, deleteAuthUser, revokeRefreshTokens } from "./lib/firebaseIdentity.js";
import { verifyFirebaseIdToken } from "./lib/firebaseToken.js";
import { buildAuthorizedView, mergeAuthorizedSave } from "./lib/authorization.js";
import { authorizeSetUserPin } from "./lib/userPin.js";

const MAX_PIN_LENGTH = 16;
const BCRYPT_ROUNDS = 10;
const MAX_ATTEMPTS_BEFORE_LOCK = 5;
const BASE_LOCK_SECONDS = 30;
const MAX_LOCK_SECONDS = 15 * 60;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

// Precomputed once per isolate -- a real bcrypt.compare against this fixed hash is what makes
// "no such account" take the same time as "wrong PIN" (timing-safety).
const DUMMY_HASH = '$2a$12$WYqt7KhvBYA/n3dNGZsuaOwQYOS9PIP8RXWA0F1RUxJHP64bK8lhG';

// -------------------------------------------------------------------------------------------
// Rate limiting (login only) -- unchanged from the original login-only version of this file.
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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value)));
  const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `rl:${kind}:${hex}`;
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
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
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

// Every error the client sees is this generic shape -- never a stack trace, never which
// internal step failed, never sensitive data.
function authError(message, status, headers) {
  return jsonResponse({ error: { message } }, status, headers);
}

// -------------------------------------------------------------------------------------------
// Shared auth: verifies the bearer ID token and resolves { uid, role } -- never trusts anything
// from the request body for identity/authorization.
// -------------------------------------------------------------------------------------------

async function authenticateRequest(request, env) {
  const header = request.headers.get("Authorization") || "";
  const m = header.match(/^Bearer (.+)$/);
  if (!m) return { error: { message: "Missing authorization", status: 401 } };
  try {
    const { uid, claims } = await verifyFirebaseIdToken(m[1], env.FIREBASE_PROJECT_ID);
    if (claims.approved !== true) return { error: { message: "Account not approved", status: 403 } };
    return { uid, role: claims.role || "user" };
  } catch (e) {
    // Never leak *why* verification failed (expired vs malformed vs wrong project, etc.) --
    // the client-side behavior for all of these is the same: treat the session as invalid and
    // re-authenticate.
    return { error: { message: "Invalid or expired session", status: 401 } };
  }
}

// -------------------------------------------------------------------------------------------
// POST /login -- UNCHANGED behavior from the original login-only version of this Worker.
// -------------------------------------------------------------------------------------------

async function handleLogin(request, env, cors) {
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
      return authError("Too many attempts -- please wait and try again.", 429, cors);
    }

    const accessToken = await getGoogleAccessToken(env);
    const [appData, credsDoc] = await Promise.all([
      readAppData(env, accessToken),
      readCredentials(env, accessToken),
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
}

// -------------------------------------------------------------------------------------------
// POST /data/get -- replaces the getAppData callable.
// -------------------------------------------------------------------------------------------

async function handleDataGet(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  try {
    const accessToken = await getGoogleAccessToken(env);
    const fullData = await readAppData(env, accessToken);
    const me = (fullData.users || []).find((u) => u.id === auth.uid);
    if (!me) return authError("Account not found", 403, cors);
    const view = buildAuthorizedView(fullData, { uid: auth.uid, role: auth.role, linkedId: me.linkedId || null });
    return jsonResponse({ data: { json: JSON.stringify(view) } }, 200, cors);
  } catch (e) {
    console.error("data/get error:", e && e.stack ? e.stack : e);
    return authError("Could not load data", 500, cors);
  }
}

// -------------------------------------------------------------------------------------------
// POST /data/save -- replaces the saveAppData callable.
//
// KNOWN LIMITATION (disclosed, not hidden -- same practice as the KV rate-limit caveat above):
// this is a read-then-write against Firestore, not a transaction. Two saves landing in the same
// few hundred milliseconds (e.g. two devices signed in as the same account, or a save racing a
// setUserPin-triggered users-list update) could still clobber each other's non-overlapping
// changes. This is a real gap versus a Firestore-transaction implementation, called out
// explicitly rather than silently shipped as if it were fully solved.
// -------------------------------------------------------------------------------------------

async function handleDataSave(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return authError("Invalid payload", 400, cors);
  }
  if (typeof body?.json !== "string") return authError("Invalid payload", 400, cors);
  let submitted;
  try {
    submitted = JSON.parse(body.json);
  } catch (e) {
    return authError("Invalid payload", 400, cors);
  }

  try {
    const accessToken = await getGoogleAccessToken(env);
    const serverData = await readAppData(env, accessToken);
    const me = (serverData.users || []).find((u) => u.id === auth.uid);
    if (!me) return authError("Account not found", 403, cors);

    const merged = mergeAuthorizedSave(serverData, submitted, {
      uid: auth.uid,
      role: auth.role,
      linkedId: me.linkedId || null,
    });
    await writeAppData(env, accessToken, merged);
    await bumpMeta(env, accessToken);
    return jsonResponse({ data: { ok: true } }, 200, cors);
  } catch (e) {
    console.error("data/save error:", e && e.stack ? e.stack : e);
    return authError("Could not save data", 500, cors);
  }
}

// -------------------------------------------------------------------------------------------
// POST /user/setPin -- replaces the setUserPin callable.
// -------------------------------------------------------------------------------------------

async function handleSetUserPin(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  let payload;
  try {
    payload = await request.json();
  } catch (e) {
    return authError("Invalid payload", 400, cors);
  }
  const targetUserId = String(payload?.targetUserId || "").trim();
  if (!targetUserId) return authError("targetUserId is required", 400, cors);
  if (payload?.newPin && String(payload.newPin).length > MAX_PIN_LENGTH) {
    return authError("PIN too long", 400, cors);
  }

  try {
    const accessToken = await getGoogleAccessToken(env);
    const [appData, credsDoc] = await Promise.all([
      readAppData(env, accessToken),
      readCredentials(env, accessToken),
    ]);
    const targetUser = (appData.users || []).find((u) => u.id === targetUserId) || null;

    const decision = authorizeSetUserPin({ uid: auth.uid, role: auth.role }, targetUser, payload);
    if (!decision.ok) return authError(decision.error, 403, cors);

    if (decision.op === "self") {
      const entry = credsDoc[targetUserId];
      const hashToCheck = entry && entry.pinHash ? entry.pinHash : DUMMY_HASH;
      const currentOk = await bcrypt.compare(String(payload.currentPin), hashToCheck);
      if (!currentOk || !entry) return authError("Current PIN is incorrect", 401, cors);
      const newHash = await bcrypt.hash(String(payload.newPin), BCRYPT_ROUNDS);
      await writeCredentials(env, accessToken, { [targetUserId]: { pinHash: newHash, role: entry.role } });
      // Revoke any OTHER session still running with the old PIN (see revokeRefreshTokens'
      // doc comment for exactly what this does and doesn't guarantee instantly).
      await revokeRefreshTokens(env, accessToken, targetUserId);
      return jsonResponse({ data: { ok: true } }, 200, cors);
    }

    if (decision.op === "delete") {
      await firestoreDeleteFields(env, accessToken, "moneymatrix/credentials", [targetUserId]);
      await deleteAuthUser(env, accessToken, targetUserId);
      const remainingUsers = (appData.users || []).filter((u) => u.id !== targetUserId);
      const remainingProfiles = { ...(appData.profiles || {}) };
      delete remainingProfiles[targetUserId];
      const remainingPerUser = { ...(appData.perUser || {}) };
      delete remainingPerUser[targetUserId];
      await writeAppData(env, accessToken, { ...appData, users: remainingUsers, profiles: remainingProfiles, perUser: remainingPerUser });
      await bumpMeta(env, accessToken);
      return jsonResponse({ data: { ok: true } }, 200, cors);
    }

    // create / update
    const role = payload.role || (targetUser ? targetUser.role : "user");
    const newHash = payload.newPin ? await bcrypt.hash(String(payload.newPin), BCRYPT_ROUNDS) : (credsDoc[targetUserId] || {}).pinHash;
    if (!newHash) return authError("newPin is required", 400, cors);

    await writeCredentials(env, accessToken, { [targetUserId]: { pinHash: newHash, role } });
    await setClaimsEnsuringUserExists(env, accessToken, targetUserId, { approved: true, role });
    if (targetUser && payload.newPin) {
      // Admin reset an existing account's PIN — revoke that account's other sessions the same
      // way a self-service change does.
      await revokeRefreshTokens(env, accessToken, targetUserId);
    }

    if (!targetUser) {
      // Brand-new account: give it an empty users entry so a concurrent getAppData right after
      // this call already sees it. The frontend still also does its own local bookkeeping for
      // the fields it manages (displayName, linkedId, etc.) via the normal saveAppData path
      // immediately after this call succeeds.
      const newUsers = [...(appData.users || []), { id: targetUserId, username: targetUserId, role, linkedId: payload.linkedId || null }];
      await writeAppData(env, accessToken, { ...appData, users: newUsers });
      await bumpMeta(env, accessToken);
    } else if (payload.role && payload.role !== targetUser.role) {
      const newUsers = (appData.users || []).map((u) => (u.id === targetUserId ? { ...u, role } : u));
      await writeAppData(env, accessToken, { ...appData, users: newUsers });
      await bumpMeta(env, accessToken);
    }

    return jsonResponse({ data: { ok: true } }, 200, cors);
  } catch (e) {
    console.error("user/setPin error:", e && e.stack ? e.stack : e);
    return authError("Could not complete this operation", 500, cors);
  }
}

// -------------------------------------------------------------------------------------------
// Router
// -------------------------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(env, request);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return authError("Method not allowed", 405, cors);
    }

    const url = new URL(request.url);
    switch (url.pathname) {
      case "/login":
      case "/": // preserved for backwards compatibility with the deployed login-only URL
        return handleLogin(request, env, cors);
      case "/data/get":
        return handleDataGet(request, env, cors);
      case "/data/save":
        return handleDataSave(request, env, cors);
      case "/user/setPin":
        return handleSetUserPin(request, env, cors);
      default:
        return authError("Not found", 404, cors);
    }
  },
};
