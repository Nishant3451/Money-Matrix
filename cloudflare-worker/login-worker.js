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
  readAppDataWithVersion,
  writeAppDataIfUnchanged,
  bumpMeta,
  readCredentials,
  writeCredentials,
  firestoreDeleteFields,
} from "./lib/googleFirestore.js";
import { mintFirebaseCustomToken, setClaimsEnsuringUserExists, deleteAuthUser, revokeRefreshTokens } from "./lib/firebaseIdentity.js";
import { verifyFirebaseIdToken } from "./lib/firebaseToken.js";
import { buildAuthorizedView, mergeAuthorizedSave, isFullAccessRole } from "./lib/authorization.js";
import { authorizeSetUserPin } from "./lib/userPin.js";
import {
  PRIVACY_REQUEST_CATEGORIES,
  PRIVACY_PREFERENCE_KEYS,
  POLICY_TYPES,
  MAX_DESCRIPTION_LENGTH,
  MAX_NOTE_LENGTH,
  MAX_REQUESTS_PER_WINDOW,
  REQUEST_WINDOW_MS,
  MAX_EXPORTS_PER_WINDOW,
  EXPORT_WINDOW_MS,
  MAX_PRIVACY_WRITES_PER_WINDOW,
  PRIVACY_WRITE_WINDOW_MS,
  genId,
  nowTs,
  sanitizeText,
  isNonEmptyString,
  checkAndReserveRateLimit,
  appendAudit,
  getUserRequests,
  findPublishedPolicy,
  latestPublishedPolicy,
  isValidStatusTransition,
  isKnownConsentCategory,
} from "./lib/privacy.js";

const MAX_PIN_LENGTH = 16;
const BCRYPT_ROUNDS = 10;

// PHASE 8 HARDENING: per-endpoint request-body byte ceilings -- see readJsonBody's doc comment
// for why these exist. Each is sized well above any realistic legitimate payload for that
// endpoint (never an arbitrary tiny number that could reject real use):
//   - LOGIN: username + PIN, two short strings.
//   - DATA_SAVE: the client's whole local appData JSON blob. Firestore hard-caps a document at
//     ~1 MiB, so nothing this large could ever be written successfully regardless -- 3 MiB gives
//     3x headroom above that hard ceiling while still bounding unbounded ingestion.
//   - SET_USER_PIN: a handful of short fields (ids, a PIN, a role string).
//   - PRIVACY: every /privacy/* handler already clamps its own string fields to small,
//     explicit lengths (MAX_DESCRIPTION_LENGTH, MAX_NOTE_LENGTH, etc. in lib/privacy.js) --
//     this just bounds the raw body before that per-field validation runs.
const MAX_LOGIN_BODY_BYTES = 2 * 1024;
const MAX_DATA_SAVE_BODY_BYTES = 3 * 1024 * 1024;
const MAX_SETUSERPIN_BODY_BYTES = 8 * 1024;
const MAX_PRIVACY_BODY_BYTES = 16 * 1024;
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

// PHASE 8 HARDENING (Section 2 -- security headers): every JSON response from this Worker now
// carries a small, safe set of headers that cannot break anything, because this endpoint only
// ever returns `application/json` -- never HTML, so there is no inline-script/inline-style
// surface here for a CSP to fight with (that surface lives entirely in index.html, which
// GitHub Pages serves with NO ability to set custom HTTP headers at all -- confirmed against
// GitHub's own docs/support threads; only a <meta http-equiv> CSP would even be possible there,
// and even that can't carry frame-ancestors, which browsers ignore outside a real header -- see
// PHASE-8-PRODUCTION-HARDENING-REPORT.md Section 2 for the full writeup and why a strict CSP is
// staged as a documented future migration rather than forced in here today):
//   - X-Content-Type-Options: nosniff -- stops a browser from ever MIME-sniffing a JSON
//     response as something else (e.g. HTML) if it somehow ended up rendered directly.
//   - Referrer-Policy: no-referrer -- this is an API; there is no reason any Referer header
//     should ever leave the browser when following a link derived from one of these responses.
//   - Cache-Control: no-store -- every response here is either an auth error or contains a
//     specific user's data; none of it should ever be written to any cache.
function jsonResponse(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

// Every error the client sees is this generic shape -- never a stack trace, never which
// internal step failed, never sensitive data.
function authError(message, status, headers) {
  return jsonResponse({ error: { message } }, status, headers);
}

// -------------------------------------------------------------------------------------------
// PHASE 8 HARDENING: bounded request-body reading.
//
// Every handler used to call `await request.json()` directly, with no limit at all on how much
// the caller could send -- Content-Length is attacker-controlled and was never even consulted.
// A body far bigger than anything a real client would ever send (accidentally or as a deliberate
// resource-abuse attempt) would still be fully buffered and JSON.parse'd before any of a
// handler's own field-level validation (sanitizeText's length caps, MAX_PIN_LENGTH, etc.) got a
// chance to reject it -- wasted CPU/memory on every call, reachable pre-auth via POST /login.
// This closes that gap with the smallest fix that doesn't touch legitimate use: a per-endpoint
// byte ceiling, checked BOTH against a declared Content-Length (fast rejection, no read at all)
// AND against the actual bytes streamed off the body (a missing/understated Content-Length must
// not bypass the limit). Limits are sized generously above any realistic real payload for that
// endpoint -- see each call site -- not picked arbitrarily small. On overflow this returns a
// generic 413 via the same authError() shape every other rejection uses (never a stack trace or
// a hint about which check tripped).
async function readJsonBody(request, maxBytes) {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null && Number(declaredLength) > maxBytes) {
    return { tooLarge: true };
  }
  if (!request.body) {
    // No body at all -- let JSON.parse("") below fail normally as "Invalid payload", same as
    // today, rather than a misleading 413.
    return parseJsonBytes(new Uint8Array(0));
  }
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch (_) {}
        return { tooLarge: true };
      }
      chunks.push(value);
    }
  } catch (e) {
    return { invalid: true };
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return parseJsonBytes(combined);
}

function parseJsonBytes(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { value: JSON.parse(text) };
  } catch (e) {
    return { invalid: true };
  }
}

/** Reads and JSON-parses a request body under a byte ceiling, returning the same
 * authError()-shaped Response on failure so every handler's call site stays a one-liner. Returns
 * `null` on failure (already responded); the parsed body otherwise. */
async function readBodyOrRespond(request, maxBytes, cors) {
  const result = await readJsonBody(request, maxBytes);
  if (result.tooLarge) return { error: authError("Payload too large", 413, cors) };
  if (result.invalid || result.value === undefined) return { error: authError("Invalid payload", 400, cors) };
  return { value: result.value };
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
  const read = await readBodyOrRespond(request, MAX_LOGIN_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;

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
// CONCURRENCY (Phase 5 audit item #18): this used to be a plain read-then-write against
// Firestore (no transaction) -- two saves landing in the same few hundred milliseconds (e.g.
// two devices signed in as the same account, or a save racing a setUserPin-triggered
// users-list update) could clobber each other's non-overlapping changes. That gap is now
// closed the same way HARDENING ISSUE #4 closed it for /privacy/*: read the document's
// Firestore `updateTime` alongside its data, write back conditionally on nothing else having
// changed that updateTime in between, and on conflict re-read + reapply the same merge, up to
// MAX_DATA_SAVE_ATTEMPTS times. See runPrivacyMutation's doc comment above for the mechanism
// this generalizes (that comment's note that "the same primitives should generalize to
// [handleDataSave/handleSetUserPin] directly" is exactly what this change does for
// handleDataSave). handleSetUserPin's own multi-document writes (credentials + users +
// Firebase Auth claims) are a materially different shape -- credentials and Auth claims are
// per-field writes keyed by targetUserId that don't race across different target users, but the
// appData.users array itself is a whole-document field and DID have the same lost-update
// exposure as this one did. That's now closed too -- see writeUsersFieldWithRetry above
// handleSetUserPin and PHASE-8-PRODUCTION-HARDENING-REPORT.md §6.
// -------------------------------------------------------------------------------------------
const MAX_DATA_SAVE_ATTEMPTS = 6;

async function handleDataSave(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_DATA_SAVE_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  if (typeof body?.json !== "string") return authError("Invalid payload", 400, cors);
  let submitted;
  try {
    submitted = JSON.parse(body.json);
  } catch (e) {
    return authError("Invalid payload", 400, cors);
  }

  try {
    const accessToken = await getGoogleAccessToken(env);
    for (let attempt = 0; attempt < MAX_DATA_SAVE_ATTEMPTS; attempt++) {
      const { data: serverData, updateTime } = await readAppDataWithVersion(env, accessToken);
      const me = (serverData.users || []).find((u) => u.id === auth.uid);
      if (!me) return authError("Account not found", 403, cors);

      const merged = mergeAuthorizedSave(serverData, submitted, {
        uid: auth.uid,
        role: auth.role,
        linkedId: me.linkedId || null,
      });
      const write = await writeAppDataIfUnchanged(env, accessToken, merged, updateTime);
      if (write.conflict) continue; // someone else wrote in between -- re-read and reapply

      await bumpMeta(env, accessToken);
      return jsonResponse({ data: { ok: true } }, 200, cors);
    }
    // Exhausted retries under sustained contention -- fail loudly rather than silently
    // dropping the caller's change or overwriting someone else's, exactly like
    // runPrivacyMutation above.
    return authError("This change conflicted with another update -- please try again.", 409, cors);
  } catch (e) {
    console.error("data/save error:", e && e.stack ? e.stack : e);
    return authError("Could not save data", 500, cors);
  }
}

// -------------------------------------------------------------------------------------------
// POST /user/setPin -- replaces the setUserPin callable.
//
// PHASE 8 FIX -- PIN CONCURRENCY (appData.users race): handleSetUserPin used to read appData
// ONCE at the top of the handler (shared with the authorization decision) and, for the
// create/update-role/delete branches, write that same captured object back later via a plain
// writeAppData() -- no version precondition, unlike handleDataSave/runPrivacyMutation. Two
// admins acting on two DIFFERENT target users within the same request window raced on this one
// shared document: whichever write landed second silently clobbered the first admin's
// appData.users change with its own stale copy. Concretely, for a "create": the new user's
// Firebase Auth record and moneymatrix/credentials entry (separate documents/field-writes,
// unaffected by this race) would exist and the account could log in and receive claims, but its
// appData.users entry could vanish -- and every other endpoint (handleDataSave,
// runPrivacyMutation, handleDataGet) resolves the caller via
// `(serverData.users||[]).find(u=>u.id===auth.uid)` and returns 403 "Account not found" when
// that's missing. For "update role" it meant a role change could be silently reverted by a
// losing race, with no error surfaced to either admin. This was a genuine, demonstrable
// lost-update race (not the same shape as handleDataSave's -- see writeUsersFieldWithRetry below
// -- but real), so it gets the smallest fix that closes it: the three appData.users mutation
// sites now go through the SAME optimistic-concurrency primitive (readAppDataWithVersion /
// writeAppDataIfUnchanged / retry-on-conflict) handleDataSave already uses, re-deriving the
// mutation from a FRESH read on every attempt instead of the stale `appData` closure captured
// before this request's credentials/Auth-claims writes. The credentials doc and Firebase Auth
// claims writes are untouched by this fix -- they are per-field PATCH writes keyed by
// targetUserId (firestorePatchDoc's updateMask), which Firestore already applies atomically per
// field path, so two admins touching two different target users' credentials never raced there
// in the first place; only the whole-document appData.users array had this gap. See
// PHASE-8-PRODUCTION-HARDENING-REPORT.md §6 for the full writeup and the regression test.
// -------------------------------------------------------------------------------------------
const MAX_SETUSERPIN_USERS_WRITE_ATTEMPTS = 6;

/**
 * Applies a narrow, targeted mutation to appData (scoped to the users/profiles/perUser fields
 * setUserPin touches) with the same read-fresh / write-if-unchanged / retry-on-conflict shape as
 * handleDataSave and runPrivacyMutation.
 *
 * `mutate(freshData)` must be a pure function of a freshly-read appData object: return the next
 * appData object to write, or `null` to mean "nothing to change" (e.g. a concurrent request
 * already applied this exact change, or the target no longer exists) -- in which case no write
 * is attempted on this call at all. Because `mutate` may run more than once (once per retry), it
 * must have no side effects beyond deriving its return value from the object it's handed.
 */
async function writeUsersFieldWithRetry(env, accessToken, mutate) {
  for (let attempt = 0; attempt < MAX_SETUSERPIN_USERS_WRITE_ATTEMPTS; attempt++) {
    const { data, updateTime } = await readAppDataWithVersion(env, accessToken);
    const next = mutate(data);
    if (next === null) return { applied: false };
    const write = await writeAppDataIfUnchanged(env, accessToken, next, updateTime);
    if (write.conflict) continue; // someone else wrote appData in between -- re-read and reapply
    return { applied: true };
  }
  // Exhausted retries under sustained contention. The credentials/claims writes that preceded
  // this call have already happened and are NOT rolled back (see the handler below for why that
  // asymmetry is disclosed, not hidden) -- but we must not silently drop the appData.users change
  // or pretend it landed, so this surfaces as a real 500 rather than a false success.
  throw new Error("appData users update conflicted repeatedly");
}

async function handleSetUserPin(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_SETUSERPIN_BODY_BYTES, cors);
  if (read.error) return read.error;
  const payload = read.value;
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
      await writeUsersFieldWithRetry(env, accessToken, (data) => {
        const users = data.users || [];
        if (!users.some((u) => u.id === targetUserId)) return null; // already removed by a concurrent request
        const remainingProfiles = { ...(data.profiles || {}) };
        delete remainingProfiles[targetUserId];
        const remainingPerUser = { ...(data.perUser || {}) };
        delete remainingPerUser[targetUserId];
        return {
          ...data,
          users: users.filter((u) => u.id !== targetUserId),
          profiles: remainingProfiles,
          perUser: remainingPerUser,
        };
      });
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
      await writeUsersFieldWithRetry(env, accessToken, (data) => {
        const users = data.users || [];
        if (users.some((u) => u.id === targetUserId)) return null; // already created by a concurrent request -- don't duplicate the row
        return { ...data, users: [...users, { id: targetUserId, username: targetUserId, role, linkedId: payload.linkedId || null }] };
      });
      await bumpMeta(env, accessToken);
    } else if (payload.role && payload.role !== targetUser.role) {
      await writeUsersFieldWithRetry(env, accessToken, (data) => {
        const users = data.users || [];
        const idx = users.findIndex((u) => u.id === targetUserId);
        if (idx === -1) return null; // target was concurrently deleted -- nothing to update
        if (users[idx].role === role) return null; // a concurrent request already applied this exact change
        const newUsers = [...users];
        newUsers[idx] = { ...newUsers[idx], role };
        return { ...data, users: newUsers };
      });
      await bumpMeta(env, accessToken);
    }

    return jsonResponse({ data: { ok: true } }, 200, cors);
  } catch (e) {
    console.error("user/setPin error:", e && e.stack ? e.stack : e);
    return authError("Could not complete this operation", 500, cors);
  }
}

// -------------------------------------------------------------------------------------------
// Privacy system (Part B) — /privacy/*
//
// Every handler below follows the same shape as handleSetUserPin: authenticate first (identity
// only ever comes from the verified token, never the body), read the ONE authoritative appData
// document, apply one narrow validated change, write the whole document back. See
// lib/privacy.js's module comment for the field-level schema and why generic saveAppData can
// never touch these fields.
//
// CONCURRENCY (HARDENING ISSUE #4): every /privacy/* write below goes through
// runPrivacyMutation(), which reads the document's Firestore `updateTime` alongside its data and
// writes back conditionally on nothing else having changed that updateTime in between (Firestore
// REST `currentDocument.updateTime` precondition -- see writeAppDataIfUnchanged in
// lib/googleFirestore.js). If another write lands first, the conditional write is rejected
// (rather than silently overwriting it) and we re-read + reapply the same mutation, up to
// MAX_PRIVACY_WRITE_ATTEMPTS times. This closes the read-modify-write lost-update race for the
// privacy fields specifically -- see PART-B-HARDENING-REPORT.md for why this is the right scope
// (not a full Firestore transaction, and not applied to handleDataSave/handleSetUserPin, which
// keep their previously-disclosed same-limitation as a separate, lower-risk gap).
const MAX_PRIVACY_WRITE_ATTEMPTS = 6;

/**
 * Runs one privacy mutation with optimistic-concurrency retry.
 *
 * `mutate({ appData, me })` must be a pure function of the freshly-read appData: it validates
 * against and modifies `appData` in place (or returns a new object) and returns either
 *   - { error: { message, status } }   -- a validation/authorization failure; NOT retried, and
 *                                          nothing is written.
 *   - { appData, result }              -- the (possibly modified) appData to write back, plus
 *                                          whatever `result` the handler should return to the
 *                                          client on success.
 * Because `mutate` may be called more than once (once per retry), it must not have side effects
 * beyond modifying the appData object it was handed -- every handler below satisfies this (they
 * only read/write fields on the `appData` parameter).
 */
async function runPrivacyMutation(env, auth, mutate) {
  const accessToken = await getGoogleAccessToken(env);
  for (let attempt = 0; attempt < MAX_PRIVACY_WRITE_ATTEMPTS; attempt++) {
    const { data: appData, updateTime } = await readAppDataWithVersion(env, accessToken);
    const me = (appData.users || []).find((u) => u.id === auth.uid);
    if (!me) return { error: { message: "Account not found", status: 403 } };

    const outcome = await mutate({ appData, me });
    if (outcome.error) return outcome; // validation failure -- never retried, never written

    const write = await writeAppDataIfUnchanged(env, accessToken, outcome.appData, updateTime);
    if (write.conflict) continue; // someone else wrote in between -- re-read and reapply

    await bumpMeta(env, accessToken);
    return outcome;
  }
  // Exhausted retries under sustained contention. Fail loudly rather than silently dropping the
  // caller's change or writing over someone else's -- the client is told to retry, exactly like
  // any other transient failure (see HARDENING ISSUE #2's offline-handling requirement: never a
  // false success).
  return { error: { message: "This change conflicted with another update -- please try again.", status: 409 } };
}

// POST /privacy/consent -- record or withdraw a consent decision for the caller's own account.
async function handlePrivacyConsent(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const type = sanitizeText(body?.type, 100);
  const purpose = sanitizeText(body?.purpose, 300);
  const version = sanitizeText(body?.version, 40);
  const action = body?.action === "withdraw" ? "withdraw" : "grant";
  if (!isNonEmptyString(type) || !isNonEmptyString(purpose)) {
    return authError("type and purpose are required", 400, cors);
  }
  // CONSENT API INTEGRITY: reject anything not on the server's own allow-list rather than
  // letting a client (or a direct API caller) manufacture a new consent category just by
  // sending a new string. See KNOWN_CONSENT_CATEGORIES in lib/privacy.js -- it is intentionally
  // empty today because this application has no real optional processing yet.
  if (!isKnownConsentCategory(type, purpose)) {
    return authError("Unknown consent category -- this application has no optional processing matching that type/purpose", 400, cors);
  }

  const rl = await checkAndReserveRateLimit(env, "privacy_consent", auth.uid, MAX_PRIVACY_WRITES_PER_WINDOW, PRIVACY_WRITE_WINDOW_MS);
  if (rl.misconfigured) {
    console.error("privacy/consent rate limiting is misconfigured: RATE_LIMIT_KV binding is missing.");
    return authError("Privacy actions are temporarily unavailable -- please try again shortly.", 503, cors);
  }
  if (!rl.allowed) return authError("Too many requests -- please try again later.", 429, cors);

  try {
    const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
      const consents = { ...(appData.privacyConsents || {}) };
      const mine = Array.isArray(consents[auth.uid]) ? [...consents[auth.uid]] : [];

      if (action === "withdraw") {
        let found = false;
        for (let i = mine.length - 1; i >= 0; i--) {
          if (mine[i].type === type && mine[i].purpose === purpose && mine[i].status === "granted") {
            mine[i] = { ...mine[i], status: "withdrawn", withdrawnAt: nowTs() };
            found = true;
            break;
          }
        }
        if (!found) return { error: { message: "No active consent to withdraw for this type/purpose", status: 404 } };
      } else {
        mine.push({
          id: genId("con"),
          type,
          purpose,
          version: version || null,
          timestamp: nowTs(),
          source: "privacy_center",
          status: "granted",
          withdrawnAt: null,
        });
      }
      consents[auth.uid] = mine;
      appData.privacyConsents = consents;
      appendAudit(appData, { uid: auth.uid, role: auth.role, action: `consent_${action}`, detail: { type, purpose } });
      return { appData, result: { ok: true } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/consent error:", e && e.stack ? e.stack : e);
    return authError("Could not record consent", 500, cors);
  }
}

// POST /privacy/policy/accept -- record acceptance of a specific PUBLISHED policy version.
async function handlePolicyAccept(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const policyType = sanitizeText(body?.policyType, 60);
  const version = sanitizeText(body?.version, 40);
  if (!POLICY_TYPES.includes(policyType) || !isNonEmptyString(version)) {
    return authError("Invalid policyType or version", 400, cors);
  }

  const rl = await checkAndReserveRateLimit(env, "policy_accept", auth.uid, MAX_PRIVACY_WRITES_PER_WINDOW, PRIVACY_WRITE_WINDOW_MS);
  if (rl.misconfigured) {
    console.error("privacy/policy/accept rate limiting is misconfigured: RATE_LIMIT_KV binding is missing.");
    return authError("Privacy actions are temporarily unavailable -- please try again shortly.", 503, cors);
  }
  if (!rl.allowed) return authError("Too many requests -- please try again later.", 429, cors);

  try {
    const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
      // Never trust the client's claim that a version exists/is current — it must be a real,
      // currently published policy on the server's own record.
      const match = findPublishedPolicy(appData.policyVersions, policyType, version);
      if (!match) return { error: { message: "That policy version is not currently published", status: 400 } };

      const acceptances = { ...(appData.policyAcceptances || {}) };
      const mine = { ...(acceptances[auth.uid] || {}) };
      mine[policyType] = { version, timestamp: nowTs() };
      acceptances[auth.uid] = mine;
      appData.policyAcceptances = acceptances;
      appendAudit(appData, { uid: auth.uid, role: auth.role, action: "policy_accepted", detail: { policyType, version } });
      return { appData, result: { ok: true } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/policy/accept error:", e && e.stack ? e.stack : e);
    return authError("Could not record policy acceptance", 500, cors);
  }
}

// POST /privacy/preferences -- upsert the caller's own preference toggles. Only whitelisted
// keys (PRIVACY_PREFERENCE_KEYS) are ever accepted; "essential" can never be turned off since
// it is required for the app to function at all.
async function handlePrivacyPreferences(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const submitted = body && typeof body.preferences === "object" && body.preferences ? body.preferences : {};

  const rl = await checkAndReserveRateLimit(env, "privacy_preferences", auth.uid, MAX_PRIVACY_WRITES_PER_WINDOW, PRIVACY_WRITE_WINDOW_MS);
  if (rl.misconfigured) {
    console.error("privacy/preferences rate limiting is misconfigured: RATE_LIMIT_KV binding is missing.");
    return authError("Privacy actions are temporarily unavailable -- please try again shortly.", 503, cors);
  }
  if (!rl.allowed) return authError("Too many requests -- please try again later.", 429, cors);

  try {
    const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
      const preferences = { ...(appData.privacyPreferences || {}) };
      const next = { essential: true }; // always on, never client-controlled
      for (const key of PRIVACY_PREFERENCE_KEYS) {
        if (key === "essential") continue;
        if (typeof submitted[key] === "boolean") next[key] = submitted[key];
      }
      preferences[auth.uid] = next;
      appData.privacyPreferences = preferences;
      appendAudit(appData, { uid: auth.uid, role: auth.role, action: "preferences_updated", detail: next });
      return { appData, result: { ok: true, preferences: next } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/preferences error:", e && e.stack ? e.stack : e);
    return authError("Could not save preferences", 500, cors);
  }
}

/** Shared create-a-privacy-request logic used by both /privacy/request and /privacy/delete
 * (deletion is just a request with a fixed category — see handlePrivacyDelete's comment for why
 * this deliberately does NOT delete anything itself). */
async function createPrivacyRequest(env, auth, category, description) {
  const rl = await checkAndReserveRateLimit(env, "request_create", auth.uid, MAX_REQUESTS_PER_WINDOW, REQUEST_WINDOW_MS);
  if (rl.misconfigured) {
    // See HARDENING ISSUE #3: a missing RATE_LIMIT_KV binding must never silently mean
    // "unlimited privacy requests" -- fail closed with a controlled, non-leaky error instead.
    console.error("privacy/request rate limiting is misconfigured: RATE_LIMIT_KV binding is missing.");
    return { error: { message: "Privacy requests are temporarily unavailable -- please try again shortly.", status: 503 } };
  }
  if (!rl.allowed) return { error: { message: "Too many requests -- please try again later.", status: 429 } };

  const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
    const currentPolicy = latestPublishedPolicy(appData.policyVersions, "privacy_policy");

    const record = {
      id: genId("req"),
      uid: auth.uid,
      category,
      description,
      status: "requested",
      submittedAt: nowTs(),
      updatedAt: nowTs(),
      adminNotes: "",
      resolvedAt: null,
      policyVersion: currentPolicy ? currentPolicy.version : null,
    };
    appData.privacyRequests = [record, ...(appData.privacyRequests || [])];
    appendAudit(appData, { uid: auth.uid, role: auth.role, action: "privacy_request_created", detail: { id: record.id, category } });
    return { appData, result: { record } };
  });
  if (outcome.error) return outcome;
  return outcome.result;
}

// POST /privacy/request -- create an access/correction/complaint/etc. request.
async function handlePrivacyRequestCreate(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const category = sanitizeText(body?.category, 40);
  const description = sanitizeText(body?.description, MAX_DESCRIPTION_LENGTH);
  if (!PRIVACY_REQUEST_CATEGORIES.includes(category)) return authError("Invalid category", 400, cors);
  if (!isNonEmptyString(description)) return authError("Description is required", 400, cors);

  try {
    const result = await createPrivacyRequest(env, auth, category, description);
    if (result.error) return authError(result.error.message, result.error.status, cors);
    return jsonResponse({ data: { ok: true, request: result.record } }, 200, cors);
  } catch (e) {
    console.error("privacy/request error:", e && e.stack ? e.stack : e);
    return authError("Could not submit request", 500, cors);
  }
}

// POST /privacy/delete -- creates an auditable DELETION REQUEST. This intentionally does NOT
// delete any data itself: per the task brief, deletion must be reviewable, not instant-on-click.
// The actual destructive operation an admin performs after approving the request is the
// EXISTING account-deletion path (setUserPin's "delete" op in lib/userPin.js / handleSetUserPin
// above), which already revokes sessions, deletes the Firebase Auth user, and removes the
// user's records — reused rather than reimplemented. This endpoint's job is only to create the
// auditable trail and confirm intent; an admin marks the request "completed" (via
// /privacy/request/status) once they've actually performed that existing deletion.
async function handlePrivacyDelete(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  if (body?.confirm !== true) {
    return authError("Deletion requires explicit confirmation", 400, cors);
  }
  const description = sanitizeText(body?.description, MAX_DESCRIPTION_LENGTH) || "Account deletion requested by user.";

  try {
    const result = await createPrivacyRequest(env, auth, "deletion", description);
    if (result.error) return authError(result.error.message, result.error.status, cors);
    return jsonResponse({ data: { ok: true, request: result.record } }, 200, cors);
  } catch (e) {
    console.error("privacy/delete error:", e && e.stack ? e.stack : e);
    return authError("Could not submit deletion request", 500, cors);
  }
}

// POST /privacy/request/status -- admin/superadmin only: update status + notes on ANY request.
async function handlePrivacyRequestStatus(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);
  if (!isFullAccessRole(auth.role)) return authError("Not authorized", 403, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const requestId = sanitizeText(body?.requestId, 100);
  const status = sanitizeText(body?.status, 40);
  const adminNotes = sanitizeText(body?.adminNotes, MAX_NOTE_LENGTH);
  if (!isNonEmptyString(requestId)) return authError("requestId is required", 400, cors);

  try {
    const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
      const requests = Array.isArray(appData.privacyRequests) ? appData.privacyRequests : [];
      const idx = requests.findIndex((r) => r.id === requestId);
      if (idx === -1) return { error: { message: "Request not found", status: 404 } };
      const existing = requests[idx];

      if (!isValidStatusTransition(existing.status, status)) {
        return { error: { message: `Cannot move request from "${existing.status}" to "${status}"`, status: 400 } };
      }

      const terminal = ["completed", "rejected", "partially_completed"].includes(status);
      const updated = {
        ...existing,
        status,
        adminNotes: adminNotes || existing.adminNotes,
        updatedAt: nowTs(),
        resolvedAt: terminal ? nowTs() : existing.resolvedAt,
      };
      const nextRequests = [...requests];
      nextRequests[idx] = updated;
      appData.privacyRequests = nextRequests;
      appendAudit(appData, {
        uid: auth.uid,
        role: auth.role,
        action: "privacy_request_status_changed",
        detail: { id: requestId, from: existing.status, to: status, targetUid: existing.uid },
      });
      return { appData, result: { ok: true, request: updated } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/request/status error:", e && e.stack ? e.stack : e);
    return authError("Could not update request", 500, cors);
  }
}

// POST /privacy/policy/publish -- admin/superadmin only: create or update a policy-version
// METADATA entry (type/version/effectiveDate/status). The actual policy TEXT is static content
// shipped in index.html (POLICY_CONTENT), not stored here or editable via this endpoint — see
// the Known Limitations section of the final report for why, and what would be needed to make
// policy text itself admin-editable. This endpoint only lets an admin mark a given version
// number "published" (so consent/acceptance can reference it) or "draft" (admin preview only).
async function handlePolicyPublish(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);
  if (!isFullAccessRole(auth.role)) return authError("Not authorized", 403, cors);

  const read = await readBodyOrRespond(request, MAX_PRIVACY_BODY_BYTES, cors);
  if (read.error) return read.error;
  const body = read.value;
  const type = sanitizeText(body?.type, 60);
  const version = sanitizeText(body?.version, 40);
  const effectiveDate = sanitizeText(body?.effectiveDate, 20);
  const status = body?.status === "draft" ? "draft" : "published";
  if (!POLICY_TYPES.includes(type) || !isNonEmptyString(version) || !isNonEmptyString(effectiveDate)) {
    return authError("type, version, and effectiveDate are required", 400, cors);
  }

  try {
    const outcome = await runPrivacyMutation(env, auth, async ({ appData }) => {
      const versions = Array.isArray(appData.policyVersions) ? [...appData.policyVersions] : [];
      const idx = versions.findIndex((p) => p.type === type && p.version === version);
      const entry = { type, version, effectiveDate, status };
      if (idx === -1) versions.unshift(entry);
      else versions[idx] = entry;
      appData.policyVersions = versions;
      appendAudit(appData, { uid: auth.uid, role: auth.role, action: "policy_published", detail: entry });
      return { appData, result: { ok: true, policyVersions: versions } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/policy/publish error:", e && e.stack ? e.stack : e);
    return authError("Could not publish policy version", 500, cors);
  }
}

// POST /privacy/export -- returns the caller's OWN data as structured JSON. Rate-limited
// because building this payload is more expensive than a normal read and must not become a DoS
// vector (see task brief, section 26).
async function handlePrivacyExport(request, env, cors) {
  const auth = await authenticateRequest(request, env);
  if (auth.error) return authError(auth.error.message, auth.error.status, cors);

  try {
    const rl = await checkAndReserveRateLimit(env, "export", auth.uid, MAX_EXPORTS_PER_WINDOW, EXPORT_WINDOW_MS);
    if (rl.misconfigured) {
      // See HARDENING ISSUE #3 -- export is the most expensive privacy endpoint (full authorized
      // view + audit write), so it's the last place a fail-open rate limiter should exist.
      console.error("privacy/export rate limiting is misconfigured: RATE_LIMIT_KV binding is missing.");
      return authError("Data export is temporarily unavailable -- please try again shortly.", 503, cors);
    }
    if (!rl.allowed) return authError("Too many export requests -- please try again later.", 429, cors);

    const outcome = await runPrivacyMutation(env, auth, async ({ appData, me }) => {
      // Reuse buildAuthorizedView so the export can never contain more than the caller could
      // already legitimately read via /data/get -- one authorization surface, not two.
      const view = buildAuthorizedView(appData, { uid: auth.uid, role: auth.role, linkedId: me.linkedId || null });

      const exportPayload = {
        exportedAt: new Date().toISOString(),
        account: { id: me.id, username: me.username, role: me.role, linkedId: me.linkedId || null },
        profile: view.profiles?.[auth.uid] || null,
        preferences: view.privacyPreferences?.[auth.uid] || null,
        consents: view.privacyConsents?.[auth.uid] || [],
        policyAcceptances: view.policyAcceptances?.[auth.uid] || {},
        privacyRequests: getUserRequests(view.privacyRequests, auth.uid),
        ownActivityLog: (view.activityLog || []).filter((a) => a.user === me.username || a.uid === auth.uid),
        ownRecords: view.perUser?.[auth.uid] || null,
      };

      appendAudit(appData, { uid: auth.uid, role: auth.role, action: "data_exported", detail: null });
      return { appData, result: { export: exportPayload } };
    });
    if (outcome.error) return authError(outcome.error.message, outcome.error.status, cors);
    return jsonResponse({ data: outcome.result }, 200, cors);
  } catch (e) {
    console.error("privacy/export error:", e && e.stack ? e.stack : e);
    return authError("Could not export data", 500, cors);
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
      case "/privacy/consent":
        return handlePrivacyConsent(request, env, cors);
      case "/privacy/policy/accept":
        return handlePolicyAccept(request, env, cors);
      case "/privacy/preferences":
        return handlePrivacyPreferences(request, env, cors);
      case "/privacy/policy/publish":
        return handlePolicyPublish(request, env, cors);
      case "/privacy/request":
        return handlePrivacyRequestCreate(request, env, cors);
      case "/privacy/request/status":
        return handlePrivacyRequestStatus(request, env, cors);
      case "/privacy/delete":
        return handlePrivacyDelete(request, env, cors);
      case "/privacy/export":
        return handlePrivacyExport(request, env, cors);
      default:
        return authError("Not found", 404, cors);
    }
  },
};
