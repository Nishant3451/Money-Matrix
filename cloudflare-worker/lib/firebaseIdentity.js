// ============================================================================================
// Firebase custom-token minting + custom-claims persistence — admin-only operations the Admin
// SDK normally does locally / via Identity Toolkit. Done here by hand since there is no Admin
// SDK available outside a Node process. Extracted from login-worker.js, unchanged, so the new
// /user/setPin endpoint (which can change a user's role, and therefore their claims) reuses the
// exact same code path as the working login flow.
// ============================================================================================

import { importServiceAccountKey, signJwtRS256 } from "./googleFirestore.js";

const CUSTOM_TOKEN_AUDIENCE =
  "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

export async function mintFirebaseCustomToken(env, uid, claims) {
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

// Mirrors setClaimsEnsuringUserExists() in the (now-nonexistent) original functions/index.js:
// sets custom claims on the Identity Platform user record so they survive the client's
// automatic hourly token refresh (a one-time custom token's claims do NOT). Creates the Auth
// user record first if this is genuinely their first-ever login.
export async function setClaimsEnsuringUserExists(env, accessToken, uid, claims) {
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
    // uid may already exist despite the race above (two first-logins/creations at once) —
    // that's fine, fall through to the retry below either way.
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

/** Deletes an Identity Platform (Firebase Auth) user record — used by setUserPin's delete path. */
export async function deleteAuthUser(env, accessToken, uid) {
  const base = `https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}`;
  const resp = await fetch(`${base}/accounts:delete`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: uid }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    // Already gone is fine — deleting a user that never had an Auth record (e.g. never logged
    // in) shouldn't block the rest of the delete operation.
    const isNotFound = err?.error?.message?.includes("USER_NOT_FOUND");
    if (!isNotFound) throw new Error(`accounts:delete failed (${resp.status}): ${JSON.stringify(err)}`);
  }
}

// Revokes all previously-issued refresh tokens for a user by bumping their `validSince` claim —
// this is the same mechanism the Firebase Admin SDK's auth().revokeRefreshTokens(uid) uses under
// the hood (there is no separate "revoke" endpoint; validSince IS the mechanism). Called after a
// PIN change so a device that still has the OLD PIN's session can't keep refreshing indefinitely.
//
// HONEST LIMITATION (disclosed, not hidden): this stops the refresh token from minting any NEW
// ID token after this point. It does NOT invalidate an ID token that was already issued and
// hasn't expired yet (ID tokens are self-contained/stateless and normally last up to 1 hour) —
// doing that would require this Worker to call accounts:lookup and compare validSince on every
// single authenticated request (an extra network round-trip per request), which is a real
// cost/latency trade-off, not a free win. This implementation does NOT do that extra check, so
// treat "revoked" here as "can't get a new session," not "every existing session dies instantly."
// If near-instant revocation genuinely matters for your threat model, that per-request lookup
// (or shortening the ID token lifetime) is the next step — not implemented here.
export async function revokeRefreshTokens(env, accessToken, uid) {
  const base = `https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}`;
  const resp = await fetch(`${base}/accounts:update`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: uid, validSince: String(Math.floor(Date.now() / 1000)) }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    const isNotFound = err?.error?.message?.includes("USER_NOT_FOUND");
    // Not-found here just means this account has never actually logged in yet (no Auth record
    // to revoke) — nothing to do, not a real failure.
    if (!isNotFound) throw new Error(`accounts:update (validSince) failed (${resp.status}): ${JSON.stringify(err)}`);
  }
}
