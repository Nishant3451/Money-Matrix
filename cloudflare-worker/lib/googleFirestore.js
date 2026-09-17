// ============================================================================================
// Google OAuth2 (service-account JWT-bearer flow) + Firestore REST helpers.
//
// Extracted, byte-for-byte, from the existing login-worker.js (no logic changed) so that the
// new /data/get, /data/save, and /user/setPin endpoints reuse exactly the same code path the
// already-working login endpoint uses, rather than a second, slightly-different implementation.
// login-worker.js now imports from here instead of defining these locally.
// ============================================================================================

const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const OAUTH_SCOPE =
  "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit";

let cachedAccessToken = null; // { token, expiresAt }

export function base64UrlFromBytes(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlFromString(str) {
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

export async function importServiceAccountKey(pemPrivateKey) {
  const der = pemToDer(pemPrivateKey);
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

export async function signJwtRS256(header, payload, key) {
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

export async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function decodeFirestoreValue(value) {
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
export function decodeFirestoreFields(fields) {
  const out = {};
  for (const key of Object.keys(fields || {})) out[key] = decodeFirestoreValue(fields[key]);
  return out;
}

/** Encodes a plain JS value into a Firestore REST "Value" object. Only the shapes this app
 * actually writes are handled (string/number/boolean/null/object/array — appData only ever
 * stores a single string `json` field and meta only ever stores a string/int timestamp). */
export function encodeFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "number") return Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  if (typeof value === "boolean") return { booleanValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(encodeFirestoreValue) } };
  if (typeof value === "object") return { mapValue: { fields: encodeFirestoreFields(value) } };
  throw new Error(`Cannot encode Firestore value of type ${typeof value}`);
}
export function encodeFirestoreFields(obj) {
  const fields = {};
  for (const key of Object.keys(obj || {})) fields[key] = encodeFirestoreValue(obj[key]);
  return fields;
}

export async function getGoogleAccessToken(env) {
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

export function firestoreDocUrl(env, docPath) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${docPath}`;
}

export async function firestoreGetDoc(env, accessToken, docPath) {
  const resp = await fetch(firestoreDocUrl(env, docPath), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (resp.status === 404) return {}; // doc doesn't exist yet — same as snap.exists === false
  if (!resp.ok) throw new Error(`Firestore read failed for ${docPath} (${resp.status})`);
  const json = await resp.json();
  return decodeFirestoreFields(json.fields || {});
}

/** Same read as firestoreGetDoc, but also returns Firestore's own `updateTime` string for the
 * document (or null if it doesn't exist yet). This is what makes optimistic-concurrency writes
 * possible — see writeAppDataIfUnchanged below — without needing a real Firestore transaction. */
export async function firestoreGetDocWithMeta(env, accessToken, docPath) {
  const resp = await fetch(firestoreDocUrl(env, docPath), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (resp.status === 404) return { fields: {}, updateTime: null, exists: false };
  if (!resp.ok) throw new Error(`Firestore read failed for ${docPath} (${resp.status})`);
  const json = await resp.json();
  return { fields: decodeFirestoreFields(json.fields || {}), updateTime: json.updateTime || null, exists: true };
}

/** PATCHes (creates-or-replaces) the given fields on a document, without touching any other
 * top-level fields already on that document (Firestore's `updateMask` semantics). */
export async function firestorePatchDoc(env, accessToken, docPath, fields) {
  const fieldPaths = Object.keys(fields);
  const mask = fieldPaths.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
  const url = `${firestoreDocUrl(env, docPath)}?${mask}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: encodeFirestoreFields(fields) }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(`Firestore write failed for ${docPath} (${resp.status}): ${JSON.stringify(err)}`);
  }
  return resp.json();
}

// Mirrors readAppData() in the (now-nonexistent) original functions/index.js: the whole app
// state lives in one string field called `json` on moneymatrix/appData, not as top-level
// document fields.
export async function readAppData(env, accessToken) {
  const doc = await firestoreGetDoc(env, accessToken, "moneymatrix/appData");
  try {
    return JSON.parse(doc.json || "{}");
  } catch (e) {
    return {};
  }
}

export async function writeAppData(env, accessToken, data) {
  return firestorePatchDoc(env, accessToken, "moneymatrix/appData", { json: JSON.stringify(data) });
}

/** Same read as readAppData, but also returns the document's `updateTime` so a caller can later
 * write back conditionally on nothing else having changed it in the meantime (see
 * writeAppDataIfUnchanged). Used by the /privacy/* handlers' optimistic-concurrency retry loop —
 * see HARDENING ISSUE #4 in PART-B-HARDENING-REPORT.md for why this exists and what it does and
 * does not solve. */
export async function readAppDataWithVersion(env, accessToken) {
  const { fields, updateTime } = await firestoreGetDocWithMeta(env, accessToken, "moneymatrix/appData");
  let data;
  try {
    data = JSON.parse(fields.json || "{}");
  } catch (e) {
    data = {};
  }
  return { data, updateTime };
}

/** Conditionally writes moneymatrix/appData: the write is only applied if the document's
 * updateTime on the server still matches `expectedUpdateTime` (Firestore's REST
 * `currentDocument.updateTime` precondition — https://cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/patch).
 * If the document changed since it was read (another request wrote in between), Firestore
 * rejects the write with 409/FAILED_PRECONDITION and we return `{ conflict: true }` instead of
 * throwing, so the caller can re-read and retry rather than silently losing the other write's
 * changes (a lost-update race — see HARDENING ISSUE #4).
 *
 * If `expectedUpdateTime` is null (document didn't exist on our read), we instead require
 * `currentDocument.exists = false` so two concurrent "create" writes can't stomp each other
 * either. */
export async function writeAppDataIfUnchanged(env, accessToken, data, expectedUpdateTime) {
  const fieldPaths = ["json"];
  const mask = fieldPaths.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
  const precondition = expectedUpdateTime
    ? `currentDocument.updateTime=${encodeURIComponent(expectedUpdateTime)}`
    : `currentDocument.exists=false`;
  const url = `${firestoreDocUrl(env, "moneymatrix/appData")}?${mask}&${precondition}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(data) }) }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    // Google's REST error model maps a failed `currentDocument` precondition (our optimistic
    // -concurrency check) to status "FAILED_PRECONDITION" (HTTP 400) or, on some paths,
    // "ABORTED" (HTTP 409). Both mean exactly one thing: the document changed since we read it
    // -- the safe response is "re-read and retry", not "give up" or "treat as success". Any
    // OTHER error (malformed request, auth failure, etc.) is a real error and must NOT be
    // silently retried as if it were a conflict, or a genuine bug could loop forever.
    const status = err?.error?.status;
    if (status === "FAILED_PRECONDITION" || status === "ABORTED") {
      return { conflict: true };
    }
    throw new Error(`Firestore write failed for moneymatrix/appData (${resp.status}): ${JSON.stringify(err)}`);
  }
  return { conflict: false };
}

/** Bumps the tiny, non-sensitive meta timestamp doc the frontend's onSnapshot listener watches
 * (see firestore.rules — clients may READ this doc directly once approved, but never write it;
 * only server-side code with service-account credentials writes it). */
export async function bumpMeta(env, accessToken) {
  return firestorePatchDoc(env, accessToken, "moneymatrix/meta", { updatedAt: Date.now() });
}

/** Deletes specific top-level field(s) from a document via Firestore REST's updateMask
 * semantics: a field named in updateMask but absent from the request body is deleted. Used by
 * setUserPin's delete-user path to remove one user's entry from moneymatrix/credentials without
 * touching any other user's entry. */
export async function firestoreDeleteFields(env, accessToken, docPath, fieldPaths) {
  const mask = fieldPaths.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
  const url = `${firestoreDocUrl(env, docPath)}?${mask}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: {} }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(`Firestore field-delete failed for ${docPath} (${resp.status}): ${JSON.stringify(err)}`);
  }
  return resp.json();
}

export async function readCredentials(env, accessToken) {
  return firestoreGetDoc(env, accessToken, "moneymatrix/credentials");
}

export async function writeCredentials(env, accessToken, credentialsDoc) {
  return firestorePatchDoc(env, accessToken, "moneymatrix/credentials", credentialsDoc);
}
