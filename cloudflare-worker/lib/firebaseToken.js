// ============================================================================================
// Firebase ID TOKEN verification (NOT the custom token minted by the login worker — a Firebase
// ID token is what signInWithCustomToken() gives the client afterwards, and it's what every
// protected data endpoint must receive as `Authorization: Bearer <ID token>`).
//
// Verifies, per Google's documented procedure for verifying ID tokens without the Admin SDK:
//   1. Header alg is RS256 and kid matches one of Google's currently published public keys.
//   2. Signature verifies against that key.
//   3. `exp` is in the future, `iat` is in the past (small clock-skew allowance).
//   4. `aud` == your Firebase project ID.
//   5. `iss` == https://securetoken.google.com/<project ID>.
//   6. `sub` is non-empty (this is the Firebase uid).
// https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
//
// Keys come from Google's JWK-format endpoint for the securetoken service account (the same
// keys also exist as X.509 certs at a different URL, but those require ASN.1 extraction to get
// an importable SPKI key out of the certificate — the JWK endpoint hands back an already
// WebCrypto-importable key, which is more robust in a Workers isolate with no ASN.1 library):
//   https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
// Cached per-isolate the same way login-worker.js caches its OAuth2 access token.
// ============================================================================================

const JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

let cachedJwks = null; // { keysByKid: {kid: JsonWebKey}, expiresAt }

async function getGoogleJwks(fetchImpl = fetch, { forceRefresh = false } = {}) {
  const now = Date.now();
  if (!forceRefresh && cachedJwks && cachedJwks.expiresAt > now) return cachedJwks.keysByKid;
  const resp = await fetchImpl(JWKS_URL);
  if (!resp.ok) throw new Error(`Failed to fetch Google JWKS (${resp.status})`);
  const json = await resp.json();
  const keysByKid = {};
  for (const jwk of json.keys || []) keysByKid[jwk.kid] = jwk;
  const cacheControl = resp.headers.get("cache-control") || "";
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const maxAgeMs = maxAgeMatch ? Number(maxAgeMatch[1]) * 1000 : 5 * 60 * 1000;
  cachedJwks = { keysByKid, expiresAt: now + maxAgeMs };
  return keysByKid;
}

function base64UrlToBytes(b64url) {
  const b64 = b64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), "=");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlToJson(b64url) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(b64url)));
}

async function importGoogleJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/**
 * Verifies a Firebase ID token. Throws with a short, generic reason on any failure — callers
 * should map any thrown error to a 401 and never surface the specific reason to the client.
 *
 * @returns {{uid: string, claims: object}} on success — `claims` is the full decoded payload,
 *          including the `approved`/`role` custom claims set by the login worker.
 */
export async function verifyFirebaseIdToken(idToken, projectId, fetchImpl = fetch) {
  if (!idToken || typeof idToken !== "string" || idToken.split(".").length !== 3) {
    throw new Error("malformed token");
  }
  const [headerB64, payloadB64, sigB64] = idToken.split(".");
  const header = base64UrlToJson(headerB64);
  const payload = base64UrlToJson(payloadB64);

  if (header.alg !== "RS256") throw new Error("unexpected alg");
  if (!header.kid) throw new Error("missing kid");

  const jwks = await getGoogleJwks(fetchImpl);
  let jwk = jwks[header.kid];
  if (!jwk) {
    // Cached key set doesn't have this kid — could be genuine key rotation happening within
    // our cache window (Google rotates on its own schedule; our cache just respects the
    // max-age it publishes). Try one uncached fetch before giving up, same as jwks-rsa /
    // the Admin SDK's own JWKS client do for exactly this reason.
    const fresh = await getGoogleJwks(fetchImpl, { forceRefresh: true });
    jwk = fresh[header.kid];
  }
  if (!jwk) throw new Error("unknown signing key");

  const key = await importGoogleJwk(jwk);
  const signingInput = `${headerB64}.${payloadB64}`;
  const valid = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    base64UrlToBytes(sigB64),
    new TextEncoder().encode(signingInput)
  );
  if (!valid) throw new Error("bad signature");

  const now = Math.floor(Date.now() / 1000);
  const CLOCK_SKEW_SECONDS = 60;
  if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SECONDS < now) throw new Error("expired");
  if (typeof payload.iat !== "number" || payload.iat - CLOCK_SKEW_SECONDS > now) throw new Error("not yet valid");
  if (payload.aud !== projectId) throw new Error("bad audience");
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error("bad issuer");
  if (!payload.sub || typeof payload.sub !== "string") throw new Error("missing sub");
  if (payload.auth_time && payload.auth_time - CLOCK_SKEW_SECONDS > now) throw new Error("auth_time in future");

  return { uid: payload.sub, claims: payload };
}

export const __testing__ = { getGoogleJwks, importGoogleJwk, base64UrlToJson };
