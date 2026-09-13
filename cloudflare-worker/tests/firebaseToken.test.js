import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { verifyFirebaseIdToken } from "../lib/firebaseToken.js";

// Node's webcrypto is the same SubtleCrypto interface Workers exposes as global `crypto`.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const PROJECT_ID = "money-metrix-9f1da";
const KID = "test-kid-1";

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function generateKeyPairAndJwk() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  return { privateKey: keyPair.privateKey, publicJwk };
}

async function signToken(privateKey, payloadOverrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid: KID, typ: "JWT" };
  const payload = {
    iss: `https://securetoken.google.com/${PROJECT_ID}`,
    aud: PROJECT_ID,
    sub: "user123",
    iat: now,
    exp: now + 3600,
    auth_time: now,
    approved: true,
    role: "user",
    ...payloadOverrides,
  };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

function fakeFetch(jwks) {
  return async () =>
    new Response(JSON.stringify({ keys: [jwks] }), { status: 200, headers: { "cache-control": "max-age=3600" } });
}

test("a validly-signed, well-formed ID token verifies and returns uid+claims", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const token = await signToken(privateKey);
  const result = await verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(publicJwk));
  assert.equal(result.uid, "user123");
  assert.equal(result.claims.role, "user");
  assert.equal(result.claims.approved, true);
});

test("a token signed with a DIFFERENT key is rejected", async () => {
  const { publicJwk } = await generateKeyPairAndJwk(); // published key
  const { privateKey: wrongKey } = await generateKeyPairAndJwk(); // attacker's own key
  const token = await signToken(wrongKey); // signed with the wrong key, but claims kid=test-kid-1
  await assert.rejects(() => verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(publicJwk)));
});

test("an expired token is rejected", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const now = Math.floor(Date.now() / 1000);
  const token = await signToken(privateKey, { exp: now - 1000, iat: now - 2000 });
  await assert.rejects(() => verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(publicJwk)));
});

test("wrong audience (different Firebase project) is rejected", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const token = await signToken(privateKey, { aud: "some-other-project" });
  await assert.rejects(() => verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(publicJwk)));
});

test("wrong issuer is rejected", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const token = await signToken(privateKey, { iss: "https://securetoken.google.com/some-other-project" });
  await assert.rejects(() => verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(publicJwk)));
});

test("a token that has been tampered with (payload changed after signing) is rejected", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const token = await signToken(privateKey);
  const [h, p, s] = token.split(".");
  const tamperedPayload = b64urlJson({ ...JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()), role: "superadmin" });
  const tamperedToken = `${h}.${tamperedPayload}.${s}`;
  await assert.rejects(() => verifyFirebaseIdToken(tamperedToken, PROJECT_ID, fakeFetch(publicJwk)));
});

test("malformed token (not 3 dot-separated parts) is rejected", async () => {
  await assert.rejects(() => verifyFirebaseIdToken("not.a.valid.jwt.at.all", PROJECT_ID, fakeFetch({})));
  await assert.rejects(() => verifyFirebaseIdToken("", PROJECT_ID, fakeFetch({})));
});

test("unknown kid (not in the published key set) is rejected", async () => {
  const { privateKey, publicJwk } = await generateKeyPairAndJwk();
  const token = await signToken(privateKey);
  const emptyKeySet = { ...publicJwk, kid: "some-other-kid" };
  await assert.rejects(() => verifyFirebaseIdToken(token, PROJECT_ID, fakeFetch(emptyKeySet)));
});
