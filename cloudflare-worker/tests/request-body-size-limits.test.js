// ============================================================================================
// PHASE 8 HARDENING ITEM #5 -- request body size limits.
//
// Before this phase, every handler called `await request.json()` directly with no ceiling at
// all -- not even a Content-Length check -- so an oversized body was fully buffered and
// JSON.parse'd before any of a handler's own field-level validation got a chance to reject it,
// reachable pre-auth via POST /login. This proves readJsonBody/readBodyOrRespond actually reject
// oversized bodies (both via a declared Content-Length AND via the streamed byte count, so a
// missing/understated Content-Length can't bypass the limit) with a generic 413, while leaving
// legitimately small payloads unaffected.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto, generateKeyPairSync } from "node:crypto";
import { encodeFirestoreFields } from "../lib/googleFirestore.js";
import worker from "../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const PROJECT_ID = "money-metrix-9f1da";

function makeBasicEnv() {
  return {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    }).privateKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: { async get() { return null; }, async put() {} },
  };
}

test("POST /login: a body far over the 2KB limit is rejected 413, declared via Content-Length, without ever being parsed", async () => {
  const env = makeBasicEnv();
  let firestoreOrIdentityCallCount = 0;
  globalThis.fetch = async (url) => {
    // /login is unauthenticated and reads no Firestore doc before validating the body, so a
    // correctly-implemented size check must reject before ANY outbound call happens.
    firestoreOrIdentityCallCount += 1;
    throw new Error(`Should not have made any outbound call: ${url}`);
  };

  const oversized = JSON.stringify({ username: "alice", pin: "1234", junk: "x".repeat(10_000) });
  const resp = await worker.fetch(
    new Request("https://worker.example/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io" },
      body: oversized,
    }),
    env, {}
  );
  assert.equal(resp.status, 413);
  const body = await resp.json();
  assert.equal(body.error.message, "Payload too large");
  assert.equal(firestoreOrIdentityCallCount, 0, "must reject before touching any backend at all");
});

test("POST /login: a streamed body with NO declared Content-Length is still capped by actual bytes read", async () => {
  const env = makeBasicEnv();
  globalThis.fetch = async () => { throw new Error("Should not have made any outbound call"); };

  // A ReadableStream body has no automatically-computed Content-Length in the fetch spec, so
  // this exercises the byte-counting-while-reading path, not the header fast-path.
  const chunk = new TextEncoder().encode("x".repeat(1024));
  const stream = new ReadableStream({
    start(controller) {
      // 4 * 1024 bytes of padding alone already exceeds the 2KB login limit.
      for (let i = 0; i < 4; i++) controller.enqueue(chunk);
      controller.close();
    },
  });

  const resp = await worker.fetch(
    new Request("https://worker.example/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io" },
      body: stream,
      duplex: "half",
    }),
    env, {}
  );
  assert.equal(resp.status, 413);
});

test("POST /login: a normal, small, well-formed body is completely unaffected", async () => {
  const env = makeBasicEnv();
  globalThis.fetch = async (url) => {
    const u = typeof url === "string" ? url : url.url;
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/appData")) {
      return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify({ users: [] }) }) }), { status: 200 });
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/credentials")) {
      return new Response(JSON.stringify({ fields: {} }), { status: 200 });
    }
    throw new Error(`Unmocked fetch: ${u}`);
  };

  const resp = await worker.fetch(
    new Request("https://worker.example/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io" },
      body: JSON.stringify({ username: "ghost", pin: "1234" }),
    }),
    env, {}
  );
  // Unknown user -> 401 "Invalid username or PIN", NOT 413/400 -- proves the size check let a
  // normal small payload through untouched and normal validation ran as before.
  assert.equal(resp.status, 401);
});

test("POST /data/save: an authenticated request with an oversized body is rejected 413 before any Firestore read", async () => {
  const env = makeBasicEnv();
  const kid = "test-kid-bodysize";
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = kid; publicJwk.alg = "RS256"; publicJwk.use = "sig";

  function b64url(bytes) {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlJson(obj) { return b64url(new TextEncoder().encode(JSON.stringify(obj))); }
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid, typ: "JWT" };
  const payload = { iss: `https://securetoken.google.com/${PROJECT_ID}`, aud: PROJECT_ID, sub: "alice", iat: now, exp: now + 3600, auth_time: now, approved: true, role: "user" };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, new TextEncoder().encode(signingInput));
  const idToken = `${signingInput}.${b64url(new Uint8Array(sig))}`;

  let firestoreReadCount = 0;
  globalThis.fetch = async (url) => {
    const u = typeof url === "string" ? url : url.url;
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
    }
    // authenticateRequest only needs the JWK above -- it never touches Firestore. Any call past
    // that point (getGoogleAccessToken / readAppDataWithVersion) means the size check did NOT
    // reject before starting real work.
    firestoreReadCount += 1;
    throw new Error(`Unexpected call past auth: ${u}`);
  };

  const oversized = JSON.stringify({ json: JSON.stringify({ padding: "x".repeat(4 * 1024 * 1024) }) }); // > 3MB cap
  const resp = await worker.fetch(
    new Request("https://worker.example/data/save", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${idToken}` },
      body: oversized,
    }),
    env, {}
  );
  assert.equal(resp.status, 413);
  assert.equal(firestoreReadCount, 0, "must reject before any Firestore access, not just before the write");
});
