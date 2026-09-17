// ============================================================================================
// HARDENING CORRECTION #2 -- Consent API integrity, Layer 2.
//
// Full-HTTP tests against the real POST /privacy/consent handler in login-worker.js. This file
// first proves the handler rejects an unregistered category (production behavior, since
// KNOWN_CONSENT_CATEGORIES ships empty -- see lib/privacy.js), then registers ONE synthetic
// category into that same exported (mutable) array to exercise grant/withdraw/ownership/audit
// end-to-end -- simulating what happens once a genuine optional category is eventually added to
// the application. This module-scope mutation is local to this file's own process (Node's test
// runner isolates each test file into its own process) and never touches production, which
// continues to ship with the array empty (see privacy-consent-allowlist.test.js Layer 1).
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { KNOWN_CONSENT_CATEGORIES } from "../lib/privacy.js";
import { encodeFirestoreFields } from "../lib/googleFirestore.js";
import worker from "../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const TEST_CATEGORY = { type: "product_updates_email", purpose: "occasional feature-announcement email" };

test("before registration: granting ANY consent is rejected (400) -- proves 'reject rather than invent' is what's actually shipped", async () => {
  assert.equal(KNOWN_CONSENT_CATEGORIES.length, 0, "must start empty, matching production");
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { type: "anything_at_all", purpose: "anything at all", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 400);
  assert.equal((env.__state.appData.privacyConsents || {}).alice, undefined, "no consent record should have been created for an unknown category");
});

// From here on, register the one synthetic category the rest of this file needs. Done inside a
// test() body (not bare module-scope code) so it executes in Node test-runner EXECUTION order,
// after the "before registration" test above has already run and asserted the empty state --
// module-scope statements all run during file loading, before any test body, which would
// otherwise silently corrupt that assertion regardless of source-line order.
test("(setup) register a synthetic known category for the remaining tests in this file", () => {
  KNOWN_CONSENT_CATEGORIES.push(TEST_CATEGORY);
  assert.equal(KNOWN_CONSENT_CATEGORIES.length, 1);
});

test("normal grant: a request matching a known category succeeds and is recorded under the caller's real uid", async () => {
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { ...TEST_CATEGORY, action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  const mine = env.__state.appData.privacyConsents.alice;
  assert.equal(mine.length, 1);
  assert.equal(mine[0].type, TEST_CATEGORY.type);
  assert.equal(mine[0].purpose, TEST_CATEGORY.purpose);
  assert.equal(mine[0].status, "granted");
});

test("normal withdrawal: withdrawing a previously granted known-category consent succeeds", async () => {
  const { env, idToken } = await makeAuthedEnv();
  await worker.fetch(req("/privacy/consent", { body: { ...TEST_CATEGORY, action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  const withdraw = await worker.fetch(
    req("/privacy/consent", { body: { ...TEST_CATEGORY, action: "withdraw" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(withdraw.status, 200);
  const mine = env.__state.appData.privacyConsents.alice;
  assert.equal(mine[mine.length - 1].status, "withdrawn");
});

test("unknown consent type: a type not on the allow-list is rejected even with a real, otherwise-valid purpose", async () => {
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { type: "sms_marketing", purpose: TEST_CATEGORY.purpose, action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 400);
});

test("unknown purpose: a known type paired with a purpose it doesn't actually have is rejected", async () => {
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { type: TEST_CATEGORY.type, purpose: "selling your data to a data broker", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 400);
});

test("forged arbitrary category: a caller cannot invent a brand-new category by simply sending a new string", async () => {
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { type: "totally_made_up_category", purpose: "totally made up purpose", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 400);
  assert.equal((env.__state.appData.privacyConsents || {}).alice, undefined);
});

test("ownership: a granted consent is recorded under the token-derived uid, never a body-supplied uid", async () => {
  const { env, idToken } = await makeAuthedEnv();
  const resp = await worker.fetch(
    req("/privacy/consent", { body: { ...TEST_CATEGORY, action: "grant", uid: "someone-else", userId: "someone-else" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.equal(env.__state.appData.privacyConsents["someone-else"], undefined);
  assert.equal(env.__state.appData.privacyConsents.alice.length, 1);
});

test("audit logging: a successful grant writes an audit entry with the real actor uid/role and the category", async () => {
  const { env, idToken } = await makeAuthedEnv();
  await worker.fetch(req("/privacy/consent", { body: { ...TEST_CATEGORY, action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  const entry = env.__state.appData.privacyAuditLog[0];
  assert.equal(entry.uid, "alice");
  assert.equal(entry.action, "consent_grant");
  assert.equal(entry.detail.type, TEST_CATEGORY.type);
  assert.equal(entry.detail.purpose, TEST_CATEGORY.purpose);
});

test("audit logging: a rejected (unknown-category) attempt does NOT write an audit entry", async () => {
  const { env, idToken } = await makeAuthedEnv();
  await worker.fetch(req("/privacy/consent", { body: { type: "made_up", purpose: "made_up", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal((env.__state.appData.privacyAuditLog || []).length, 0);
});

// ---------------------------------------------------------------------------------------------
// Test harness (self-contained, same technique as the other integration test files)
// ---------------------------------------------------------------------------------------------

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}
let kidCounter = 0;
async function generateSecuretokenKeyPair() {
  kidCounter += 1;
  const kid = `known-cat-kid-${kidCounter}`;
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = kid;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  return { privateKey: keyPair.privateKey, publicJwk, kid };
}
async function signIdToken(privateKey, uid, PROJECT_ID, kid) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid, typ: "JWT" };
  const payload = {
    iss: `https://securetoken.google.com/${PROJECT_ID}`,
    aud: PROJECT_ID,
    sub: uid,
    iat: now,
    exp: now + 3600,
    auth_time: now,
    approved: true,
    role: "user",
  };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}
function req(path, { body, headers } = {}) {
  return new Request(`https://worker.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", ...(headers || {}) },
    body: JSON.stringify(body || {}),
  });
}
function makeFakeKv() {
  const store = new Map();
  return {
    async get(key, type) {
      const v = store.get(key);
      if (v === undefined) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
  };
}
async function makeAuthedEnv() {
  const PROJECT_ID = "money-metrix-9f1da";
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey: svcKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const state = {
    appData: {
      users: [{ id: "alice", username: "alice", role: "user", linkedId: null }],
      privacyConsents: {}, policyVersions: [], policyAcceptances: {}, privacyPreferences: {},
      privacyRequests: [], privacyAuditLog: [],
    },
    version: "v0",
  };
  let versionCounter = 0;
  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: svcKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: makeFakeKv(),
    __state: state,
  };
  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
    }
    if (u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(state.appData) }), updateTime: state.version }), { status: 200 });
      }
      if (method === "PATCH") {
        const body = JSON.parse(init.body);
        state.appData = JSON.parse(body.fields.json.stringValue);
        versionCounter += 1;
        state.version = `v${versionCounter}`;
        return new Response(JSON.stringify({ updateTime: state.version }), { status: 200 });
      }
    }
    if (u.includes("moneymatrix/meta")) return new Response(JSON.stringify({}), { status: 200 });
    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };
  const idToken = await signIdToken(privateKey, "alice", PROJECT_ID, kid);
  return { env, idToken };
}
