// ============================================================================================
// Integration tests for the Part-B privacy endpoints: /privacy/consent, /privacy/policy/accept,
// /privacy/policy/publish, /privacy/preferences, /privacy/request, /privacy/request/status,
// /privacy/delete, /privacy/export.
//
// Uses the same in-memory Firestore + Firebase-Auth-JWKS fake harness as worker.integration.test.js
// (duplicated here rather than imported, matching that file's own self-contained convention) so
// these exercise the REAL login-worker.js code, not a reimplementation.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import worker from "../login-worker.js";
import { KNOWN_CONSENT_CATEGORIES } from "../lib/privacy.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

// This file's pre-existing tests use /privacy/consent with type:"t1"/purpose:"p1" purely as a
// vehicle to test unrelated things (grant/withdraw round-tripping, forged-identity rejection) --
// not to test the allow-list itself (see privacy-consent-allowlist.test.js for that). Since
// production ships KNOWN_CONSENT_CATEGORIES empty (see lib/privacy.js), register exactly the one
// synthetic pair this file's tests need so they keep exercising what they were actually written
// to exercise, without silently reintroducing "any string is accepted".
KNOWN_CONSENT_CATEGORIES.push({ type: "t1", purpose: "p1" });

const PROJECT_ID = "money-metrix-9f1da";
let kidCounter = 0;
function nextKid() {
  kidCounter += 1;
  return `svc-kid-${kidCounter}`;
}

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function generateSecuretokenKeyPair() {
  const kid = nextKid();
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

async function signIdToken(privateKey, uid, claimsOverride = {}, kid) {
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
    ...claimsOverride,
  };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

function encodeFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "number") return { integerValue: String(value) };
  if (typeof value === "boolean") return { booleanValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(encodeFirestoreValue) } };
  if (typeof value === "object") return { mapValue: { fields: encodeFirestoreFields(value) } };
}
function encodeFirestoreFields(obj) {
  const fields = {};
  for (const k of Object.keys(obj || {})) fields[k] = encodeFirestoreValue(obj[k]);
  return fields;
}

function makeFakeKv() {
  const store = new Map();
  return {
    async get(key, type) {
      const v = store.get(key);
      if (v === undefined) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(key, value) {
      store.set(key, value);
    },
    _store: store,
  };
}

function makeEnv({ users = [], kv = makeFakeKv() } = {}) {
  const state = {
    appData: {
      users, profiles: {}, settings: {}, permissions: {}, customSections: [], userPermissions: {},
      shared: {}, perUser: {}, activityLog: [],
      privacyConsents: {}, policyVersions: [], policyAcceptances: {}, privacyPreferences: {},
      privacyRequests: [], privacyAuditLog: [],
    },
    credentials: {},
  };
  return {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@money-metrix-9f1da.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: PRIVATE_KEY_PEM,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: kv,
    __state: state,
  };
}

function installFakeFetch(env, jwk) {
  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    let body = null;
    if (init?.body) {
      try { body = JSON.parse(init.body); } catch (e) { body = null; }
    }
    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-access-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(env.__state.appData) }) }), { status: 200 });
      }
      if (method === "PATCH") {
        env.__state.appData = JSON.parse(body.fields.json.stringValue);
        return new Response(JSON.stringify({}), { status: 200 });
      }
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/meta")) {
      return new Response(JSON.stringify({}), { status: 200 });
    }
    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };
}

function req(path, { body, headers = {} } = {}) {
  return new Request(`https://worker.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// A dummy RSA keypair just so makeEnv has something PEM-shaped; these tests never exercise the
// service-account signing path against a real Google endpoint (it's mocked above).
import { generateKeyPairSync } from "node:crypto";
const { privateKey: PRIVATE_KEY_PEM } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

async function setupUser(env, jwt, { uid, role = "user" }) {
  env.__state.appData.users.push({ id: uid, username: uid, role, linkedId: null });
}

// ---------------------------------------------------------------------------------------------

test("privacy endpoints reject requests with no Authorization header", async () => {
  const env = makeEnv();
  const { publicJwk } = await generateSecuretokenKeyPair();
  installFakeFetch(env, publicJwk);
  for (const path of ["/privacy/consent", "/privacy/preferences", "/privacy/request", "/privacy/delete", "/privacy/export"]) {
    const resp = await worker.fetch(req(path, { body: {} }), env, {});
    assert.equal(resp.status, 401, `${path} should require auth`);
  }
});

test("consent: grant then withdraw round-trips and is audited under the caller's real uid", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const grant = await worker.fetch(req("/privacy/consent", { body: { type: "t1", purpose: "p1", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(grant.status, 200);
  assert.equal(env.__state.appData.privacyConsents.alice.length, 1);
  assert.equal(env.__state.appData.privacyConsents.alice[0].status, "granted");
  assert.equal(env.__state.appData.privacyAuditLog[0].uid, "alice");

  const withdraw = await worker.fetch(req("/privacy/consent", { body: { type: "t1", purpose: "p1", action: "withdraw" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(withdraw.status, 200);
  assert.equal(env.__state.appData.privacyConsents.alice[0].status, "withdrawn");
});

test("policy accept: rejects a version the server has not published, even if the client claims it exists", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/policy/accept", { body: { policyType: "privacy_policy", version: "9.9-forged" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 400);
  assert.deepEqual(env.__state.appData.policyAcceptances, {});
});

test("policy publish: admin-only, and a published version becomes acceptable", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "boss", username: "boss", role: "admin", linkedId: null },
    ],
  });
  installFakeFetch(env, publicJwk);
  const userToken = await signIdToken(privateKey, "alice", { role: "user" }, kid);
  const adminToken = await signIdToken(privateKey, "boss", { role: "admin" }, kid);

  const deniedPublish = await worker.fetch(req("/privacy/policy/publish", { body: { type: "privacy_policy", version: "1.0", effectiveDate: "2026-01-01" }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(deniedPublish.status, 403, "a plain user must not be able to publish policy versions");

  const publish = await worker.fetch(req("/privacy/policy/publish", { body: { type: "privacy_policy", version: "1.0", effectiveDate: "2026-01-01" }, headers: { Authorization: `Bearer ${adminToken}` } }), env, {});
  assert.equal(publish.status, 200);

  const accept = await worker.fetch(req("/privacy/policy/accept", { body: { policyType: "privacy_policy", version: "1.0" }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(accept.status, 200);
  assert.equal(env.__state.appData.policyAcceptances.alice.privacy_policy.version, "1.0");
});

test("preferences: essential is always true regardless of what the client submits", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/preferences", { body: { preferences: { essential: false, unknownKey: true } }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.data.preferences.essential, true, "essential must not be client-controllable");
  assert.equal(body.data.preferences.unknownKey, undefined, "unrecognized preference keys must be dropped");
});

test("privacy request: User A cannot see or act on User B's request (IDOR check)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
      { id: "boss", username: "boss", role: "admin", linkedId: null },
    ],
  });
  installFakeFetch(env, publicJwk);
  const aliceToken = await signIdToken(privateKey, "alice", {}, kid);
  const bobToken = await signIdToken(privateKey, "bob", {}, kid);
  const adminToken = await signIdToken(privateKey, "boss", { role: "admin" }, kid);

  const create = await worker.fetch(req("/privacy/request", { body: { category: "access", description: "please show my data" }, headers: { Authorization: `Bearer ${aliceToken}` } }), env, {});
  assert.equal(create.status, 200);
  const { data } = await create.json();
  const requestId = data.request.id;
  assert.equal(data.request.uid, "alice");

  // Bob (not admin) tries to change alice's request status -- must be rejected as not authorized.
  const bobAttempt = await worker.fetch(req("/privacy/request/status", { body: { requestId, status: "approved" }, headers: { Authorization: `Bearer ${bobToken}` } }), env, {});
  assert.equal(bobAttempt.status, 403);

  // Forged/unknown request id -- must 404, not silently succeed.
  const forgedId = await worker.fetch(req("/privacy/request/status", { body: { requestId: "does-not-exist", status: "approved" }, headers: { Authorization: `Bearer ${adminToken}` } }), env, {});
  assert.equal(forgedId.status, 404);

  // Admin legitimately updates status.
  const adminUpdate = await worker.fetch(req("/privacy/request/status", { body: { requestId, status: "approved", adminNotes: "looks fine" }, headers: { Authorization: `Bearer ${adminToken}` } }), env, {});
  assert.equal(adminUpdate.status, 200);
  assert.equal(env.__state.appData.privacyRequests[0].status, "approved");

  // Once terminal, further transitions are rejected -- verify by moving it to a terminal state
  // and then attempting another change.
  await worker.fetch(req("/privacy/request/status", { body: { requestId, status: "completed" }, headers: { Authorization: `Bearer ${adminToken}` } }), env, {});
  const afterTerminal = await worker.fetch(req("/privacy/request/status", { body: { requestId, status: "under_review" }, headers: { Authorization: `Bearer ${adminToken}` } }), env, {});
  assert.equal(afterTerminal.status, 400, "a terminal request status must not be reopened");
});

test("privacy request creation is rate-limited", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  let lastStatus = 200;
  for (let i = 0; i < 12; i++) {
    const resp = await worker.fetch(req("/privacy/request", { body: { category: "other", description: `req ${i}` }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
    lastStatus = resp.status;
  }
  assert.equal(lastStatus, 429, "the 12th request in the same window should be rate-limited");
});

test("delete: creates an auditable request but does NOT delete anything itself", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const noConfirm = await worker.fetch(req("/privacy/delete", { body: { confirm: false }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(noConfirm.status, 400, "must require explicit confirm:true");

  const resp = await worker.fetch(req("/privacy/delete", { body: { confirm: true }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 200);
  assert.equal(env.__state.appData.users.length, 1, "the user account must still exist -- this only records a request");
  assert.equal(env.__state.appData.privacyRequests[0].category, "deletion");
  assert.equal(env.__state.appData.privacyRequests[0].status, "requested");
});

test("export: returns only the caller's own data, never another user's", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
  });
  env.__state.appData.privacyRequests = [
    { id: "r1", uid: "alice", category: "access", status: "requested" },
    { id: "r2", uid: "bob", category: "access", status: "requested" },
  ];
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/export", { headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 200);
  const { data } = await resp.json();
  assert.equal(data.export.account.id, "alice");
  assert.equal(data.export.privacyRequests.length, 1);
  assert.equal(data.export.privacyRequests[0].uid, "alice");
});

// ---------------------------------------------------------------------------------------------
// HARDENING ISSUE #3 (integration level): a missing RATE_LIMIT_KV binding must fail CLOSED for
// the privacy endpoints that rely on it, never silently behave as if rate limiting were active
// and unlimited. See cloudflare-worker/tests/privacy-rate-limit.test.js for the underlying
// checkAndReserveRateLimit unit tests (all 5 required scenarios); these confirm the same fix is
// actually wired up end-to-end through the real HTTP handlers.
// ---------------------------------------------------------------------------------------------

test("HARDENING #3: /privacy/request fails closed (503) when RATE_LIMIT_KV is missing, and never records the request", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  delete env.RATE_LIMIT_KV; // the exact misconfiguration the hardening brief describes
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/request", { body: { category: "access", description: "please show my data" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 503, "must fail closed with a controlled error, not silently succeed unlimited");
  assert.equal((env.__state.appData.privacyRequests || []).length, 0, "no request should have been recorded");
});

test("HARDENING #3: /privacy/delete fails closed (503) when RATE_LIMIT_KV is missing", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  delete env.RATE_LIMIT_KV;
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/delete", { body: { confirm: true }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 503);
  assert.equal((env.__state.appData.privacyRequests || []).length, 0);
});

test("HARDENING #3: /privacy/export fails closed (503) when RATE_LIMIT_KV is missing, and does not export data", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  delete env.RATE_LIMIT_KV;
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(req("/privacy/export", { headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(resp.status, 503);
});

test("HARDENING #3: with RATE_LIMIT_KV present, /privacy/request and /privacy/export behave exactly as before (regression guard)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const create = await worker.fetch(req("/privacy/request", { body: { category: "access", description: "hello" }, headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(create.status, 200);
  const exp = await worker.fetch(req("/privacy/export", { headers: { Authorization: `Bearer ${idToken}` } }), env, {});
  assert.equal(exp.status, 200);
});

// ---------------------------------------------------------------------------------------------
// Section 6 recheck: identity must always come from the verified token, never from anything
// client-supplied in the body -- forged uid/userId/ownerId/role fields must be inert.
// ---------------------------------------------------------------------------------------------

test("ADVERSARIAL: a forged uid/userId/ownerId/role in the body cannot redirect a consent write to another user", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
  });
  installFakeFetch(env, publicJwk);
  const aliceToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(
    req("/privacy/consent", {
      body: { type: "t1", purpose: "p1", action: "grant", uid: "bob", userId: "bob", ownerId: "bob", role: "superadmin" },
      headers: { Authorization: `Bearer ${aliceToken}` },
    }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.equal(env.__state.appData.privacyConsents.bob, undefined, "bob must not have received a consent record he never granted");
  assert.equal(env.__state.appData.privacyConsents.alice.length, 1, "the write must have landed under alice's real, token-derived uid");
  assert.equal(env.__state.appData.privacyAuditLog[0].uid, "alice", "the audit entry must record the real caller, not the forged uid");
  assert.equal(env.__state.appData.privacyAuditLog[0].actorRole, "user", "the forged role:\"superadmin\" in the body must be ignored");
});

test("ADVERSARIAL: a non-admin cannot create a deletion request for another user by forging uid in the body", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
  });
  installFakeFetch(env, publicJwk);
  const aliceToken = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(
    req("/privacy/delete", { body: { confirm: true, uid: "bob", userId: "bob" }, headers: { Authorization: `Bearer ${aliceToken}` } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.equal(env.__state.appData.privacyRequests[0].uid, "alice", "the deletion request must be recorded under the real caller, not the forged target");
});

test("ADVERSARIAL: a plain user's forged role:\"admin\" in the body cannot authorize /privacy/policy/publish or /privacy/request/status", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  // The token itself carries role:"user" -- claiming role:"admin" only in the JSON body must not help.
  const aliceToken = await signIdToken(privateKey, "alice", { role: "user" }, kid);

  const publish = await worker.fetch(
    req("/privacy/policy/publish", { body: { type: "privacy_policy", version: "9.0", effectiveDate: "2026-01-01", role: "admin" }, headers: { Authorization: `Bearer ${aliceToken}` } }),
    env,
    {}
  );
  assert.equal(publish.status, 403);

  const status = await worker.fetch(
    req("/privacy/request/status", { body: { requestId: "whatever", status: "approved", role: "superadmin" }, headers: { Authorization: `Bearer ${aliceToken}` } }),
    env,
    {}
  );
  assert.equal(status.status, 403);
});

// ---------------------------------------------------------------------------------------------
// PHASE 5 AUDIT ITEM #12: /privacy/consent, /privacy/policy/accept, and /privacy/preferences
// previously had NO rate limiting at all (disclosed as a known gap in
// PART-B-HARDENING-REPORT.md §14). They now go through the same checkAndReserveRateLimit
// fail-closed mechanism as /privacy/request and /privacy/export (see MAX_PRIVACY_WRITES_PER_WINDOW
// / PRIVACY_WRITE_WINDOW_MS in lib/privacy.js). These tests prove both halves: the endpoints
// actually enforce a cap, and a missing RATE_LIMIT_KV binding fails closed (503), never silently
// unlimited.
// ---------------------------------------------------------------------------------------------

test("PHASE 5 #12: /privacy/preferences is rate-limited (previously unlimited)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  let lastStatus = 200;
  for (let i = 0; i < 65; i++) {
    const resp = await worker.fetch(
      req("/privacy/preferences", { body: { preferences: { essential: true } }, headers: { Authorization: `Bearer ${idToken}` } }),
      env, {}
    );
    lastStatus = resp.status;
  }
  assert.equal(lastStatus, 429, "requests beyond the cap in the same window must be rejected");
});

test("PHASE 5 #12: /privacy/consent is rate-limited (previously unlimited)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  let lastStatus = 200;
  for (let i = 0; i < 65; i++) {
    const action = i % 2 === 0 ? "grant" : "withdraw";
    const resp = await worker.fetch(
      req("/privacy/consent", { body: { type: "t1", purpose: "p1", action }, headers: { Authorization: `Bearer ${idToken}` } }),
      env, {}
    );
    lastStatus = resp.status;
  }
  assert.equal(lastStatus, 429, "requests beyond the cap in the same window must be rejected");
});

test("PHASE 5 #12: /privacy/policy/accept is rate-limited (previously unlimited)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  env.__state.appData.policyVersions = [{ type: "privacy_policy", version: "1.0", status: "published", effectiveDate: "2026-01-01" }];
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  let lastStatus = 200;
  for (let i = 0; i < 65; i++) {
    const resp = await worker.fetch(
      req("/privacy/policy/accept", { body: { policyType: "privacy_policy", version: "1.0" }, headers: { Authorization: `Bearer ${idToken}` } }),
      env, {}
    );
    lastStatus = resp.status;
  }
  assert.equal(lastStatus, 429, "requests beyond the cap in the same window must be rejected");
});

test("PHASE 5 #12: all three newly-limited endpoints fail CLOSED (503) when RATE_LIMIT_KV is missing", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  delete env.RATE_LIMIT_KV;
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const consent = await worker.fetch(
    req("/privacy/consent", { body: { type: "t1", purpose: "p1", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(consent.status, 503, "/privacy/consent must fail closed, not silently unlimited");
  assert.equal(Object.keys(env.__state.appData.privacyConsents || {}).length, 0, "no consent should have been recorded");

  const prefs = await worker.fetch(
    req("/privacy/preferences", { body: { preferences: { essential: true } }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(prefs.status, 503, "/privacy/preferences must fail closed, not silently unlimited");
  assert.equal(Object.keys(env.__state.appData.privacyPreferences || {}).length, 0, "no preferences should have been recorded");

  const accept = await worker.fetch(
    req("/privacy/policy/accept", { body: { policyType: "privacy_policy", version: "1.0" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(accept.status, 503, "/privacy/policy/accept must fail closed, not silently unlimited");
});

test("PHASE 5 #12: with RATE_LIMIT_KV present, the three newly-limited endpoints still work exactly as before (regression guard)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "alice", username: "alice", role: "user", linkedId: null }] });
  env.__state.appData.policyVersions = [{ type: "privacy_policy", version: "1.0", status: "published", effectiveDate: "2026-01-01" }];
  installFakeFetch(env, publicJwk);
  const idToken = await signIdToken(privateKey, "alice", {}, kid);

  const consent = await worker.fetch(
    req("/privacy/consent", { body: { type: "t1", purpose: "p1", action: "grant" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(consent.status, 200);

  const prefs = await worker.fetch(
    req("/privacy/preferences", { body: { preferences: { essential: true } }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(prefs.status, 200);

  const accept = await worker.fetch(
    req("/privacy/policy/accept", { body: { policyType: "privacy_policy", version: "1.0" }, headers: { Authorization: `Bearer ${idToken}` } }),
    env, {}
  );
  assert.equal(accept.status, 200);
});
