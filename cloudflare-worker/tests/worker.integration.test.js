import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, webcrypto } from "node:crypto";
import worker from "../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const PROJECT_ID = "money-metrix-9f1da";
let kidCounter = 0;
function nextKid() {
  kidCounter += 1;
  return `svc-kid-${kidCounter}`;
}

// ---------------------------------------------------------------------------------------------
// Test fixtures: a real RSA keypair standing in for the Firebase service account, and a second
// one standing in for Google's securetoken signing key (what Google actually controls — we
// serve its public half back from our fake JWKS endpoint so the real verifyFirebaseIdToken code
// path runs unmodified).
// ---------------------------------------------------------------------------------------------

const serviceAccount = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

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

// ---------------------------------------------------------------------------------------------
// Fake backing stores + fetch dispatcher. Every URL the real code calls is intercepted here;
// nothing in this file talks to the real internet.
// ---------------------------------------------------------------------------------------------

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

function makeEnv({ users = [], credentials = {}, jwk, kv = makeFakeKv() } = {}) {
  const state = {
    appData: { users, profiles: {}, settings: {}, permissions: {}, customSections: [], userPermissions: {}, shared: {}, perUser: {}, activityLog: [] },
    credentials,
    identityCalls: [], // { path, body } for every accounts:* call, so tests can assert on them
  };
  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@money-metrix-9f1da.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: serviceAccount.privateKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: kv,
    __state: state,
  };
  return env;
}

function installFakeFetch(env, jwk) {
  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    let body = null;
    if (init?.body) {
      try {
        body = JSON.parse(init.body);
      } catch (e) {
        body = null; // form-urlencoded (the OAuth2 token exchange) or similar — not needed by any mock branch below
      }
    }

    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-access-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { "cache-control": "max-age=3600" } });
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(env.__state.appData) }) }), { status: 200 });
      }
      if (method === "PATCH") {
        const jsonField = body.fields.json.stringValue;
        env.__state.appData = JSON.parse(jsonField);
        return new Response(JSON.stringify({}), { status: 200 });
      }
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/credentials")) {
      if (method === "GET") {
        return new Response(JSON.stringify({ fields: encodeFirestoreFields(env.__state.credentials) }), { status: 200 });
      }
      if (method === "PATCH") {
        // Merge patched fields (updateMask semantics: only named fields change; a field named
        // in the mask but absent from the body is DELETED — same as production Firestore).
        const maskMatch = u.match(/updateMask\.fieldPaths=([^&]+)/g) || [];
        const maskFields = maskMatch.map((m) => decodeURIComponent(m.split("=")[1]));
        for (const f of maskFields) {
          if (body.fields && f in body.fields) {
            env.__state.credentials[f] = decodeFirestoreValueForTest(body.fields[f]);
          } else {
            delete env.__state.credentials[f];
          }
        }
        return new Response(JSON.stringify({}), { status: 200 });
      }
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/meta")) {
      return new Response(JSON.stringify({}), { status: 200 });
    }
    if (u.includes("identitytoolkit.googleapis.com")) {
      const path = u.split("/").pop();
      env.__state.identityCalls.push({ path, body });
      if (path === "accounts:signUp") {
        // Faithfully reproduce the REAL Google behavior this whole fix is about: this
        // client-facing, API-key method 404s when called with only an OAuth2 bearer token and
        // no API key. If a regression ever reintroduces a call to this path, this mock makes
        // the test fail with the SAME error production showed, instead of silently succeeding.
        return new Response("{}", { status: 404 });
      }
      if (path === "accounts:update") {
        if (body.localId && !(env.__state.__knownAuthUsers && env.__state.__knownAuthUsers.has(body.localId))) {
          return new Response(JSON.stringify({ error: { message: "There is no user record corresponding to this identifier. USER_NOT_FOUND" } }), { status: 400 });
        }
        return new Response(JSON.stringify({}), { status: 200 });
      }
      if (path === "accounts") {
        // The CORRECT admin/OAuth2 user-creation endpoint (POST {base}/accounts, no ":signUp").
        env.__state.__knownAuthUsers = env.__state.__knownAuthUsers || new Set();
        env.__state.__knownAuthUsers.add(body.localId);
        return new Response(JSON.stringify({}), { status: 200 });
      }
      if (path === "accounts:delete") {
        return new Response(JSON.stringify({}), { status: 200 });
      }
    }
    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };
}

function decodeFirestoreValueForTest(v) {
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("mapValue" in v) {
    const out = {};
    for (const k of Object.keys(v.mapValue.fields || {})) out[k] = decodeFirestoreValueForTest(v.mapValue.fields[k]);
    return out;
  }
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(decodeFirestoreValueForTest);
  return null;
}

function req(path, { method = "POST", body, headers = {} } = {}) {
  return new Request(`https://worker.example${path}`, {
    method,
    headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// A known-good bcrypt hash for PIN "1234" at the app's configured rounds, precomputed once so
// tests don't waste time re-hashing (bcrypt is deliberately slow).
import bcrypt from "bcryptjs";
let HASH_1234;
test.before(async () => {
  HASH_1234 = await bcrypt.hash("1234", 10);
});

// ---------------------------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------------------------

test("login: valid username/PIN succeeds, returns a custom token, and does NOT call accounts:signUp (the broken endpoint) for an existing Auth user", async () => {
  const env = makeEnv({
    users: [{ id: "alice", username: "alice", role: "user", linkedId: null }],
    credentials: { alice: { pinHash: HASH_1234, role: "user" } },
  });
  env.__state.__knownAuthUsers = new Set(["alice"]); // Auth record already exists
  installFakeFetch(env);

  const resp = await worker.fetch(req("/login", { body: { username: "alice", pin: "1234" } }), env, {});
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.user.username, "alice");
  assert.ok(body.token, "should return a custom token");

  const signUpCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:signUp");
  assert.equal(signUpCalls.length, 0, "must NEVER call the broken accounts:signUp endpoint");
  const createCalls = env.__state.identityCalls.filter((c) => c.path === "accounts");
  assert.equal(createCalls.length, 0, "must not call the create endpoint at all when the Auth user already exists");
  const updateCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:update");
  assert.ok(updateCalls.length >= 1, "must still persist claims via accounts:update");
});

test("login: a genuinely brand-new Auth user is created via the CORRECT endpoint (plain `accounts`, not `accounts:signUp`) exactly once", async () => {
  const env = makeEnv({
    users: [{ id: "brandnew", username: "brandnew", role: "user", linkedId: null }],
    credentials: { brandnew: { pinHash: HASH_1234, role: "user" } },
  });
  env.__state.__knownAuthUsers = new Set(); // explicitly: no Auth record exists yet for anyone
  installFakeFetch(env);

  const resp = await worker.fetch(req("/login", { body: { username: "brandnew", pin: "1234" } }), env, {});
  assert.equal(resp.status, 200);
  const signUpCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:signUp");
  assert.equal(signUpCalls.length, 0, "must never call the broken accounts:signUp endpoint");
  const createCalls = env.__state.identityCalls.filter((c) => c.path === "accounts");
  assert.equal(createCalls.length, 1, "first-ever login for a new account should create the Auth record exactly once, via the correct endpoint");
});

test("login: wrong PIN is rejected with a generic message", async () => {
  const env = makeEnv({
    users: [{ id: "alice", username: "alice", role: "user" }],
    credentials: { alice: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env);
  const resp = await worker.fetch(req("/login", { body: { username: "alice", pin: "0000" } }), env, {});
  assert.equal(resp.status, 401);
  const body = await resp.json();
  assert.equal(body.error.message, "Invalid username or PIN");
});

test("login: unknown username is rejected with the SAME generic message (no user enumeration)", async () => {
  const env = makeEnv({ users: [], credentials: {} });
  installFakeFetch(env);
  const resp = await worker.fetch(req("/login", { body: { username: "ghost", pin: "1234" } }), env, {});
  assert.equal(resp.status, 401);
  const body = await resp.json();
  assert.equal(body.error.message, "Invalid username or PIN");
});

test("login: rate limiting locks after 5 failed attempts for the same username", async () => {
  const env = makeEnv({
    users: [{ id: "alice", username: "alice", role: "user" }],
    credentials: { alice: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env);
  let last;
  for (let i = 0; i < 5; i++) {
    last = await worker.fetch(req("/login", { body: { username: "alice", pin: "wrong" } }), env, {});
  }
  assert.equal(last.status, 401); // 5th attempt still just "invalid"
  const sixth = await worker.fetch(req("/login", { body: { username: "alice", pin: "wrong" } }), env, {});
  assert.equal(sixth.status, 429);
  const body = await sixth.json();
  assert.match(body.error.message, /Too many attempts/);
});

// ---------------------------------------------------------------------------------------------
// /data/get, /data/save — authenticated with a REAL signed ID token
// ---------------------------------------------------------------------------------------------

test("data/get: unauthenticated request is rejected", async () => {
  const env = makeEnv();
  installFakeFetch(env);
  const resp = await worker.fetch(req("/data/get"), env, {});
  assert.equal(resp.status, 401);
});

test("data/get: invalid/garbage token is rejected", async () => {
  const env = makeEnv();
  installFakeFetch(env);
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: "Bearer not-a-real-token" } }), env, {});
  assert.equal(resp.status, 401);
});

test("data/get: authorized user gets their downline-scoped view, not the full dataset", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sup_a", username: "sup_a", role: "user", linkedId: "supA" },
      { id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" },
    ],
  });
  env.__state.appData.shared = {
    supervisors: [{ id: "supA" }, { id: "supB" }],
    members: [{ id: "m1", supervisorId: "supA" }, { id: "m2", supervisorId: "supB" }],
    coaches: [],
    transactions: [],
    gifts: [],
  };
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sup_a", {}, kid);

  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${token}` } }), env, {});
  assert.equal(resp.status, 200);
  const { data } = await resp.json();
  const view = JSON.parse(data.json);
  assert.deepEqual(view.shared.members.map((m) => m.id), ["m1"], "must only see their own downline, not sup_b's");
});

test("data/save: an unauthorized (unapproved) token is rejected", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "u1", username: "u1", role: "user" }] });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "u1", { approved: false }, kid);
  const resp = await worker.fetch(req("/data/save", { headers: { Authorization: `Bearer ${token}` }, body: { json: "{}" } }), env, {});
  assert.equal(resp.status, 403);
});

test("data/save: a scoped user's forged `users` role-escalation is dropped, but their in-scope edit persists", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" },
    ],
  });
  env.__state.appData.shared = {
    supervisors: [{ id: "supB" }],
    members: [{ id: "m2", supervisorId: "supB", name: "Original" }],
    coaches: [], transactions: [], gifts: [],
  };
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sup_b", {}, kid);

  const submitted = JSON.parse(JSON.stringify(env.__state.appData));
  submitted.users[0].role = "superadmin"; // forged escalation attempt
  submitted.shared.members[0].name = "Edited"; // legitimate in-scope edit

  const resp = await worker.fetch(req("/data/save", { headers: { Authorization: `Bearer ${token}` }, body: { json: JSON.stringify(submitted) } }), env, {});
  assert.equal(resp.status, 200);
  assert.equal(env.__state.appData.users[0].role, "user", "role escalation must not persist");
  assert.equal(env.__state.appData.shared.members[0].name, "Edited", "in-scope edit must persist");
});

test("data/save + data/get: a scoped user's own isolated clients round-trip end-to-end through the real HTTP handlers", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" }],
  });
  env.__state.appData.shared = { supervisors: [{ id: "supB" }], members: [], coaches: [], transactions: [], gifts: [], clients: [] };
  env.__state.appData.perUser = { sup_b: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] } };
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sup_b", {}, kid);

  const submitted = JSON.parse(JSON.stringify(env.__state.appData));
  submitted.perUser.sup_b.clients.push({ id: "c1", name: "Rahul Patel", phone: "9876543210" });

  const saveResp = await worker.fetch(req("/data/save", { headers: { Authorization: `Bearer ${token}` }, body: { json: JSON.stringify(submitted) } }), env, {});
  assert.equal(saveResp.status, 200);
  assert.deepEqual(env.__state.appData.perUser.sup_b.clients, [{ id: "c1", name: "Rahul Patel", phone: "9876543210" }], "client persisted server-side");

  const getResp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${token}` } }), env, {});
  assert.equal(getResp.status, 200);
  const { data } = await getResp.json();
  const view = JSON.parse(data.json);
  assert.deepEqual(view.perUser.sup_b.clients, [{ id: "c1", name: "Rahul Patel", phone: "9876543210" }], "client comes back on the next data/get");
});

test("data/save: a scoped user cannot write into another user's perUser clients via the real HTTP handler", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sup_a", username: "sup_a", role: "user", linkedId: "supA" },
      { id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" },
    ],
  });
  env.__state.appData.shared = { supervisors: [{ id: "supA" }, { id: "supB" }], members: [], coaches: [], transactions: [], gifts: [], clients: [] };
  env.__state.appData.perUser = {
    sup_a: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] },
    sup_b: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] },
  };
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sup_b", {}, kid);

  const submitted = JSON.parse(JSON.stringify(env.__state.appData));
  submitted.perUser.sup_a.clients.push({ id: "hacked", name: "Sneaky" }); // someone else's bucket

  const resp = await worker.fetch(req("/data/save", { headers: { Authorization: `Bearer ${token}` }, body: { json: JSON.stringify(submitted) } }), env, {});
  assert.equal(resp.status, 200);
  assert.deepEqual(env.__state.appData.perUser.sup_a.clients, [], "sup_a's clients bucket must remain untouched by sup_b's save");
});

// ---------------------------------------------------------------------------------------------
// /user/setPin — including session revocation
// ---------------------------------------------------------------------------------------------

test("setPin: self-service PIN change succeeds with correct currentPin, stores only a hash, and revokes refresh tokens", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "alice", username: "alice", role: "user" }],
    credentials: { alice: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "alice", {}, kid);

  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "alice", currentPin: "1234", newPin: "5678" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.notEqual(env.__state.credentials.alice.pinHash, "5678", "plaintext PIN must never be stored");
  assert.ok(env.__state.credentials.alice.pinHash.startsWith("$2"), "must be a bcrypt hash");
  const revokeCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:update" && c.body.validSince);
  assert.equal(revokeCalls.length, 1, "self PIN change must revoke refresh tokens exactly once");
  assert.equal(revokeCalls[0].body.localId, "alice");
});

test("setPin: self-service change with WRONG currentPin is rejected and does not revoke anything", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "alice", username: "alice", role: "user" }],
    credentials: { alice: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "alice", {}, kid);
  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "alice", currentPin: "0000", newPin: "5678" } }),
    env,
    {}
  );
  assert.equal(resp.status, 401);
  assert.equal(env.__state.credentials.alice.pinHash, HASH_1234, "PIN must not change");
  const revokeCalls = env.__state.identityCalls.filter((c) => c.body?.validSince);
  assert.equal(revokeCalls.length, 0);
});

test("setPin: a plain user cannot reset someone else's PIN", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "alice", username: "alice", role: "user" },
      { id: "bob", username: "bob", role: "user" },
    ],
    credentials: { alice: { pinHash: HASH_1234, role: "user" }, bob: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "alice", {}, kid);
  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "bob", newPin: "9999" } }),
    env,
    {}
  );
  assert.equal(resp.status, 403);
  assert.equal(env.__state.credentials.bob.pinHash, HASH_1234);
});

test("setPin: admin reset of an existing user's PIN succeeds and also revokes tokens", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "admin1", username: "admin1", role: "admin" },
      { id: "bob", username: "bob", role: "user" },
    ],
    credentials: { admin1: { pinHash: HASH_1234, role: "admin" }, bob: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "admin1", { role: "admin" }, kid);
  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "bob", newPin: "4321" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.notEqual(env.__state.credentials.bob.pinHash, HASH_1234);
  const revokeCalls = env.__state.identityCalls.filter((c) => c.body?.validSince && c.body.localId === "bob");
  assert.equal(revokeCalls.length, 1);
});

// The following tests were added specifically to cover the accounts:signUp -> 404 production
// bug: any existing-Auth-user PIN update reaches setClaimsEnsuringUserExists' accounts:update
// call, which for a genuinely-already-existing Auth user should succeed directly and never
// touch the create fallback at all. Before the fix, `env.__state.__knownAuthUsers` didn't even
// matter for this failure mode in production (the bug was the URL, not the not-found branching)
// — but modeling both "target's Auth record already exists" explicitly here is what lets these
// tests tell the two failure modes apart.

test("setPin (A): superadmin changes PIN of an EXISTING SUPERVISOR with unchanged role — Auth record already exists", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin" },
      { id: "sup_a", username: "sup_a", role: "supervisor", linkedId: "supA" },
    ],
    credentials: { sa: { pinHash: HASH_1234, role: "superadmin" }, sup_a: { pinHash: HASH_1234, role: "supervisor" } },
  });
  env.__state.__knownAuthUsers = new Set(["sa", "sup_a"]); // both have logged in before
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sa", { role: "superadmin" }, kid);

  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "sup_a", newPin: "9012" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.notEqual(env.__state.credentials.sup_a.pinHash, HASH_1234);
  assert.equal(env.__state.credentials.sup_a.role, "supervisor", "role must stay unchanged when payload.role is omitted");
  assert.equal(env.__state.appData.users.find((u) => u.id === "sup_a").role, "supervisor");
  const createCalls = env.__state.identityCalls.filter((c) => c.path === "accounts" || c.path === "accounts:signUp");
  assert.equal(createCalls.length, 0, "an existing Auth user's PIN change must never hit any account-creation endpoint");
});

test("setPin (B): superadmin resets PIN of an existing plain user, role unchanged, Auth record already exists", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin" },
      { id: "carol", username: "carol", role: "user" },
    ],
    credentials: { sa: { pinHash: HASH_1234, role: "superadmin" }, carol: { pinHash: HASH_1234, role: "user" } },
  });
  env.__state.__knownAuthUsers = new Set(["sa", "carol"]);
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sa", { role: "superadmin" }, kid);

  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "carol", newPin: "3344" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.notEqual(env.__state.credentials.carol.pinHash, HASH_1234);
  assert.equal(env.__state.credentials.carol.role, "user");
  const revokeCalls = env.__state.identityCalls.filter((c) => c.body?.validSince && c.body.localId === "carol");
  assert.equal(revokeCalls.length, 1, "existing-user PIN reset must revoke refresh tokens");
  const createCalls = env.__state.identityCalls.filter((c) => c.path === "accounts" || c.path === "accounts:signUp");
  assert.equal(createCalls.length, 0);
});

test("setPin (D): superadmin creates a brand-new user's credentials via the CORRECT account-creation endpoint", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "sa", username: "sa", role: "superadmin" }],
    credentials: { sa: { pinHash: HASH_1234, role: "superadmin" } },
  });
  env.__state.__knownAuthUsers = new Set(["sa"]); // "dave" does not exist yet anywhere
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sa", { role: "superadmin" }, kid);

  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "dave", newPin: "1111", role: "user" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200);
  assert.ok(env.__state.credentials.dave, "credentials entry must be created");
  assert.ok(env.__state.credentials.dave.pinHash.startsWith("$2"), "must store a bcrypt hash, never plaintext");
  assert.ok(env.__state.appData.users.some((u) => u.id === "dave"), "users list must include the new account");
  const createCalls = env.__state.identityCalls.filter((c) => c.path === "accounts");
  assert.equal(createCalls.length, 1, "must create the Auth record via the correct plain `accounts` endpoint exactly once");
  const brokenCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:signUp");
  assert.equal(brokenCalls.length, 0, "must never call the broken accounts:signUp endpoint");
});

test("setPin (G): the broken accounts:signUp endpoint is never called for ANY setUserPin operation, existing or new", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin" },
      { id: "existing", username: "existing", role: "user" },
    ],
    credentials: { sa: { pinHash: HASH_1234, role: "superadmin" }, existing: { pinHash: HASH_1234, role: "user" } },
  });
  env.__state.__knownAuthUsers = new Set(["sa"]); // note: "existing" has an appData/credentials
  // entry but (deliberately, for this test) no prior Auth login — the exact production
  // scenario that used to 404.
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "sa", { role: "superadmin" }, kid);

  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "existing", newPin: "2222" } }),
    env,
    {}
  );
  assert.equal(resp.status, 200, "must succeed even when the target has never logged in before");
  const brokenCalls = env.__state.identityCalls.filter((c) => c.path === "accounts:signUp");
  assert.equal(brokenCalls.length, 0);
});

test("setPin (H): a failed operation returns a generic error with no internal detail, secret, or hash", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "u1", username: "u1", role: "user" }],
    credentials: { u1: { pinHash: HASH_1234, role: "user" } },
  });
  installFakeFetch(env, publicJwk);
  const token = await signIdToken(privateKey, "u1", {}, kid);
  const resp = await worker.fetch(
    req("/user/setPin", { headers: { Authorization: `Bearer ${token}` }, body: { targetUserId: "u1", currentPin: "0000", newPin: "9999" } }),
    env,
    {}
  );
  assert.equal(resp.status, 401);
  const text = await resp.text();
  assert.doesNotMatch(text, /\$2[aby]\$/, "response body must never contain a bcrypt hash");
  assert.doesNotMatch(text, /Bearer |privateKey|BEGIN (RSA )?PRIVATE KEY/, "response body must never contain tokens/keys");
  const parsed = JSON.parse(text);
  assert.deepEqual(Object.keys(parsed), ["error"]);
  assert.equal(parsed.error.message, "Current PIN is incorrect");
});

// ---------------------------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------------------------

for (const path of ["/", "/login", "/data/get", "/data/save", "/user/setPin"]) {
  test(`CORS preflight OPTIONS ${path} returns 204 with Authorization allowed`, async () => {
    const env = makeEnv();
    const resp = await worker.fetch(new Request(`https://worker.example${path}`, { method: "OPTIONS", headers: { Origin: "https://nishant3451.github.io" } }), env, {});
    assert.equal(resp.status, 204);
    assert.match(resp.headers.get("Access-Control-Allow-Headers") || "", /Authorization/);
    assert.equal(resp.headers.get("Access-Control-Allow-Origin"), "https://nishant3451.github.io");
  });
}

test("CORS: a disallowed origin gets no Access-Control-Allow-Origin header", async () => {
  const env = makeEnv();
  const resp = await worker.fetch(new Request("https://worker.example/login", { method: "OPTIONS", headers: { Origin: "https://evil.example" } }), env, {});
  assert.equal(resp.headers.get("Access-Control-Allow-Origin"), null);
});
