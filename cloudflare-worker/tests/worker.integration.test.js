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

// ---------------------------------------------------------------------------------------------
// SECTION AUTHORIZATION through the real HTTP handlers (Products / Quotations+invoices / Payments).
// Identity is the verified token + the server-stored users record; nothing in the request body,
// headers or any client-side state decides access.
// ---------------------------------------------------------------------------------------------
async function sectionEnv({ permissions, userPermissions } = {}) {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: null },
      { id: "u1", username: "u1", role: "user", linkedId: "supA" },
    ],
  });
  Object.assign(env.__state.appData, {
    permissions: permissions || { superadmin: {}, admin: {}, user: { marathon: "write" } },
    userPermissions: userPermissions || {},
    shared: {
      supervisors: [{ id: "supA" }], members: [{ id: "m1", supervisorId: "supA" }], coaches: [], gifts: [], clients: [],
      products: [{ id: "p1", name: "TOP-SECRET-PRODUCT" }],
      quotations: [{ id: "q1", customerName: "SECRET-CUSTOMER", invoiceNumber: "INV-SECRET-9", ownerId: "u1" }],
      transactions: [{ id: "t1", customer: "PAYER", amount: 100, ownerId: "u1" }],
    },
    perUser: {},
  });
  installFakeFetch(env, publicJwk);
  const tokenFor = (uid, claims = {}) => signIdToken(privateKey, uid, { role: (env.__state.appData.users.find((u) => u.id === uid) || {}).role, ...claims }, kid);
  const call = async (path, uid, body) => worker.fetch(req(path, { headers: { Authorization: `Bearer ${await tokenFor(uid)}` }, body }), env, {});
  const get = async (uid, body) => { const r = await call("/data/get", uid, body); return { status: r.status, text: await r.text() }; };
  const view = async (uid) => { const r = await get(uid); assert.equal(r.status, 200); return JSON.parse(JSON.parse(r.text).data.json); };
  const save = async (uid, submitted) => call("/data/save", uid, { json: JSON.stringify(submitted) });
  return { env, get, view, save, data: () => env.__state.appData };
}

test("section auth / data/get: superadmin receives products, quotations and transactions", async () => {
  const h = await sectionEnv();
  const v = await h.view("sa");
  assert.deepEqual(v.shared.products.map((p) => p.id), ["p1"]);
  assert.deepEqual(v.shared.quotations.map((p) => p.id), ["q1"]);
  assert.deepEqual(v.shared.transactions.map((p) => p.id), ["t1"]);
});

test("section auth / data/get: a user without access gets products=[] quotations=[] and NOTHING sensitive appears anywhere in the response bytes", async () => {
  const h = await sectionEnv({ permissions: { superadmin: {}, admin: {}, user: {} } }); // no Payments either
  const r = await h.get("u1");
  assert.equal(r.status, 200);
  const v = JSON.parse(JSON.parse(r.text).data.json);
  assert.deepEqual(v.shared.products, []);
  assert.deepEqual(v.shared.quotations, []);
  assert.deepEqual(v.shared.transactions, []);
  for (const secret of ["TOP-SECRET-PRODUCT", "SECRET-CUSTOMER", "INV-SECRET-9", "PAYER"]) assert.ok(!r.text.includes(secret), `${secret} must not be in the payload`);
  assert.deepEqual(v.shared.members.map((m) => m.id), ["m1"], "unrelated in-scope data is still delivered");
});

test("section auth / data/get: role, uid and permissions supplied in the request body are ignored — only the verified token decides", async () => {
  const h = await sectionEnv();
  const r = await h.get("u1", { role: "superadmin", uid: "sa", permissions: { user: { products: "write" } }, userPermissions: { u1: { products: "write" } } });
  assert.equal(r.status, 200);
  const v = JSON.parse(JSON.parse(r.text).data.json);
  assert.deepEqual(v.shared.products, []);
  assert.deepEqual(v.shared.quotations, []);
  assert.ok(!r.text.includes("TOP-SECRET-PRODUCT") && !r.text.includes("SECRET-CUSTOMER"));
});

test("section auth / data/save: a hidden-section user cannot alter, wipe or unlock anything — forged permissions and stale data are discarded", async () => {
  const h = await sectionEnv();
  const before = JSON.parse(JSON.stringify(h.data()));
  const submitted = JSON.parse(JSON.stringify(before));
  submitted.shared.products = [{ id: "evil" }];
  submitted.shared.quotations = [];
  submitted.shared.transactions = [{ id: "evil-t" }];
  submitted.userPermissions = { u1: { products: "write", quotations: "write" } };
  submitted.permissions.user = { products: "write", quotations: "write", marathon: "write" };
  submitted.users.find((u) => u.id === "u1").role = "superadmin";
  const r = await h.save("u1", submitted);
  assert.equal(r.status, 200, "the save itself succeeds; the unauthorized parts are silently dropped (existing behaviour)");
  assert.deepEqual(h.data().shared.products, before.shared.products);
  assert.deepEqual(h.data().shared.quotations, before.shared.quotations);
  assert.deepEqual(h.data().shared.transactions, before.shared.transactions, "shared writes by a scoped user stay dropped (pre-existing)");
  assert.deepEqual(h.data().userPermissions, before.userPermissions);
  assert.deepEqual(h.data().permissions, before.permissions);
  assert.equal(h.data().users.find((u) => u.id === "u1").role, "user");
  assert.deepEqual((await h.view("u1")).shared.products, [], "and they still cannot read it afterwards");
});

test("section auth / Manage Access lifecycle end-to-end: superadmin grants → user sees data → superadmin revokes → hidden again", async () => {
  const h = await sectionEnv();
  assert.deepEqual((await h.view("u1")).shared.products, [], "starts hidden");

  // superadmin (as the Manage Access UI does) writes an individual override through the normal save
  const sa1 = JSON.parse(JSON.stringify(h.data()));
  sa1.userPermissions = { u1: { products: "view", quotations: "view" } };
  assert.equal((await h.save("sa", sa1)).status, 200);
  const granted = await h.view("u1");
  assert.deepEqual(granted.shared.products.map((p) => p.id), ["p1"]);
  assert.deepEqual(granted.shared.quotations.map((p) => p.id), ["q1"]);
  assert.deepEqual(granted.userPermissions, { u1: { products: "view", quotations: "view" } });
  // view-only: their own write attempt on the section is still discarded
  const u1Save = JSON.parse(JSON.stringify(h.data())); u1Save.shared.products = [{ id: "p1" }, { id: "hax" }];
  await h.save("u1", u1Save);
  assert.deepEqual(h.data().shared.products.map((p) => p.id), ["p1"]);

  // revoke
  const sa2 = JSON.parse(JSON.stringify(h.data())); sa2.userPermissions = { u1: { products: "hidden" } };
  assert.equal((await h.save("sa", sa2)).status, 200);
  const revoked = await h.view("u1");
  assert.deepEqual(revoked.shared.products, []);
  assert.deepEqual(revoked.shared.quotations, [], "quotations: the override was replaced wholesale, so the role default (hidden) applies again");
});

test("section auth / data/save: an ADMIN cannot grant access (permissions/userPermissions are superadmin-only)", async () => {
  const h = await sectionEnv();
  const before = JSON.parse(JSON.stringify(h.data()));
  const s = JSON.parse(JSON.stringify(before));
  s.userPermissions = { u1: { products: "write" }, adm: { products: "hidden" } };
  s.permissions.user = { products: "write", quotations: "write", marathon: "write" };
  assert.equal((await h.save("adm", s)).status, 200);
  assert.deepEqual(h.data().userPermissions, before.userPermissions);
  assert.deepEqual(h.data().permissions, before.permissions);
  assert.deepEqual((await h.view("u1")).shared.products, []);
});

test("section auth / superadmin keeps full access and writes even when the stored matrix/override says hidden", async () => {
  const h = await sectionEnv({ permissions: { superadmin: { products: "hidden", quotations: "hidden", marathon: "hidden" }, admin: {}, user: {} }, userPermissions: { sa: { products: "hidden" } } });
  const v = await h.view("sa");
  assert.deepEqual(v.shared.products.map((p) => p.id), ["p1"]);
  const s = JSON.parse(JSON.stringify(h.data())); s.shared.products.push({ id: "p2" });
  await h.save("sa", s);
  assert.deepEqual(h.data().shared.products.map((p) => p.id), ["p1", "p2"]);
});

// ---------------------------------------------------------------------------------------------
// ROLE FRESHNESS through the real handlers. Scenario: a role-only demotion (what User Management does when no new PIN
// is entered) changes ONLY appData.users[].role. The user's already-issued ID token still says `admin`; the credentials
// doc and the persisted claim are stale too. Before the fix such a token kept full admin authority.
// ---------------------------------------------------------------------------------------------
async function freshnessEnv() {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: null },
      { id: "u1", username: "u1", role: "user", linkedId: "supA" },
    ],
    credentials: { sa: { pinHash: HASH_1234, role: "superadmin" }, adm: { pinHash: HASH_1234, role: "admin" }, u1: { pinHash: HASH_1234, role: "user" } },
  });
  env.__state.__knownAuthUsers = new Set(["sa", "adm", "u1"]);
  Object.assign(env.__state.appData, {
    permissions: { superadmin: {}, admin: {}, user: { marathon: "write" } }, userPermissions: {},
    shared: { supervisors: [{ id: "supA" }], members: [{ id: "m1", supervisorId: "supA" }], coaches: [], gifts: [], clients: [], products: [], quotations: [], transactions: [] },
    perUser: { u1: { transactions: [{ id: "u1-private-tx" }], products: [], quotations: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] } },
  });
  installFakeFetch(env, publicJwk);
  const sign = (uid, role) => signIdToken(privateKey, uid, { role }, kid);
  const as = async (token, path, body) => worker.fetch(req(path, { headers: { Authorization: `Bearer ${token}` }, body }), env, {});
  const setStoredRole = (uid, role) => { env.__state.appData.users.find((u) => u.id === uid).role = role; };
  return { env, sign, as, setStoredRole, data: () => env.__state.appData };
}
const viewOf = async (resp) => JSON.parse((await resp.json()).data.json);

test("role freshness / data/get: a demoted admin's OLD admin token no longer yields the full-access view", async () => {
  const h = await freshnessEnv();
  const oldToken = await h.sign("adm", "admin");
  // Observable for "treated as full-access": the user DIRECTORY. (Payments/Quotations are now hierarchy-scoped even for
  // admins, so another user's bucket is no longer a valid probe.) A scoped caller only receives their downline's accounts.
  const before = await viewOf(await h.as(oldToken, "/data/get", {}));
  assert.ok(before.users.some((u) => u.id === "u1") && before.users.some((u) => u.id === "sa"), "control: while still an admin they receive every account");
  h.setStoredRole("adm", "user");
  const after = await viewOf(await h.as(oldToken, "/data/get", {}));
  assert.ok(!after.users.some((u) => u.id === "u1" || u.id === "sa"), "demoted: the directory shrinks to the scoped view immediately");
});

test("role freshness / data/save: a demoted admin cannot re-promote themselves or edit users with the old token", async () => {
  const h = await freshnessEnv();
  const oldToken = await h.sign("adm", "admin");
  h.setStoredRole("adm", "user");
  const forged = JSON.parse(JSON.stringify(h.data()));
  forged.users.find((u) => u.id === "adm").role = "admin";                        // try to undo the demotion
  forged.users.find((u) => u.id === "u1").role = "admin";                         // and mint another admin
  forged.users.push({ id: "backdoor", username: "backdoor", role: "admin", linkedId: null });
  forged.userPermissions = { adm: { products: "write" } };
  const r = await h.as(oldToken, "/data/save", { json: JSON.stringify(forged) });
  assert.equal(r.status, 200);
  assert.equal(h.data().users.find((u) => u.id === "adm").role, "user", "the demotion stands");
  assert.equal(h.data().users.find((u) => u.id === "u1").role, "user");
  assert.ok(!h.data().users.some((u) => u.id === "backdoor"));
  assert.deepEqual(h.data().userPermissions, {});
});

test("role freshness / user/setPin: a demoted admin's old token can no longer reset or delete other accounts", async () => {
  const h = await freshnessEnv();
  const oldToken = await h.sign("adm", "admin");
  const control = await h.as(oldToken, "/user/setPin", { targetUserId: "u1", newPin: "5555" });
  assert.equal(control.status, 200, "control: a current admin can reset a user's PIN");
  h.setStoredRole("adm", "user");
  const reset = await h.as(oldToken, "/user/setPin", { targetUserId: "u1", newPin: "6666" });
  assert.equal(reset.status, 403);
  const del = await h.as(oldToken, "/user/setPin", { targetUserId: "u1", delete: true });
  assert.equal(del.status, 403);
  assert.ok(h.data().users.some((u) => u.id === "u1"), "target account still exists");
});

test("role freshness / privacy admin endpoints: a demoted admin's old token cannot publish policies or change request status", async () => {
  const h = await freshnessEnv();
  const oldToken = await h.sign("adm", "admin");
  const publish = (t) => h.as(t, "/privacy/policy/publish", { type: "privacy_policy", version: "1.4", effectiveDate: "2026-01-01" });
  assert.equal((await publish(oldToken)).status, 200, "control: a current admin can publish");
  h.setStoredRole("adm", "user");
  assert.equal((await publish(oldToken)).status, 403);
  const status = await h.as(oldToken, "/privacy/request/status", { requestId: "r1", status: "completed" });
  assert.equal(status.status, 403, "403 (not 404) — authorization is decided before the request is even looked up");
});

test("role freshness / login: re-login after a role-only demotion does NOT mint the stale admin role", async () => {
  const h = await freshnessEnv();
  h.setStoredRole("adm", "user");                    // credentials doc still says admin — this used to win
  const resp = await worker.fetch(req("/login", { body: { username: "adm", pin: "1234" } }), h.env, {});
  assert.equal(resp.status, 200);
  assert.equal((await resp.json()).user.role, "user");
  const claimWrites = h.env.__state.identityCalls.filter((c) => c.path === "accounts:update").map((c) => c.body.customAttributes).filter(Boolean);
  assert.ok(claimWrites.length >= 1 && claimWrites.every((c) => JSON.parse(c).role === "user"), "persisted claims are the demoted role: " + claimWrites.join(","));
});

test("role freshness / superadmin demoted to admin loses superadmin-only powers immediately (access settings stay locked)", async () => {
  const h = await freshnessEnv();
  const oldToken = await h.sign("sa", "superadmin");
  h.setStoredRole("sa", "admin");
  const s = JSON.parse(JSON.stringify(h.data()));
  s.userPermissions = { u1: { products: "write" } };
  assert.equal((await h.as(oldToken, "/data/save", { json: JSON.stringify(s) })).status, 200);
  assert.deepEqual(h.data().userPermissions, {}, "only a (current) superadmin may change access settings");
});

test("role freshness / controls: current admins and superadmins are unaffected, and a stored PROMOTION does not raise a user's token role", async () => {
  const h = await freshnessEnv();
  const admToken = await h.sign("adm", "admin");
  const adminView = await viewOf(await h.as(admToken, "/data/get", {}));
  assert.ok(adminView.users.some((u) => u.id === "u1") && adminView.users.some((u) => u.id === "sa"), "admin: full-access directory as before");
  const saToken = await h.sign("sa", "superadmin");
  const s = JSON.parse(JSON.stringify(h.data())); s.userPermissions = { u1: { products: "view" } };
  await h.as(saToken, "/data/save", { json: JSON.stringify(s) });
  assert.deepEqual(h.data().userPermissions, { u1: { products: "view" } }, "superadmin: access-settings write still works");
  // promotion in the stored record only; the token still says `user` => still the scoped view
  h.setStoredRole("u1", "admin");
  const u1Token = await h.sign("u1", "user");
  const u1View = await viewOf(await h.as(u1Token, "/data/get", {}));
  assert.deepEqual(Object.keys(u1View.perUser), ["u1"], "no privilege is granted from the stored role alone");
});

test("role freshness / privacy/export: a demoted admin's old token exports with the demoted role's section access", async () => {
  const h = await freshnessEnv();
  h.data().perUser.adm = { transactions: [], products: [{ id: "adm-own-product" }], quotations: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] };
  const oldToken = await h.sign("adm", "admin");
  const exported = async () => (await (await h.as(oldToken, "/privacy/export", {})).json()).data.export;
  assert.deepEqual((await exported()).ownRecords.products.map((p) => p.id), ["adm-own-product"], "control: admin default => Products write");
  h.setStoredRole("adm", "user");
  assert.deepEqual((await exported()).ownRecords.products, [], "demoted to user => Products hidden by default, so not exported either");
});

// ---------------------------------------------------------------------------------------------
// DATA SCOPE through the real HTTP handlers: Payments + Quotations, hierarchy supTop > supMid > supLow, supOther unrelated.
// The only request field the server reads is `scope`, and it is a REQUEST that is validated, never trusted.
// ---------------------------------------------------------------------------------------------
async function scopeEnv() {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: "supMid" },
      { id: "top", username: "top", role: "user", linkedId: "supTop" },
      { id: "low", username: "low", role: "user", linkedId: "supLow" },
      { id: "other", username: "other", role: "user", linkedId: "supOther" },
    ],
  });
  const pay = (o, status) => ({ id: `pay-${o}`, customer: `PAYER-${o}`, amount: 10, status, ownerId: o });
  const quo = (o) => ({ id: `q-${o}`, customerName: `QCUST-${o}`, invoiceNumber: `INV-${o}`, ownerId: o });
  Object.assign(env.__state.appData, {
    permissions: { superadmin: {}, admin: {}, user: { marathon: "write", quotations: "write" } }, userPermissions: {},
    shared: {
      supervisors: [{ id: "supTop", supervisorId: null }, { id: "supMid", supervisorId: "supTop" }, { id: "supLow", supervisorId: "supMid" }, { id: "supOther", supervisorId: null }],
      members: [], coaches: [], gifts: [], clients: [], products: [],
      transactions: [pay("sa", "pending"), pay("adm", "completed"), pay("top", "pending"), pay("low", "pending"), pay("other", "pending"), { id: "pay-legacy", customer: "PAYER-legacy", status: "pending" }],
      quotations: [quo("sa"), quo("adm"), quo("top"), quo("low"), quo("other")],
    },
    perUser: {},
  });
  installFakeFetch(env, publicJwk);
  const as = async (uid, path, body) => worker.fetch(req(path, { headers: { Authorization: `Bearer ${await signIdToken(privateKey, uid, { role: (env.__state.appData.users.find((u) => u.id === uid) || {}).role }, kid)}` }, body }), env, {});
  const get = async (uid, body) => { const r = await as(uid, "/data/get", body); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) {} return { status: r.status, text, json, view: r.status === 200 ? JSON.parse(json.data.json) : null }; };
  return { env, as, get, data: () => env.__state.appData };
}
const idsOf = (a) => (a || []).map((x) => x.id).sort();

test("data scope / A,O: superadmin can request All Data and is unrestricted", async () => {
  const h = await scopeEnv();
  for (const body of [{}, { scope: "all" }]) {
    const r = await h.get("sa", body);
    assert.equal(r.status, 200);
    assert.equal(r.view.shared.transactions.length, 6, "everything, including the legacy record with no owner");
    assert.equal(r.view.shared.quotations.length, 5);
    assert.equal(r.view.dataScope.active, "all");
    assert.ok(r.view.dataScope.allowed.includes("all"));
  }
});

test("data scope / B,P: an admin cannot request All Data — rejected with a distinguishable code, and the default view is their hierarchy only", async () => {
  const h = await scopeEnv();
  const denied = await h.get("adm", { scope: "all" });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error.code, "SCOPE_NOT_ALLOWED");
  assert.ok(!denied.text.includes("PAYER-") && !denied.text.includes("QCUST-"), "the rejection leaks nothing");
  const ok = await h.get("adm", {});
  assert.equal(ok.status, 200);
  assert.deepEqual(idsOf(ok.view.shared.transactions), ["pay-adm", "pay-low"]);
  assert.deepEqual(idsOf(ok.view.shared.quotations), ["q-adm", "q-low"]);
  assert.ok(!ok.view.dataScope.allowed.includes("all"));
});

test("data scope / C: a normal user cannot request All Data", async () => {
  const h = await scopeEnv();
  for (const uid of ["low", "top", "other"]) {
    const r = await h.get(uid, { scope: "all" });
    assert.equal(r.status, 403, uid); assert.equal(r.json.error.code, "SCOPE_NOT_ALLOWED");
  }
});

test("data scope / D,E,F: forged role, uid, userId, linkedId, permissions and 'all' flags in the body change nothing", async () => {
  const h = await scopeEnv();
  const plain = await h.get("adm", {});
  const forged = await h.get("adm", { role: "superadmin", uid: "sa", userId: "sa", linkedId: "supTop", all: true, includeAll: true, scopeAll: true,
    permissions: { admin: { marathon: "write" } }, userPermissions: { adm: { marathon: "write" } }, hierarchy: { downline: ["other", "top"] }, owners: ["other", "top", "sa"] });
  assert.equal(forged.status, 200);
  assert.deepEqual(forged.view.shared.transactions, plain.view.shared.transactions);
  assert.deepEqual(forged.view.shared.quotations, plain.view.shared.quotations);
  assert.ok(!forged.text.includes("PAYER-sa") && !forged.text.includes("PAYER-top") && !forged.text.includes("PAYER-other") && !forged.text.includes("QCUST-other"));
  const forgedUser = await h.get("low", { role: "admin", uid: "adm", linkedId: "supTop", scope: "mine" });
  assert.deepEqual(idsOf(forgedUser.view.shared.transactions), ["pay-low"], "a user's own scope, whatever hierarchy they claim");
  const leafAll = await h.get("low", { scope: "mine_downline" });
  assert.equal(leafAll.status, 403, "a leaf has no downline, so that option is not offered — and is rejected if forced");
});

test("data scope / hostile scope values (wrong types, prototype keys, unknown names, 'upline') are rejected, null/absent use the default", async () => {
  const h = await scopeEnv();
  for (const bad of [{ $ne: 1 }, ["all"], ["mine"], 1, true, "ALL", "upline", "everything", "__proto__", "constructor", "", "mine ", "mine,all"]) {
    const r = await h.get("adm", { scope: bad });
    assert.equal(r.status, 403, JSON.stringify(bad)); assert.equal(r.json.error.code, "SCOPE_NOT_ALLOWED");
  }
  assert.equal((await h.get("adm", { scope: null })).status, 200);
  assert.equal((await h.get("adm", {})).status, 200);
  assert.equal((await h.get("adm", undefined)).status, 200, "no body at all still works (existing clients)");
});

test("data scope / G,H: a user cannot obtain another unrelated user's Payments or Quotations via any request", async () => {
  const h = await scopeEnv();
  for (const scope of [undefined, "mine", "downline", "mine_downline"]) {
    const r = await h.get("low", scope === undefined ? {} : { scope });
    if (r.status !== 200) { assert.equal(r.json.error.code, "SCOPE_NOT_ALLOWED"); continue; }  // 'downline' for a leaf is not offered
    for (const o of ["other", "top", "adm", "sa"]) assert.ok(!r.text.includes(`PAYER-${o}`) && !r.text.includes(`QCUST-${o}`) && !r.text.includes(`INV-${o}`), `${scope}: ${o}`);
    assert.ok(!r.text.includes("PAYER-legacy"));
  }
});

test("data scope / I: hierarchy is respected — adm sees their downline's records, never an upline's or an unrelated user's", async () => {
  const h = await scopeEnv();
  const down = await h.get("adm", { scope: "downline" });
  assert.deepEqual(idsOf(down.view.shared.transactions), ["pay-low"]);
  const mine = await h.get("adm", { scope: "mine" });
  assert.deepEqual(idsOf(mine.view.shared.transactions), ["pay-adm"]);
  const top = await h.get("top", {});
  assert.deepEqual(idsOf(top.view.shared.transactions), ["pay-adm", "pay-low", "pay-top"], "top's downline includes adm and low");
  assert.ok(!top.text.includes("PAYER-other"));
});

test("data scope / J,K: a hidden section stays hidden whatever scope is requested; view-only stays view-only", async () => {
  const h = await scopeEnv();
  h.data().userPermissions = { adm: { marathon: "hidden", quotations: "view" } };
  for (const scope of [undefined, "mine", "downline", "mine_downline"]) {
    const r = await h.get("adm", scope === undefined ? {} : { scope });
    assert.equal(r.status, 200); assert.deepEqual(r.view.shared.transactions, [], `hidden Payments (${scope})`);
    assert.ok(r.view.shared.quotations.length > 0, "view-only Quotations are still served");
  }
  const before = JSON.parse(JSON.stringify(h.data().shared.quotations));
  const s = JSON.parse(JSON.stringify(h.data())); s.shared.quotations = s.shared.quotations.map((q) => ({ ...q, customerName: "CHANGED" }));
  assert.equal((await h.as("adm", "/data/save", { json: JSON.stringify(s) })).status, 200);
  assert.deepEqual(h.data().shared.quotations, before, "view-only: the write is discarded");
});

test("data scope / M,N: the Payment-status filter can never expose anything — the server decides what exists before any status is applied", async () => {
  const h = await scopeEnv();
  const baseline = await h.get("adm", {});
  for (const status of ["pending", "completed", "all", "refunded", "__proto__", "", null, { $ne: "x" }, ["pending"]]) {
    const r = await h.get("adm", { paymentStatus: status, status, filter: status, payment_status: status });
    assert.equal(r.status, 200, JSON.stringify(status));
    assert.deepEqual(r.view.shared.transactions, baseline.view.shared.transactions, "no status value changes what the server returns");
    for (const unauthorised of ["PAYER-sa", "PAYER-top", "PAYER-other", "PAYER-legacy"]) assert.ok(!r.text.includes(unauthorised), `${JSON.stringify(status)} -> ${unauthorised}`);
  }
  // unauthorised PENDING records exist (top/other/sa/legacy are pending) yet never reach a Pending-filtering client
  assert.ok(h.data().shared.transactions.filter((t) => t.status === "pending").length > baseline.view.shared.transactions.filter((t) => t.status === "pending").length);
});

test("data scope / L: stale-data replay and narrowed-client saves cannot damage out-of-scope data", async () => {
  const h = await scopeEnv();
  const before = JSON.parse(JSON.stringify(h.data().shared.transactions));
  const held = (await h.get("adm", {})).view;                        // the admin's client only ever holds pay-adm + pay-low
  const s = JSON.parse(JSON.stringify(h.data()));
  s.shared.transactions = held.shared.transactions.map((t) => (t.id === "pay-adm" ? { ...t, amount: 77 } : t));
  s.shared.transactions.push({ id: "pay-evil", customer: "EVIL", ownerId: "top" }, { id: "pay-other", customer: "HIJACK", ownerId: "adm" });
  assert.equal((await h.as("adm", "/data/save", { json: JSON.stringify(s) })).status, 200);
  const after = Object.fromEntries(h.data().shared.transactions.map((t) => [t.id, t]));
  assert.equal(after["pay-adm"].amount, 77, "in-scope edit applied");
  for (const keep of ["pay-sa", "pay-top", "pay-other", "pay-legacy"]) assert.deepEqual(after[keep], before.find((t) => t.id === keep), `${keep} untouched`);
  assert.ok(!after["pay-evil"], "cannot forge a record for an upline");
  // moving `low` out of adm's tree: an old client replaying low's record cannot edit or delete it any more
  h.data().shared.supervisors.find((x) => x.id === "supLow").supervisorId = "supOther";
  const replay = JSON.parse(JSON.stringify(h.data())); replay.shared.transactions = held.shared.transactions.map((t) => (t.id === "pay-low" ? { ...t, amount: 31337 } : t));
  await h.as("adm", "/data/save", { json: JSON.stringify(replay) });
  assert.equal(h.data().shared.transactions.find((t) => t.id === "pay-low").amount, 10);
});

test("data scope / O: superadmin saves remain unrestricted", async () => {
  const h = await scopeEnv();
  const s = JSON.parse(JSON.stringify(h.data())); s.shared.transactions = [{ id: "only", ownerId: "other" }];
  assert.equal((await h.as("sa", "/data/save", { json: JSON.stringify(s) })).status, 200);
  assert.deepEqual(h.data().shared.transactions.map((t) => t.id), ["only"]);
});

test("data scope / a demoted admin's old token is scoped as the demoted role, and still cannot request All Data", async () => {
  const h = await scopeEnv();
  h.data().users.find((u) => u.id === "adm").role = "user";
  const denied = await h.get("adm", { scope: "all" });
  assert.equal(denied.status, 403);
  assert.deepEqual(idsOf((await h.get("adm", {})).view.shared.transactions), ["pay-adm", "pay-low"]);
});
