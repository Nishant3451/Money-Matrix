// ============================================================================================
// Server-side policy acceptance gate (ISSUE 1 of the final hardening pass): /data/get and
// /data/save must refuse to expose or mutate protected application data for an authenticated
// user who has not accepted every CURRENTLY PUBLISHED policy version, using ONLY the server's
// own stored policyVersions/policyAcceptances -- never anything from the request, localStorage,
// or the client's role claim. /privacy/* endpoints (a separate code path, runPrivacyMutation)
// must remain completely unaffected, so the gate can always be satisfied from inside it.
//
// Harness: real RSA keypairs standing in for the Firebase service account and Google's
// securetoken signing key, a fake JWKS endpoint, and an in-memory Firestore double -- same
// pattern already used by worker.integration.test.js and
// cloudflare-worker/tests/privacy-request-status-transitions.test.js (duplicated per those
// files' own stated convention rather than imported).
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto, generateKeyPairSync } from "node:crypto";
import worker from "../login-worker.js";
import { hasAcceptedAllCurrentPolicies, currentPublishedPolicySummary, POLICY_TYPES } from "../lib/privacy.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const PROJECT_ID = "money-metrix-9f1da";
let kidCounter = 0;
const nextKid = () => `pag-kid-${++kidCounter}`;

function b64url(bytes) { let bin = ""; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
const b64urlJson = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));

async function generateSecuretokenKeyPair() {
  const kid = nextKid();
  const keyPair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = kid; publicJwk.alg = "RS256"; publicJwk.use = "sig";
  return { privateKey: keyPair.privateKey, publicJwk, kid };
}
async function signIdToken(privateKey, uid, claimsOverride = {}, kid) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid, typ: "JWT" };
  const payload = { iss: `https://securetoken.google.com/${PROJECT_ID}`, aud: PROJECT_ID, sub: uid, iat: now, exp: now + 3600, auth_time: now, approved: true, role: "user", ...claimsOverride };
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
function encodeFirestoreFields(obj) { const fields = {}; for (const k of Object.keys(obj || {})) fields[k] = encodeFirestoreValue(obj[k]); return fields; }
function makeFakeKv() { const store = new Map(); return { async get(key, type) { const v = store.get(key); if (v === undefined) return null; return type === "json" ? JSON.parse(v) : v; }, async put(key, value) { store.set(key, value); }, _store: store }; }
function makeEnv({ users = [], policyVersions = [], policyAcceptances = {} } = {}) {
  const state = { appData: { users, profiles: {}, settings: {}, permissions: {}, customSections: [], userPermissions: {}, shared: { members: [], coaches: [], supervisors: [], transactions: [], gifts: [], products: [{ id: "p1" }], quotations: [], clients: [] }, perUser: {}, activityLog: [], privacyConsents: {}, policyVersions, policyAcceptances, privacyPreferences: {}, privacyRequests: [], privacyAuditLog: [] } };
  return { FIREBASE_PROJECT_ID: PROJECT_ID, FIREBASE_CLIENT_EMAIL: "svc@money-metrix-9f1da.iam.gserviceaccount.com", FIREBASE_PRIVATE_KEY: PRIVATE_KEY_PEM, ALLOWED_ORIGIN: "https://nishant3451.github.io", RATE_LIMIT_KV: makeFakeKv(), __state: state };
}
function installFakeFetch(env, jwk) {
  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    let body = null; if (init?.body) { try { body = JSON.parse(init.body); } catch (e) { body = null; } }
    if (u === "https://oauth2.googleapis.com/token") return new Response(JSON.stringify({ access_token: "fake-access-token", expires_in: 3600 }), { status: 200 });
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/appData")) {
      if (method === "GET") return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(env.__state.appData) }) }), { status: 200 });
      if (method === "PATCH") { env.__state.appData = JSON.parse(body.fields.json.stringValue); return new Response(JSON.stringify({}), { status: 200 }); }
    }
    if (u.includes("firestore.googleapis.com") && u.includes("moneymatrix/meta")) return new Response(JSON.stringify({}), { status: 200 });
    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };
}
function req(path, { body, headers = {} } = {}) {
  return new Request(`https://worker.example${path}`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined });
}
const { privateKey: PRIVATE_KEY_PEM } = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });

const PUBLISHED = POLICY_TYPES.map((type, i) => ({ type, version: "1.0", effectiveDate: "2026-09-01", status: "published" }));
const acceptedAll = (uid) => ({ [uid]: Object.fromEntries(POLICY_TYPES.map((t) => [t, { version: "1.0", timestamp: 1 }])) });

async function setup(overrides = {}) {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({
    users: [{ id: "u1", username: "u1", role: "user", linkedId: null }, { id: "sa1", username: "sa1", role: "superadmin", linkedId: null }],
    policyVersions: PUBLISHED,
    ...overrides,
  });
  installFakeFetch(env, publicJwk);
  const userToken = await signIdToken(privateKey, "u1", { role: "user" }, kid);
  const superToken = await signIdToken(privateKey, "sa1", { role: "superadmin" }, kid);
  return { env, userToken, superToken };
}

// ------------------------------------------------------------------------------------------
// 1-3: missing / partial / outdated acceptance -> denied
// ------------------------------------------------------------------------------------------
test("1: no policy acceptance at all -> /data/get denied with POLICY_ACCEPTANCE_REQUIRED, no BUSINESS data leaked (only policy metadata needed to render the gate)", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403);
  const body = await resp.json();
  assert.equal(body.error.code, "POLICY_ACCEPTANCE_REQUIRED");
  assert.equal(body.data.json, undefined, "no appData JSON payload in a denied response");
  assert.deepEqual(Object.keys(body.data).sort(), ["policyAcceptances", "policyVersions"], "only policy metadata is included, nothing else");
  assert.deepEqual(Object.keys(body.data.policyAcceptances), ["u1"], "only the caller's OWN acceptance entry, never anyone else's");
});
test("1b: the minimal data returned with a POLICY_ACCEPTANCE_REQUIRED denial carries no business data whatsoever, however it's inspected", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  const raw = await resp.text();
  for (const leak of ["products", "quotations", "transactions", "shared", "perUser", "users", "profiles", "\"p1\""]) {
    assert.doesNotMatch(raw, new RegExp(leak), `response body must not mention "${leak}"`);
  }
});
test("2: missing exactly ONE required policy -> denied", async () => {
  const acc = acceptedAll("u1");
  delete acc.u1[POLICY_TYPES[0]];
  const { env, userToken } = await setup({ policyAcceptances: acc });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403);
  assert.equal((await resp.json()).error.code, "POLICY_ACCEPTANCE_REQUIRED");
});
test("3: outdated policy version (accepted an OLD version of a currently-published policy) -> denied", async () => {
  const acc = acceptedAll("u1");
  acc.u1[POLICY_TYPES[0]] = { version: "0.9-old", timestamp: 1 };
  const { env, userToken } = await setup({ policyAcceptances: acc });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403);
});

// ------------------------------------------------------------------------------------------
// 4: all current versions accepted -> allowed
// ------------------------------------------------------------------------------------------
test("4: every current published version accepted -> /data/get returns real data (200, with json payload)", async () => {
  const { env, userToken } = await setup({ policyAcceptances: acceptedAll("u1") });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200);
  const body = await resp.json();
  const view = JSON.parse(body.data.json);
  assert.ok(Array.isArray(view.shared.products));
});

// ------------------------------------------------------------------------------------------
// 5: superadmin is NOT exempt
// ------------------------------------------------------------------------------------------
test("5: superadmin WITHOUT current acceptance is also denied -- no role bypass for the policy gate", async () => {
  const { env, superToken } = await setup({ policyAcceptances: {} });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${superToken}` } }), env, {});
  assert.equal(resp.status, 403);
  assert.equal((await resp.json()).error.code, "POLICY_ACCEPTANCE_REQUIRED");
});
test("5b: superadmin WITH current acceptance is allowed, and (as already covered elsewhere) still gets full unfiltered data", async () => {
  const { env, superToken } = await setup({ policyAcceptances: acceptedAll("sa1") });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${superToken}` } }), env, {});
  assert.equal(resp.status, 200);
});

// ------------------------------------------------------------------------------------------
// 6/7: nothing from the request/client can satisfy the gate
// ------------------------------------------------------------------------------------------
test("6: forged policyAcceptances in the /data/save request body does not satisfy the gate -- only the server's own stored record counts", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const forgedJson = JSON.stringify({ policyAcceptances: acceptedAll("u1") });
  const resp = await worker.fetch(req("/data/save", { body: { json: forgedJson }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403);
  assert.equal((await resp.json()).error.code, "POLICY_ACCEPTANCE_REQUIRED");
  assert.deepEqual(env.__state.appData.policyAcceptances, {}, "the forged acceptance was never written to storage either");
});
test("7: a forged/elevated role claim in the token cannot bypass the gate (the check runs before any role-based branching)", async () => {
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
  const env = makeEnv({ users: [{ id: "u1", username: "u1", role: "user", linkedId: null }], policyVersions: PUBLISHED, policyAcceptances: {} });
  installFakeFetch(env, publicJwk);
  const forgedToken = await signIdToken(privateKey, "u1", { role: "superadmin" }, kid); // token claims superadmin; server derives real role from users[]/custom claims elsewhere, but even if it trusted this, the gate still has no role exemption
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${forgedToken}` } }), env, {});
  assert.equal(resp.status, 403);
});

// ------------------------------------------------------------------------------------------
// 8/9: policy acceptance itself remains usable; and unlocks /data/get right after
// ------------------------------------------------------------------------------------------
test("8: /privacy/policy/accept remains fully usable BEFORE the gate is satisfied (no circular dependency)", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const resp = await worker.fetch(req("/privacy/policy/accept", { body: { policyType: POLICY_TYPES[0], version: "1.0" }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200, "accepting a policy is never itself blocked by the data gate");
});
test("8b: other /privacy/* endpoints (export, request) are also unaffected by the data gate", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const exportResp = await worker.fetch(req("/privacy/export", { body: {}, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(exportResp.status, 200);
  const reqResp = await worker.fetch(req("/privacy/request", { body: { category: "access", description: "help" }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(reqResp.status, 200);
});
test("9: accepting all required policies (one call per type, as the real client does) unlocks /data/get on the very next call", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  const denied = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(denied.status, 403);
  for (const type of POLICY_TYPES) {
    const r = await worker.fetch(req("/privacy/policy/accept", { body: { policyType: type, version: "1.0" }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
    assert.equal(r.status, 200);
  }
  const allowed = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(allowed.status, 200);
});

// ------------------------------------------------------------------------------------------
// 10: publishing behavior (an unpublished type is not required) still correct
// ------------------------------------------------------------------------------------------
test("10: a policy type with nothing published yet is not required -- a brand-new deployment does not lock every user out", async () => {
  const { env, userToken } = await setup({ policyVersions: [], policyAcceptances: {} });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200, "nothing published yet -> nothing required yet");
});
test("10b: partial publication -- only types actually published are required, others are not", async () => {
  const { env, userToken } = await setup({ policyVersions: [PUBLISHED[0]], policyAcceptances: { u1: { [POLICY_TYPES[0]]: { version: "1.0", timestamp: 1 } } } });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200);
});
test("10c: latest-by-effectiveDate wins when a type has multiple published entries (reuses latestPublishedPolicy, not array order)", async () => {
  const olderFirst = [
    { type: POLICY_TYPES[0], version: "2.0", effectiveDate: "2026-09-20", status: "published" },
    { type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-01-01", status: "published" },
  ];
  const { env, userToken } = await setup({ policyVersions: olderFirst, policyAcceptances: { u1: { [POLICY_TYPES[0]]: { version: "1.0", timestamp: 1 } } } });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403, "accepted the OLDER version by effectiveDate even though it appears first in array order -- still denied");
});

// ------------------------------------------------------------------------------------------
// 11-15: MICRO-HARDENING -- draft/published edge cases and the minimal 403 response itself
// ------------------------------------------------------------------------------------------
test("11: a DRAFT-only policy version does not require acceptance -- only 'published' counts as current", async () => {
  const draftOnly = [{ type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-09-01", status: "draft" }];
  const { env, userToken } = await setup({ policyVersions: draftOnly, policyAcceptances: {} });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200, "a draft with nothing published for that type is not required yet");
});
test("12: current published + a NEWER draft -- the draft does not force acceptance, and is never included in the 403 gate data", async () => {
  const mixed = [
    { type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-09-01", status: "published" },
    { type: POLICY_TYPES[0], version: "2.0-preview", effectiveDate: "2026-12-01", status: "draft" },
  ];
  const acc = { u1: { [POLICY_TYPES[0]]: { version: "1.0", timestamp: 1 } } };
  // leave the other POLICY_TYPES unpublished so the response is still a 403 (a different type is
  // used to trigger the denial; this test is about what that denial exposes, not this one type)
  const { env, userToken } = await setup({ policyVersions: mixed, policyAcceptances: acc });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 200, "the only published version of type[0] is already accepted, and nothing else is published, so /data/get succeeds");
  // Re-run with an additional required-but-unaccepted type present so we can inspect a real denial:
  const mixed2 = [...mixed, { type: POLICY_TYPES[1], version: "1.0", effectiveDate: "2026-09-01", status: "published" }];
  const { env: env2, userToken: token2 } = await setup({ policyVersions: mixed2, policyAcceptances: acc });
  const resp2 = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${token2}` } }), env2, {});
  assert.equal(resp2.status, 403);
  const body2 = await resp2.json();
  const versions = body2.data.policyVersions;
  assert.ok(!versions.some((v) => v.status === "draft"), "no draft-status entry ever appears in the gate response");
  assert.ok(!versions.some((v) => v.version === "2.0-preview"), "the draft preview version string itself is never exposed");
  assert.equal(versions.filter((v) => v.type === POLICY_TYPES[0]).length, 1, "exactly one (published) entry for the type that also has a draft");
});
test("13: a new version PUBLISHED after a user already accepted the old one makes the old acceptance insufficient", async () => {
  const acc = { u1: { [POLICY_TYPES[0]]: { version: "1.0", timestamp: 1 } } };
  const { env, userToken } = await setup({ policyVersions: [{ type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-01-01", status: "published" }], policyAcceptances: acc });
  const before = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(before.status, 200, "only type[0] published and accepted at its current version -- allowed");
  // Admin publishes a newer version of the SAME type -- simulate directly on the stored state,
  // the same shape handlePolicyPublish itself writes.
  env.__state.appData.policyVersions.push({ type: POLICY_TYPES[0], version: "2.0", effectiveDate: "2026-09-20", status: "published" });
  const after = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(after.status, 403, "the old accepted version is no longer current -- must accept again");
});
test("14: forged policyVersions in the /data/save request body cannot satisfy or influence the gate", async () => {
  const { env, userToken } = await setup({ policyAcceptances: {} });
  // Attacker submits a body claiming nothing is published at all, hoping to slip past the gate.
  const forgedJson = JSON.stringify({ policyVersions: [] });
  const resp = await worker.fetch(req("/data/save", { body: { json: forgedJson }, headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403, "the gate is evaluated against the server's stored policyVersions, never the submitted body");
  assert.equal((await resp.json()).error.code, "POLICY_ACCEPTANCE_REQUIRED");
  assert.deepEqual(env.__state.appData.policyVersions, PUBLISHED, "the forged policyVersions was never written to storage either");
});
test("15: the 403 response never includes users/shared/perUser/business records or another user's acceptance, and carries enough for the gate", async () => {
  const { env, userToken } = await setup({ policyAcceptances: { sa1: acceptedAll("sa1").sa1 } });
  const resp = await worker.fetch(req("/data/get", { headers: { Authorization: `Bearer ${userToken}` } }), env, {});
  assert.equal(resp.status, 403);
  const body = await resp.json();
  assert.deepEqual(Object.keys(body.data).sort(), ["policyAcceptances", "policyVersions"]);
  assert.deepEqual(Object.keys(body.data.policyAcceptances), ["u1"], "never another user's (sa1's) acceptance record");
  assert.equal(body.data.policyVersions.length, POLICY_TYPES.length, "one entry per policy type -- enough for the gate to render every row");
  assert.ok(body.data.policyVersions.every((v) => v.status === "published"), "every entry sent is the current published one");
});

// ------------------------------------------------------------------------------------------
// Pure-function unit coverage of hasAcceptedAllCurrentPolicies itself
// ------------------------------------------------------------------------------------------
test("hasAcceptedAllCurrentPolicies: pure-function cases", () => {
  assert.equal(hasAcceptedAllCurrentPolicies({ policyVersions: [], policyAcceptances: {} }, "u1"), true);
  assert.equal(hasAcceptedAllCurrentPolicies({ policyVersions: PUBLISHED, policyAcceptances: {} }, "u1"), false);
  assert.equal(hasAcceptedAllCurrentPolicies({ policyVersions: PUBLISHED, policyAcceptances: acceptedAll("u1") }, "u1"), true);
  assert.equal(hasAcceptedAllCurrentPolicies({ policyVersions: PUBLISHED, policyAcceptances: acceptedAll("u2") }, "u1"), false, "someone else's acceptance doesn't count");
});
test("currentPublishedPolicySummary: pure-function cases", () => {
  assert.deepEqual(currentPublishedPolicySummary([]), [], "nothing published -> empty summary");
  assert.deepEqual(currentPublishedPolicySummary(PUBLISHED).map((p) => p.status), PUBLISHED.map(() => "published"));
  const draftOnly = [{ type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-01-01", status: "draft" }];
  assert.deepEqual(currentPublishedPolicySummary(draftOnly), [], "a draft-only entry is never included");
  const mixed = [
    { type: POLICY_TYPES[0], version: "1.0", effectiveDate: "2026-01-01", status: "published" },
    { type: POLICY_TYPES[0], version: "2.0-preview", effectiveDate: "2026-12-01", status: "draft" },
  ];
  const summary = currentPublishedPolicySummary(mixed);
  assert.equal(summary.length, 1);
  assert.equal(summary[0].version, "1.0", "only the published entry, never the newer draft");
});
