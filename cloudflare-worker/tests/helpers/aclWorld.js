// Shared harness for the record-ACL Worker tests: real Worker + fake versioned Firestore + real Firebase-style ID tokens.
// (Lives in helpers/ so node --test's *.test.js glob does not treat it as a test file.)
import assert from "node:assert/strict";
import { webcrypto, generateKeyPairSync } from "node:crypto";
import { encodeFirestoreFields } from "../../lib/googleFirestore.js";
import { resolveDataScope } from "../../lib/authorization.js";
import worker from "../../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const PROJECT_ID = "money-metrix-9f1da";
const KID = "acl-test-kid";
const ORIGIN = "https://nishant3451.github.io";
export { worker, ORIGIN };

const b64url = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const b64urlJson = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
publicJwk.kid = KID; publicJwk.alg = "RS256"; publicJwk.use = "sig";
const { privateKey: svcKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
async function signIdToken(uid, role) {
  const now = Math.floor(Date.now() / 1000);
  const input = `${b64urlJson({ alg: "RS256", kid: KID, typ: "JWT" })}.${b64urlJson({ iss: `https://securetoken.google.com/${PROJECT_ID}`, aud: PROJECT_ID, sub: uid, iat: now, exp: now + 3600, auth_time: now, approved: true, role })}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, kp.privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

// ---------- fixture ----------
export const clone = (x) => JSON.parse(JSON.stringify(x));
export const SUPS = [
  { id: "n_top", supervisorId: null }, { id: "n_mid", supervisorId: "n_top" },
  { id: "n_low", supervisorId: "n_mid" }, { id: "n_peer", supervisorId: "n_top" },
];
export const USERS = [
  { id: "root", username: "root", role: "superadmin", linkedId: null },
  { id: "top", username: "top", role: "admin", linkedId: "n_top" },
  { id: "mid", username: "mid", role: "admin", linkedId: "n_mid" },
  { id: "low", username: "low", role: "user", linkedId: "n_low" },
  { id: "peer", username: "peer", role: "user", linkedId: "n_peer" },
];
export const MAX_SCOPE = { root: "all", top: "mine_downline", mid: "mine_upline_downline", low: "mine_upline", peer: "mine_upline" };
export const rec = (id, ownerId, extra = {}) => ({ id, ownerId, customer: `cust-${id}`, amount: 100, ...extra });
export const g = (uid, ...perms) => ({ uid, perms: ["view", ...perms] });
export const acl = (rev, grants) => ({ rev, grants });
export const find = (arr, id) => (arr || []).find((r) => r.id === id);

export function makeDoc({ tx = [], q = [], perUser = {}, activityLog = [], extra = {}, users = USERS, sups = SUPS, permissions = { user: { marathon: "write", quotations: "write" } } } = {}) {
  return {
    users: clone(users), permissions, userPermissions: {}, profiles: {}, settings: {},
    shared: { supervisors: clone(sups), members: [], coaches: [], transactions: clone(tx), quotations: clone(q) },
    perUser: clone(perUser), activityLog: clone(activityLog), ...extra,
  };
}

/** A Worker + fake Firestore (versioned, with precondition) for one test. */
export function makeWorld(initial, { kv = true } = {}) {
  const state = { doc: initial, version: "v0", n: 0 };
  const world = { state, beforePatch: null, patchCount: 0, conflicts: 0 };
  world.env = { FIREBASE_PROJECT_ID: PROJECT_ID, FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com", FIREBASE_PRIVATE_KEY: svcKey, ALLOWED_ORIGIN: ORIGIN };
  if (kv) world.env.RATE_LIMIT_KV = { async get() { return null; }, async put() {} };
  world.install = () => {
    globalThis.fetch = async (url, init) => {
      const u = typeof url === "string" ? url : url.url;
      const method = init?.method || "GET";
      if (u === "https://oauth2.googleapis.com/token") return new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }), { status: 200 });
      if (u.startsWith("https://www.googleapis.com/service_accounts/v1/jwk/")) return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
      if (u.includes("moneymatrix/appData")) {
        if (method === "GET") return new Response(JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(state.doc) }), updateTime: state.version }), { status: 200 });
        if (method === "PATCH") {
          world.patchCount += 1;
          if (world.beforePatch) { const h = world.beforePatch; world.beforePatch = null; await h(); }
          const expected = new URL(u, "https://firestore.googleapis.com").searchParams.get("currentDocument.updateTime");
          if (expected && expected !== state.version) { world.conflicts += 1; return new Response(JSON.stringify({ error: { code: 400, status: "FAILED_PRECONDITION" } }), { status: 400 }); }
          state.doc = JSON.parse(JSON.parse(init.body).fields.json.stringValue);
          state.n += 1; state.version = `v${state.n}`;
          return new Response(JSON.stringify({ updateTime: state.version }), { status: 200 });
        }
      }
      if (u.includes("moneymatrix/meta")) return new Response("{}", { status: 200 });
      throw new Error(`Unmocked fetch: ${method} ${u}`);
    };
  };
  world.install();
  return world;
}

export async function call(world, uid, path, body, { tokenRole, raw, headers } = {}) {
  world.install(); // another world may have replaced globalThis.fetch
  const stored = world.state.doc.users.find((u) => u.id === uid);
  const token = await signIdToken(uid, tokenRole ?? (stored ? stored.role : "user"));
  const req = new Request(`https://worker.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, Authorization: `Bearer ${token}`, ...(headers || {}) },
    body: raw !== undefined ? raw : JSON.stringify(body ?? {}),
  });
  const res = await worker.fetch(req, world.env, {});
  let json = null;
  try { json = await res.json(); } catch { /* empty */ }
  return { status: res.status, json };
}
export const getView = async (world, uid, scope) => {
  const u = world.state.doc.users.find((x) => x.id === uid);
  const widest = u ? resolveDataScope(world.state.doc, { uid, role: u.role, linkedId: u.linkedId || null }).maxScope : undefined;
  const r = await call(world, uid, "/data/get", { scope: scope ?? MAX_SCOPE[uid] ?? widest });
  assert.equal(r.status, 200, `data/get as ${uid}: ${JSON.stringify(r.json)}`);
  return JSON.parse(r.json.data.json);
};
/** Client behaviour: load the view, edit it, POST the whole blob back. */
export async function save(world, uid, edit) {
  const v = await getView(world, uid);
  edit(v);
  return call(world, uid, "/data/save", { json: JSON.stringify(v) });
}
export const setAcl = (world, uid, body) => call(world, uid, "/record/acl", { collection: "transactions", bucket: null, ...body });
export const stored = (world, id, coll = "transactions") => find(world.state.doc.shared[coll], id);
