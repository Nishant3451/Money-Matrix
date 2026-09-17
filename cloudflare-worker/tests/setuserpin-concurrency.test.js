// ============================================================================================
// PHASE 8 HARDENING ITEM #6 -- /user/setPin appData.users concurrency.
//
// Proves the lost-update race described in login-worker.js's writeUsersFieldWithRetry doc
// comment is closed: two admins creating two DIFFERENT new accounts within the same request
// window must both survive in appData.users, not have the second write silently clobber the
// first's addition. Mirrors data-save-concurrency.test.js's gated-fake-Firestore approach (a
// deterministic, real interleaving -- not a timing guess) but drives it through /user/setPin's
// "create" op, and additionally mocks moneymatrix/credentials + identitytoolkit.googleapis.com
// since setUserPin (unlike /data/save) also touches those.
//
// Before the Phase 8 fix, handleSetUserPin captured a single `appData` read at the top of the
// handler and, for create/update-role/delete, wrote that SAME stale object back later via a
// plain, unconditioned writeAppData() -- so the second writer's stale copy would blindly
// overwrite the first writer's already-landed appData.users change. This test fails against that
// old code (dave's create would vanish) and passes against the fix (both land).
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto, generateKeyPairSync } from "node:crypto";
import { encodeFirestoreFields } from "../lib/googleFirestore.js";
import worker from "../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

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

/** Same shape as data-save-concurrency.test.js's gated fetch, extended to also serve
 * moneymatrix/credentials, moneymatrix/meta, and identitytoolkit.googleapis.com -- everything
 * handleSetUserPin's "create" path touches. Only the moneymatrix/appData document is
 * version-gated (that's the document under test); credentials/identity calls always succeed. */
function makeGatedEnvFetch({ jwk }) {
  const state = {
    appData: { users: [], profiles: {}, perUser: {} },
    version: "v0",
    credentials: {},
    identityCalls: [],
  };
  let versionCounter = 0;
  let patchCount = 0;
  let conflictCount = 0;
  let armed = false;
  let releaseGate = null;
  let gateHit = null;

  const fetchImpl = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    let body = null;
    if (init?.body) {
      try { body = JSON.parse(init.body); } catch (e) { body = null; }
    }

    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }

    if (u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(
          JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(state.appData) }), updateTime: state.version }),
          { status: 200 }
        );
      }
      if (method === "PATCH") {
        patchCount += 1;
        if (armed && patchCount === 1) {
          armed = false;
          gateHit.resolveHit();
          await new Promise((resolve) => { releaseGate = resolve; });
        }
        const parsedUrl = new URL(u, "https://firestore.googleapis.com");
        const expected = parsedUrl.searchParams.get("currentDocument.updateTime");
        if (expected && expected !== state.version) {
          conflictCount += 1;
          return new Response(
            JSON.stringify({ error: { code: 400, message: "stale updateTime", status: "FAILED_PRECONDITION" } }),
            { status: 400 }
          );
        }
        state.appData = JSON.parse(body.fields.json.stringValue);
        versionCounter += 1;
        state.version = `v${versionCounter}`;
        return new Response(JSON.stringify({ updateTime: state.version }), { status: 200 });
      }
    }

    if (u.includes("moneymatrix/credentials")) {
      if (method === "GET") {
        return new Response(JSON.stringify({ fields: encodeFirestoreFields(state.credentials) }), { status: 200 });
      }
      if (method === "PATCH") {
        const maskFields = (u.match(/updateMask\.fieldPaths=([^&]+)/g) || []).map((m) => decodeURIComponent(m.split("=")[1]));
        for (const f of maskFields) {
          if (body.fields && f in body.fields) state.credentials[f] = decodeFirestoreValueForTest(body.fields[f]);
          else delete state.credentials[f];
        }
        return new Response(JSON.stringify({}), { status: 200 });
      }
    }

    if (u.includes("moneymatrix/meta")) {
      return new Response(JSON.stringify({}), { status: 200 });
    }

    if (u.includes("identitytoolkit.googleapis.com")) {
      const path = u.split("/").pop();
      state.identityCalls.push({ path, body });
      if (path === "accounts:update") return new Response(JSON.stringify({}), { status: 200 });
      if (path === "accounts:signUp") return new Response(JSON.stringify({}), { status: 200 });
      if (path === "accounts:delete") return new Response(JSON.stringify({}), { status: 200 });
    }

    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };

  return {
    fetchImpl,
    state,
    get conflictCount() { return conflictCount; },
    armGateOnFirstAppDataPatch() {
      armed = true;
      gateHit = {};
      const hitPromise = new Promise((resolve) => { gateHit.resolveHit = resolve; });
      return { waitForGate: () => hitPromise, release: () => releaseGate && releaseGate() };
    },
  };
}

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) { return b64url(new TextEncoder().encode(JSON.stringify(obj))); }
async function generateSecuretokenKeyPair(kid) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = kid; publicJwk.alg = "RS256"; publicJwk.use = "sig";
  return { privateKey: keyPair.privateKey, publicJwk };
}
async function signIdToken(privateKey, uid, PROJECT_ID, kid, role) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid, typ: "JWT" };
  const payload = { iss: `https://securetoken.google.com/${PROJECT_ID}`, aud: PROJECT_ID, sub: uid, iat: now, exp: now + 3600, auth_time: now, approved: true, role };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

test("two admins creating two different new accounts at once: both survive in appData.users (no lost update)", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const kid = "test-kid-setuserpin";
  const { privateKey, publicJwk } = await generateSecuretokenKeyPair(kid);
  const { privateKey: svcKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: svcKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: { async get() { return null; }, async put() {} },
  };
  const gated = makeGatedEnvFetch({ jwk: publicJwk });
  // Seed one existing admin so the caller's own authorization lookup succeeds.
  gated.state.appData = { users: [{ id: "admin1", username: "admin1", role: "admin", linkedId: null }], profiles: {}, perUser: {} };

  globalThis.fetch = (url, init) => gated.fetchImpl(url, init);

  const adminToken = await signIdToken(privateKey, "admin1", PROJECT_ID, kid, "admin");
  function createReq(targetUserId) {
    return new Request("https://worker.example/user/setPin", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ targetUserId, newPin: "1234", role: "user" }),
    });
  }

  const gate = gated.armGateOnFirstAppDataPatch();
  // Carol's create reaches the point of committing its appData.users write (based on the
  // version it read) and pauses right there.
  const carolPromise = worker.fetch(createReq("carol"), env, {});
  await gate.waitForGate();

  // While carol is paused, dave's create runs to completion and lands first, bumping the
  // document's version -- making carol's paused precondition stale.
  const daveResp = await worker.fetch(createReq("dave"), env, {});
  assert.equal(daveResp.status, 200);
  assert.ok(gated.state.appData.users.some((u) => u.id === "dave"), "dave's create must have landed");

  // Release carol: her now-stale-precondition write must be rejected and retried -- re-read
  // (now sees dave), reapply carol's create, write again successfully, WITHOUT erasing dave.
  gate.release();
  const carolResp = await carolPromise;

  assert.equal(carolResp.status, 200, "carol's create must succeed after retrying past the conflict");
  assert.ok(gated.conflictCount >= 1, "a genuine FAILED_PRECONDITION conflict must have occurred and been handled");
  assert.ok(gated.state.appData.users.some((u) => u.id === "carol"), "carol's retried create must have landed");
  assert.ok(gated.state.appData.users.some((u) => u.id === "dave"), "dave's earlier create must STILL be present -- not clobbered by carol's retry");
  assert.equal(gated.state.appData.users.length, 3, "exactly admin1 + carol + dave -- no duplicates, nothing lost");
});

test("/user/setPin create still succeeds normally with no contention", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const kid = "test-kid-setuserpin-solo";
  const { privateKey, publicJwk } = await generateSecuretokenKeyPair(kid);
  const { privateKey: svcKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: svcKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: { async get() { return null; }, async put() {} },
  };
  const gated = makeGatedEnvFetch({ jwk: publicJwk });
  gated.state.appData = { users: [{ id: "admin1", username: "admin1", role: "admin", linkedId: null }], profiles: {}, perUser: {} };
  globalThis.fetch = (url, init) => gated.fetchImpl(url, init);

  const adminToken = await signIdToken(privateKey, "admin1", PROJECT_ID, kid, "admin");
  const resp = await worker.fetch(
    new Request("https://worker.example/user/setPin", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ targetUserId: "erin", newPin: "1234", role: "user" }),
    }),
    env, {}
  );
  assert.equal(resp.status, 200);
  assert.ok(gated.state.appData.users.some((u) => u.id === "erin"));
  assert.equal(gated.conflictCount, 0, "no contention, no conflicts expected");
});

test("admin promoting a role and a concurrent admin creating a different user both survive", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const kid = "test-kid-setuserpin-role";
  const { privateKey, publicJwk } = await generateSecuretokenKeyPair(kid);
  const { privateKey: svcKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    FIREBASE_PRIVATE_KEY: svcKey,
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: { async get() { return null; }, async put() {} },
  };
  const gated = makeGatedEnvFetch({ jwk: publicJwk });
  gated.state.appData = {
    users: [
      { id: "admin1", username: "admin1", role: "admin", linkedId: null },
      { id: "frank", username: "frank", role: "user", linkedId: null },
    ],
    profiles: {},
    perUser: {},
  };
  // frank needs an existing credentials entry: a role-only update (no newPin) reads the
  // existing hash rather than minting a new one, mirroring a real promotion via the Users screen.
  gated.state.credentials = { frank: { pinHash: "shim$10$existingsalt$existingdigest", role: "user" } };
  globalThis.fetch = (url, init) => gated.fetchImpl(url, init);

  const adminToken = await signIdToken(privateKey, "admin1", PROJECT_ID, kid, "admin");
  function req(targetUserId, extra) {
    return new Request("https://worker.example/user/setPin", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ targetUserId, ...extra }),
    });
  }

  const gate = gated.armGateOnFirstAppDataPatch();
  // Promote frank to admin -- pauses right before committing.
  const promotePromise = worker.fetch(req("frank", { role: "admin" }), env, {});
  await gate.waitForGate();

  // A different admin creates a brand-new user "grace" while the promotion is paused.
  const graceResp = await worker.fetch(req("grace", { newPin: "1234", role: "user" }), env, {});
  assert.equal(graceResp.status, 200);

  gate.release();
  const promoteResp = await promotePromise;
  assert.equal(promoteResp.status, 200);

  const users = gated.state.appData.users;
  const frank = users.find((u) => u.id === "frank");
  const grace = users.find((u) => u.id === "grace");
  assert.ok(frank, "frank must still exist");
  assert.equal(frank.role, "admin", "frank's promotion must not have been silently lost");
  assert.ok(grace, "grace's concurrent create must not have been silently lost");
});
