// ============================================================================================
// PHASE 5 AUDIT ITEM #18 -- /data/save concurrency.
//
// Proves the lost-update race that PART-B-HARDENING-REPORT.md §14 explicitly disclosed as a
// known, un-fixed limitation ("handleDataSave ... retain[s] [its] previously-disclosed
// read-then-write race") is now closed: handleDataSave was changed from a plain read-then-write
// to the same optimistic-concurrency retry loop (readAppDataWithVersion / writeAppDataIfUnchanged
// / retry-on-conflict) that runPrivacyMutation already used for /privacy/*. This file mirrors
// cloudflare-worker/tests/privacy-concurrency.test.js's Layer-2 approach (a gated fake Firestore
// that deterministically forces a genuine interleaving) but drives it through /data/save instead.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { encodeFirestoreFields } from "../lib/googleFirestore.js";
import worker from "../login-worker.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function makeVersionedFirestoreFetch() {
  const state = { doc: {}, version: "v0" };
  let versionCounter = 0;
  const fetchImpl = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    if (u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(
          JSON.stringify({ fields: encodeFirestoreFields({ json: JSON.stringify(state.doc) }), updateTime: state.version }),
          { status: 200 }
        );
      }
      if (method === "PATCH") {
        const parsedUrl = new URL(u, "https://firestore.googleapis.com");
        const expected = parsedUrl.searchParams.get("currentDocument.updateTime");
        if (expected && expected !== state.version) {
          return new Response(
            JSON.stringify({ error: { code: 400, message: "stale updateTime", status: "FAILED_PRECONDITION" } }),
            { status: 400 }
          );
        }
        const body = JSON.parse(init.body);
        state.doc = JSON.parse(body.fields.json.stringValue);
        versionCounter += 1;
        state.version = `v${versionCounter}`;
        return new Response(JSON.stringify({ updateTime: state.version }), { status: 200 });
      }
    }
    if (u.includes("moneymatrix/meta")) return new Response(JSON.stringify({}), { status: 200 });
    throw new Error(`Unmocked fetch: ${method} ${u}`);
  };
  return { fetchImpl, state };
}

function makeGatedVersionedFirestoreFetch() {
  const { fetchImpl, state } = makeVersionedFirestoreFetch();
  let patchCount = 0;
  let conflictCount = 0;
  let armed = false;
  let releaseGate = null;
  let gateHit = null;
  const gatedFetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";
    if (u.includes("moneymatrix/appData") && method === "PATCH") {
      patchCount += 1;
      if (armed && patchCount === 1) {
        armed = false;
        gateHit.resolveHit();
        await new Promise((resolve) => { releaseGate = resolve; });
      }
    }
    const resp = await fetchImpl(url, init);
    if (u.includes("moneymatrix/appData") && method === "PATCH" && resp.status === 400) conflictCount += 1;
    return resp;
  };
  return {
    fetchImpl: gatedFetch,
    state,
    get conflictCount() { return conflictCount; },
    armGateOnFirstPatch() {
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
async function signIdToken(privateKey, uid, PROJECT_ID, kid, role = "admin") {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid, typ: "JWT" };
  const payload = { iss: `https://securetoken.google.com/${PROJECT_ID}`, aud: PROJECT_ID, sub: uid, iat: now, exp: now + 3600, auth_time: now, approved: true, role };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

test("a /data/save that loses the precondition race is retried and does not clobber a concurrent save", async () => {
  // Uses two non-privileged ("user") callers, each saving only their OWN perUser bucket -- this
  // is the realistic contention case the fix targets: mergeAuthorizedSave's scoped branch merges
  // per-uid (`perUser[uid]`), so two different users' concurrent saves are app-level compatible
  // and SHOULD both survive once the Firestore-level lost-update race is closed. (A full-access
  // admin's save is intentionally "apply whole section as-is" per authorization.js's own
  // comment, so two admins racing on the SAME section is a separate, pre-existing app-level
  // behavior this fix does not change or claim to -- see the audit report.)
  const PROJECT_ID = "money-metrix-9f1da";
  const kid = "test-kid-datasave";
  const { privateKey, publicJwk } = await generateSecuretokenKeyPair(kid);
  const { generateKeyPairSync } = await import("node:crypto");
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
  const gated = makeGatedVersionedFirestoreFetch();
  gated.state.doc = {
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
    perUser: {},
  };

  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
    }
    return gated.fetchImpl(url, init);
  };

  const aliceToken = await signIdToken(privateKey, "alice", PROJECT_ID, kid, "user");
  const bobToken = await signIdToken(privateKey, "bob", PROJECT_ID, kid, "user");
  function req(uid, note, token) {
    return new Request("https://worker.example/data/save", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ json: JSON.stringify({ perUser: { [uid]: { custom: { note } } } }) }),
    });
  }

  const gate = gated.armGateOnFirstPatch();
  // Alice's save (only her own perUser bucket) reaches the gate right as it's about to commit
  // based on the version it originally read, and pauses there.
  const alicePromise = worker.fetch(req("alice", "alice-new", aliceToken), env, {});
  await gate.waitForGate();

  // While alice is paused, bob's save (only his own bucket) runs to completion -- it lands and
  // bumps the document's version, making alice's paused precondition stale.
  const bobResp = await worker.fetch(req("bob", "bob-new", bobToken), env, {});
  assert.equal(bobResp.status, 200);
  assert.equal(gated.state.doc.perUser.bob?.custom?.note, "bob-new", "bob's write must have landed");

  // Release alice: her now-stale-precondition write must be rejected by the fake Firestore and
  // trigger handleDataSave's retry loop -- re-read (now sees bob's change), reapply alice's
  // save, write again successfully, WITHOUT clobbering bob's already-landed change.
  gate.release();
  const aliceResp = await alicePromise;

  assert.equal(aliceResp.status, 200, "alice's save must succeed after retrying past the conflict");
  assert.ok(gated.conflictCount >= 1, "a genuine FAILED_PRECONDITION conflict must have occurred and been handled");
  assert.equal(gated.state.doc.perUser.alice?.custom?.note, "alice-new", "alice's retried save must have landed");
  assert.equal(gated.state.doc.perUser.bob?.custom?.note, "bob-new", "bob's earlier save must STILL be present -- not clobbered by alice's retry");
});

test("/data/save still succeeds normally (single writer, no contention)", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const kid = "test-kid-datasave-solo";
  const { privateKey, publicJwk } = await generateSecuretokenKeyPair(kid);
  const { generateKeyPairSync } = await import("node:crypto");
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
  const { fetchImpl, state } = makeVersionedFirestoreFetch();
  state.doc = { users: [{ id: "alice", username: "alice", role: "admin", linkedId: null }], settings: {} };

  globalThis.fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    if (u === "https://oauth2.googleapis.com/token") {
      return new Response(JSON.stringify({ access_token: "fake-token", expires_in: 3600 }), { status: 200 });
    }
    if (u === "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com") {
      return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
    }
    return fetchImpl(url, init);
  };

  const aliceToken = await signIdToken(privateKey, "alice", PROJECT_ID, kid);
  const resp = await worker.fetch(
    new Request("https://worker.example/data/save", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${aliceToken}` },
      body: JSON.stringify({ json: JSON.stringify({ users: state.doc.users, settings: { hello: "world" } }) }),
    }),
    env, {}
  );
  assert.equal(resp.status, 200);
  assert.equal(state.doc.settings.hello, "world");
});
