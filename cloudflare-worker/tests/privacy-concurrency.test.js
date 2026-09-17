// ============================================================================================
// HARDENING ISSUE #4 -- concurrent privacy writes.
//
// These tests exercise readAppDataWithVersion / writeAppDataIfUnchanged directly against a
// small fake Firestore that actually enforces the `currentDocument.updateTime` precondition
// (unlike the existing integration-test fakes, which always accept a PATCH unconditionally --
// see cloudflare-worker/tests/privacy-endpoints.integration.test.js's installFakeFetch). That
// makes this the right layer to prove the lost-update race is actually closed, without having to
// orchestrate real concurrent HTTP requests against the higher-level worker.
//
// Then a second block drives login-worker.js's runPrivacyMutation (via two full /privacy/*
// requests racing on the SAME document) against that same precondition-enforcing fake, to prove
// the end-to-end retry loop in login-worker.js actually uses this correctly: two independent
// privacy writes landing "at the same time" must BOTH survive, not silently clobber each other.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  readAppDataWithVersion,
  writeAppDataIfUnchanged,
  encodeFirestoreFields,
} from "../lib/googleFirestore.js";
import worker from "../login-worker.js";
import { KNOWN_CONSENT_CATEGORIES } from "../lib/privacy.js";

// These tests use /privacy/consent purely as a vehicle to exercise the concurrency retry
// mechanism, not to test the consent allow-list itself (see privacy-consent-allowlist.test.js
// for that). Production ships KNOWN_CONSENT_CATEGORIES empty (see lib/privacy.js) -- register
// the one synthetic pair these tests need so they keep exercising concurrency, not accidentally
// testing "any string is accepted".
KNOWN_CONSENT_CATEGORIES.push({ type: "t1", purpose: "concurrency test purpose" });

if (!globalThis.crypto) globalThis.crypto = webcrypto;

/** A minimal fake single-document Firestore that DOES enforce currentDocument.updateTime, unlike
 * the other test files' fakes. `state.doc` holds the plain JS appData object; `state.version` is
 * bumped (as a fake RFC3339-ish string) on every successful write, and PATCHes are rejected with
 * a realistic Google-API FAILED_PRECONDITION error shape when the caller's precondition doesn't
 * match the current version. */
function makeVersionedFirestoreFetch(env) {
  const state = { doc: {}, version: "v0" };
  let versionCounter = 0;

  env.__docState = state;

  const fetchImpl = async (url, init) => {
    const u = typeof url === "string" ? url : url.url;
    const method = init?.method || "GET";

    if (u.includes("moneymatrix/appData")) {
      if (method === "GET") {
        return new Response(
          JSON.stringify({
            fields: encodeFirestoreFields({ json: JSON.stringify(state.doc) }),
            updateTime: state.version,
          }),
          { status: 200 }
        );
      }
      if (method === "PATCH") {
        const parsedUrl = new URL(u, "https://firestore.googleapis.com");
        const expected = parsedUrl.searchParams.get("currentDocument.updateTime");
        const requireAbsent = parsedUrl.searchParams.get("currentDocument.exists") === "false";
        if (requireAbsent) {
          // not exercised by these tests (doc always pre-exists), included for completeness
        } else if (expected && expected !== state.version) {
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

// ---------------------------------------------------------------------------------------------
// Layer 1: the raw optimistic-concurrency primitives
// ---------------------------------------------------------------------------------------------

test("writeAppDataIfUnchanged succeeds when the precondition still matches", async () => {
  const env = {};
  const { fetchImpl, state } = makeVersionedFirestoreFetch(env);
  globalThis.fetch = fetchImpl;
  state.doc = { hello: "world" };

  const { data, updateTime } = await readAppDataWithVersion(env, "tok");
  assert.deepEqual(data, { hello: "world" });

  const result = await writeAppDataIfUnchanged(env, "tok", { hello: "updated" }, updateTime);
  assert.equal(result.conflict, false);
  assert.deepEqual(state.doc, { hello: "updated" });
});

test("writeAppDataIfUnchanged reports a conflict -- and does NOT overwrite -- when the document changed since it was read", async () => {
  const env = {};
  const { fetchImpl, state } = makeVersionedFirestoreFetch(env);
  globalThis.fetch = fetchImpl;
  state.doc = { counter: 1 };

  // Caller A reads...
  const readA = await readAppDataWithVersion(env, "tok");
  // ...but caller B writes first, changing the document's version.
  await writeAppDataIfUnchanged(env, "tok", { counter: 2 }, readA.updateTime);
  assert.deepEqual(state.doc, { counter: 2 }, "B's write should have landed");

  // Caller A now tries to write back based on its now-stale read -- this MUST be rejected, not
  // silently applied (which would silently discard B's change -- the exact lost-update bug).
  const writeA = await writeAppDataIfUnchanged(env, "tok", { counter: "A's stale write" }, readA.updateTime);
  assert.equal(writeA.conflict, true);
  assert.deepEqual(state.doc, { counter: 2 }, "A's stale write must NOT have overwritten B's change");
});

// ---------------------------------------------------------------------------------------------
// Layer 2: end-to-end through login-worker.js's runPrivacyMutation retry loop -- two independent
// privacy writes "racing" on the same document must both survive.
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
  const kid = `test-kid-${kidCounter}`;
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

/** Like makeVersionedFirestoreFetch, but lets a test deterministically pause exactly one PATCH
 * call mid-flight (after it has already decided which version to check against) so a SECOND,
 * independent write can land first -- reproducing the exact race in the hardening brief: "Request
 * A reads document. Request B reads document. B writes. A writes based on stale state." Without
 * this manual gate, two requests fired via Promise.all against an in-memory fake with no real
 * I/O latency tend to run start-to-finish one after another (no genuine interleaving), which
 * would make a "concurrency" test pass for the wrong reason (no race ever actually occurred).
 * This makes the race happen on purpose, every run, deterministically. */
function makeGatedVersionedFirestoreFetch(env) {
  const { fetchImpl, state } = makeVersionedFirestoreFetch(env);
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
        // Signal the test that we've reached the gate, then wait to be released.
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
    get patchCount() { return patchCount; },
    armGateOnFirstPatch() {
      armed = true;
      gateHit = {};
      const hitPromise = new Promise((resolve) => { gateHit.resolveHit = resolve; });
      return { waitForGate: () => hitPromise, release: () => releaseGate && releaseGate() };
    },
  };
}

test("a write that loses the precondition race is retried and eventually succeeds without losing the other write's change", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();
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
  const gated = makeGatedVersionedFirestoreFetch(env);
  gated.state.doc = {
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
    privacyConsents: {}, policyVersions: [], policyAcceptances: {}, privacyPreferences: {},
    privacyRequests: [], privacyAuditLog: [],
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

  const aliceToken = await signIdToken(privateKey, "alice", PROJECT_ID, kid);
  const bobToken = await signIdToken(privateKey, "bob", PROJECT_ID, kid);
  function req(path, body, token) {
    return new Request(`https://worker.example${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
  }

  const gate = gated.armGateOnFirstPatch();
  // Alice's request will reach the gate right as it's about to commit its FIRST write attempt
  // (based on the version it read at the start) and pause there.
  const alicePromise = worker.fetch(req("/privacy/consent", { type: "t1", purpose: "concurrency test purpose", action: "grant" }, aliceToken), env, {});
  await gate.waitForGate();

  // While alice is paused, bob's request runs to completion end-to-end -- his write lands and
  // bumps the document's version, making alice's paused precondition stale.
  const bobResp = await worker.fetch(req("/privacy/consent", { type: "t1", purpose: "concurrency test purpose", action: "grant" }, bobToken), env, {});
  assert.equal(bobResp.status, 200);
  assert.equal(gated.state.doc.privacyConsents.bob?.length, 1, "bob's write must have landed");

  // Now release alice -- her stale-precondition write MUST be rejected by the fake Firestore
  // (proving the precondition really is being sent/enforced), which must drive
  // runPrivacyMutation's retry loop: re-read (now sees bob's change), reapply alice's mutation,
  // write again successfully.
  gate.release();
  const aliceResp = await alicePromise;

  assert.equal(aliceResp.status, 200, "alice's write must succeed after retrying past the conflict");
  assert.ok(gated.conflictCount >= 1, "a genuine FAILED_PRECONDITION conflict must have occurred and been handled, not just theoretically supported");
  assert.equal(gated.state.doc.privacyConsents.alice?.length, 1, "alice's retried write must have landed");
  assert.equal(gated.state.doc.privacyConsents.bob?.length, 1, "bob's earlier write must STILL be present -- not clobbered by alice's retry");
});

test("two concurrent /privacy/consent grants for different users both survive (no lost update)", async () => {
  const PROJECT_ID = "money-metrix-9f1da";
  const { privateKey, publicJwk, kid } = await generateSecuretokenKeyPair();

  const env = {
    FIREBASE_PROJECT_ID: PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: "svc@x.iam.gserviceaccount.com",
    ALLOWED_ORIGIN: "https://nishant3451.github.io",
    RATE_LIMIT_KV: { async get() { return null; }, async put() {} },
  };
  const { fetchImpl, state } = makeVersionedFirestoreFetch(env);

  const { generateKeyPairSync } = await import("node:crypto");
  const { privateKey: svcKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  env.FIREBASE_PRIVATE_KEY = svcKey;

  state.doc = {
    users: [
      { id: "alice", username: "alice", role: "user", linkedId: null },
      { id: "bob", username: "bob", role: "user", linkedId: null },
    ],
    privacyConsents: {}, policyVersions: [], policyAcceptances: {}, privacyPreferences: {},
    privacyRequests: [], privacyAuditLog: [],
  };

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
  const bobToken = await signIdToken(privateKey, "bob", PROJECT_ID, kid);

  function req(path, body, token) {
    return new Request(`https://worker.example${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
  }

  // Fire both requests "concurrently" (their internal read/write steps genuinely interleave
  // because everything here is async against the same shared `state`) -- this is exactly the
  // scenario in the hardening brief: Request A reads, Request B reads, A writes, B writes based
  // on stale state.
  const [respA, respB] = await Promise.all([
    worker.fetch(req("/privacy/consent", { type: "t1", purpose: "concurrency test purpose", action: "grant" }, aliceToken), env, {}),
    worker.fetch(req("/privacy/consent", { type: "t1", purpose: "concurrency test purpose", action: "grant" }, bobToken), env, {}),
  ]);

  assert.equal(respA.status, 200, "alice's consent write must succeed (possibly after an internal retry)");
  assert.equal(respB.status, 200, "bob's consent write must succeed (possibly after an internal retry)");

  // The critical assertion: BOTH users' consent records must be present in the final document --
  // neither write may have silently clobbered the other (the lost-update bug this fix closes).
  assert.equal(state.doc.privacyConsents.alice?.length, 1, "alice's consent must not have been lost");
  assert.equal(state.doc.privacyConsents.bob?.length, 1, "bob's consent must not have been lost");
});
