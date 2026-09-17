// ============================================================================================
// Tests for checkAndReserveRateLimit (cloudflare-worker/lib/privacy.js) -- HARDENING ISSUE #3.
//
// Covers the five scenarios called out in the hardening brief:
//   A. KV available, under the cap            -> allowed
//   B. limit reached                          -> not allowed (no misconfigured flag)
//   C. KV unavailable/misconfigured            -> FAILS CLOSED (not allowed, misconfigured: true)
//   D. authenticated user behavior              -> same uid across calls shares one bucket
//   E. different users have independent limits  -> one user's cap does not affect another's
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { checkAndReserveRateLimit } from "../lib/privacy.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

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

test("A. KV available: requests under the cap are allowed and not flagged misconfigured", async () => {
  const env = { RATE_LIMIT_KV: makeFakeKv() };
  const r1 = await checkAndReserveRateLimit(env, "request_create", "alice", 3, 60_000);
  assert.equal(r1.allowed, true);
  assert.equal(r1.misconfigured, undefined);
});

test("B. limit reached: the (cap+1)th request in the window is rejected", async () => {
  const env = { RATE_LIMIT_KV: makeFakeKv() };
  for (let i = 0; i < 3; i++) {
    const r = await checkAndReserveRateLimit(env, "request_create", "bob", 3, 60_000);
    assert.equal(r.allowed, true, `attempt ${i + 1} should be allowed`);
  }
  const blocked = await checkAndReserveRateLimit(env, "request_create", "bob", 3, 60_000);
  assert.equal(blocked.allowed, false);
});

test("C. KV unavailable/misconfigured: fails CLOSED, not open", async () => {
  const env = {}; // no RATE_LIMIT_KV binding at all -- the exact misconfiguration the brief describes
  const r = await checkAndReserveRateLimit(env, "request_create", "carol", 3, 60_000);
  assert.equal(r.allowed, false, "a missing KV binding must never silently allow unlimited privacy requests");
  assert.equal(r.misconfigured, true, "the misconfiguration must be detectable by the caller");
});

test("D. authenticated user behavior: repeated calls for the same uid share one bucket", async () => {
  const env = { RATE_LIMIT_KV: makeFakeKv() };
  const r1 = await checkAndReserveRateLimit(env, "export", "dave", 2, 60_000);
  const r2 = await checkAndReserveRateLimit(env, "export", "dave", 2, 60_000);
  const r3 = await checkAndReserveRateLimit(env, "export", "dave", 2, 60_000);
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(r3.allowed, false, "the same uid's third call within the window must be blocked");
});

test("E. different users have independent limits", async () => {
  const env = { RATE_LIMIT_KV: makeFakeKv() };
  for (let i = 0; i < 2; i++) {
    const r = await checkAndReserveRateLimit(env, "export", "erin", 2, 60_000);
    assert.equal(r.allowed, true);
  }
  const erinBlocked = await checkAndReserveRateLimit(env, "export", "erin", 2, 60_000);
  assert.equal(erinBlocked.allowed, false, "erin should now be capped");

  // frank must NOT be affected by erin's usage of the same kind/window.
  const frank = await checkAndReserveRateLimit(env, "export", "frank", 2, 60_000);
  assert.equal(frank.allowed, true, "a different uid must have its own independent bucket");
});

test("window reset: a new window after windowMs has elapsed allows requests again", async () => {
  const env = { RATE_LIMIT_KV: makeFakeKv() };
  const r1 = await checkAndReserveRateLimit(env, "request_create", "gary", 1, 10);
  assert.equal(r1.allowed, true);
  const blocked = await checkAndReserveRateLimit(env, "request_create", "gary", 1, 10);
  assert.equal(blocked.allowed, false);
  await new Promise((res) => setTimeout(res, 25));
  const afterReset = await checkAndReserveRateLimit(env, "request_create", "gary", 1, 10);
  assert.equal(afterReset.allowed, true, "a new window should allow requests again");
});
