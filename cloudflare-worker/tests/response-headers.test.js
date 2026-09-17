// ============================================================================================
// PHASE 8 HARDENING ITEM #2 -- safe response headers on every JSON response.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../login-worker.js";

test("every response (even a plain 400) carries X-Content-Type-Options, Referrer-Policy, and Cache-Control: no-store", async () => {
  const env = { ALLOWED_ORIGIN: "https://nishant3451.github.io" };
  globalThis.fetch = async () => { throw new Error("should not be called for a malformed /login body"); };
  const resp = await worker.fetch(
    new Request("https://worker.example/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://nishant3451.github.io" },
      body: "not json",
    }),
    env, {}
  );
  assert.equal(resp.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(resp.headers.get("Referrer-Policy"), "no-referrer");
  assert.equal(resp.headers.get("Cache-Control"), "no-store");
});
