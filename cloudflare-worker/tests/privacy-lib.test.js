import test from "node:test";
import assert from "node:assert/strict";
import {
  csvSafeField,
  toCsv,
  sanitizeText,
  isNonEmptyString,
  isValidStatusTransition,
  appendAudit,
  findPublishedPolicy,
  latestPublishedPolicy,
  getUserRequests,
  genId,
} from "../lib/privacy.js";

// ---- CSV / spreadsheet formula injection (task brief section 24) ----

test("csvSafeField neutralizes classic formula-injection leads", () => {
  assert.equal(csvSafeField("=cmd(|'/C calc'!A0)"), "'=cmd(|'/C calc'!A0)");
  assert.equal(csvSafeField("+123"), "'+123");
  assert.equal(csvSafeField("-123"), "'-123");
  assert.equal(csvSafeField("@SUM(A1:A2)"), "'@SUM(A1:A2)");
  assert.equal(csvSafeField("\tevil"), "'\tevil");
});

test("csvSafeField does not corrupt ordinary values", () => {
  assert.equal(csvSafeField("Rahul Patel"), "Rahul Patel");
  assert.equal(csvSafeField(42), "42");
  assert.equal(csvSafeField(null), "");
  assert.equal(csvSafeField(undefined), "");
});

test("csvSafeField quotes fields containing commas/quotes/newlines", () => {
  assert.equal(csvSafeField('Hello, "World"'), '"Hello, ""World"""');
  assert.equal(csvSafeField("line1\nline2"), '"line1\nline2"');
});

test("toCsv produces a safe header+rows string and never lets a value become a formula", () => {
  const csv = toCsv(
    [{ name: "=2+2", note: "ok" }],
    ["name", "note"]
  );
  assert.ok(csv.startsWith("name,note\r\n"));
  assert.ok(csv.includes("'=2+2"));
});

// ---- sanitizeText / isNonEmptyString ----

test("sanitizeText trims and caps length, and never throws on bad input", () => {
  assert.equal(sanitizeText("  hi  ", 10), "hi");
  assert.equal(sanitizeText("x".repeat(50), 10).length, 10);
  assert.equal(sanitizeText(12345, 10), "");
  assert.equal(sanitizeText(null, 10), "");
  assert.equal(sanitizeText({ a: 1 }, 10), "");
});

test("isNonEmptyString rejects whitespace-only and non-strings", () => {
  assert.equal(isNonEmptyString("  "), false);
  assert.equal(isNonEmptyString(""), false);
  assert.equal(isNonEmptyString(42), false);
  assert.equal(isNonEmptyString("ok"), true);
});

// ---- status transitions ----

test("isValidStatusTransition rejects moving out of a terminal status", () => {
  assert.equal(isValidStatusTransition("completed", "under_review"), false);
  assert.equal(isValidStatusTransition("rejected", "approved"), false);
  assert.equal(isValidStatusTransition("partially_completed", "requested"), false);
});

test("isValidStatusTransition allows normal forward moves and rejects unknown statuses", () => {
  assert.equal(isValidStatusTransition("requested", "under_review"), true);
  assert.equal(isValidStatusTransition("under_review", "approved"), true);
  assert.equal(isValidStatusTransition("requested", "hacked_status"), false);
});

// ---- audit log ----

test("appendAudit records the verified caller identity, not anything client-suppliable", () => {
  const appData = { privacyAuditLog: [] };
  appendAudit(appData, { uid: "real-uid", role: "user", action: "consent_grant", detail: { x: 1 } });
  assert.equal(appData.privacyAuditLog.length, 1);
  assert.equal(appData.privacyAuditLog[0].uid, "real-uid");
  assert.equal(appData.privacyAuditLog[0].actorRole, "user");
  assert.ok(appData.privacyAuditLog[0].id.startsWith("aud_"));
});

test("appendAudit is append-only and most-recent-first", () => {
  const appData = { privacyAuditLog: [{ id: "old", ts: 1, uid: "u", action: "x" }] };
  appendAudit(appData, { uid: "u2", role: "user", action: "y" });
  assert.equal(appData.privacyAuditLog.length, 2);
  assert.equal(appData.privacyAuditLog[0].action, "y"); // newest first
  assert.equal(appData.privacyAuditLog[1].id, "old"); // old entry preserved
});

test("appendAudit caps unbounded growth", () => {
  const big = Array.from({ length: 5000 }, (_, i) => ({ id: `e${i}`, ts: i, uid: "u", action: "x" }));
  const appData = { privacyAuditLog: big };
  appendAudit(appData, { uid: "u", role: "user", action: "new" });
  assert.equal(appData.privacyAuditLog.length, 5000);
});

// ---- policy lookups ----

test("findPublishedPolicy refuses to match a draft version", () => {
  const versions = [
    { type: "privacy_policy", version: "1.0", status: "published" },
    { type: "privacy_policy", version: "1.1", status: "draft" },
  ];
  assert.ok(findPublishedPolicy(versions, "privacy_policy", "1.0"));
  assert.equal(findPublishedPolicy(versions, "privacy_policy", "1.1"), undefined);
  assert.equal(findPublishedPolicy(versions, "terms_of_service", "1.0"), undefined);
});

test("latestPublishedPolicy picks the most recent effectiveDate among published only", () => {
  const versions = [
    { type: "privacy_policy", version: "1.0", effectiveDate: "2026-01-01", status: "published" },
    { type: "privacy_policy", version: "2.0", effectiveDate: "2026-06-01", status: "draft" },
    { type: "privacy_policy", version: "1.5", effectiveDate: "2026-03-01", status: "published" },
  ];
  const latest = latestPublishedPolicy(versions, "privacy_policy");
  assert.equal(latest.version, "1.5"); // 2.0 is a draft, so 1.5 (published) wins
});

// ---- request ownership filtering ----

test("getUserRequests never returns another user's request", () => {
  const all = [
    { id: "r1", uid: "userA" },
    { id: "r2", uid: "userB" },
  ];
  assert.deepEqual(getUserRequests(all, "userA").map((r) => r.id), ["r1"]);
});

// ---- id generation ----

test("genId produces unique, prefixed ids", () => {
  const a = genId("req");
  const b = genId("req");
  assert.notEqual(a, b);
  assert.ok(a.startsWith("req_"));
});
