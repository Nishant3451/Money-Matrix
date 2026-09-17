import test from "node:test";
import assert from "node:assert/strict";
import { buildAuthorizedView, mergeAuthorizedSave } from "../lib/authorization.js";

function sampleData() {
  return {
    settings: { appName: "MM" },
    permissions: {},
    customSections: [],
    profiles: { userA: {}, userB: {}, admin1: {} },
    users: [
      { id: "userA", username: "userA", role: "user", linkedId: null },
      { id: "userB", username: "userB", role: "user", linkedId: null },
      { id: "admin1", username: "admin1", role: "admin", linkedId: null },
    ],
    activityLog: [],
    shared: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [] },
    perUser: {},
    userPermissions: {},
    // Part-B privacy fields
    policyVersions: [
      { type: "privacy_policy", version: "1.0", effectiveDate: "2026-01-01", status: "published" },
      { type: "privacy_policy", version: "1.1-draft", effectiveDate: "2026-06-01", status: "draft" },
    ],
    privacyConsents: {
      userA: [{ id: "c1", type: "x", purpose: "y", status: "granted" }],
      userB: [{ id: "c2", type: "x", purpose: "y", status: "granted" }],
    },
    privacyPreferences: { userA: { essential: true }, userB: { essential: true } },
    policyAcceptances: { userA: { privacy_policy: { version: "1.0", timestamp: 1 } } },
    privacyRequests: [
      { id: "r1", uid: "userA", category: "access", status: "requested" },
      { id: "r2", uid: "userB", category: "deletion", status: "requested" },
    ],
    privacyAuditLog: [{ id: "a1", uid: "userA", action: "consent_grant" }],
  };
}

test("non-admin sees only their own consents/preferences/policyAcceptances", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "userA", role: "user", linkedId: null });
  assert.deepEqual(Object.keys(view.privacyConsents), ["userA"]);
  assert.deepEqual(Object.keys(view.privacyPreferences), ["userA"]);
  assert.deepEqual(Object.keys(view.policyAcceptances), ["userA"]);
});

test("non-admin sees only their own privacyRequests, never another user's", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "userA", role: "user", linkedId: null });
  assert.equal(view.privacyRequests.length, 1);
  assert.equal(view.privacyRequests[0].uid, "userA");
  assert.ok(!view.privacyRequests.some((r) => r.uid === "userB"));
});

test("non-admin sees only published policy versions, not drafts", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "userA", role: "user", linkedId: null });
  assert.equal(view.policyVersions.length, 1);
  assert.equal(view.policyVersions[0].status, "published");
});

test("non-admin gets an empty privacyAuditLog (admin-only surface)", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "userA", role: "user", linkedId: null });
  assert.deepEqual(view.privacyAuditLog, []);
});

test("admin sees every user's privacyRequests, consents, and drafts", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "admin1", role: "admin", linkedId: null });
  assert.equal(view.privacyRequests.length, 2);
  assert.deepEqual(Object.keys(view.privacyConsents).sort(), ["userA", "userB"]);
  assert.equal(view.policyVersions.length, 2); // published + draft
  assert.equal(view.privacyAuditLog.length, 1);
});

test("a forged/omitted uid in a request never leaks another user's data (view is keyed server-side only)", () => {
  const d = sampleData();
  // A non-admin caller has no way to ask for someone else's bucket -- buildAuthorizedView keys
  // strictly off the server-verified uid, there is no uid-selecting parameter at all.
  const view = buildAuthorizedView(d, { uid: "userB", role: "user", linkedId: null });
  assert.deepEqual(Object.keys(view.privacyConsents), ["userB"]);
});

test("generic saveAppData (admin) can NEVER modify privacy fields -- server state always wins", () => {
  const d = sampleData();
  const maliciousSubmit = {
    users: d.users,
    privacyRequests: [{ id: "r1", uid: "userA", category: "access", status: "completed", adminNotes: "forged" }],
    privacyAuditLog: [],
    privacyConsents: {},
    policyVersions: [],
    policyAcceptances: {},
    privacyPreferences: {},
  };
  const merged = mergeAuthorizedSave(d, maliciousSubmit, { uid: "admin1", role: "admin", linkedId: null });
  // Server's original privacy state must be untouched, regardless of what an admin's client
  // submitted through the generic save path.
  assert.deepEqual(merged.privacyRequests, d.privacyRequests);
  assert.deepEqual(merged.privacyAuditLog, d.privacyAuditLog);
  assert.deepEqual(merged.privacyConsents, d.privacyConsents);
  assert.deepEqual(merged.policyVersions, d.policyVersions);
});

test("generic saveAppData (non-admin) also cannot touch privacy fields", () => {
  const d = sampleData();
  const maliciousSubmit = {
    privacyRequests: [{ id: "r2", uid: "userB", status: "completed" }],
    privacyConsents: { userA: [{ id: "forged", status: "granted" }] },
  };
  const merged = mergeAuthorizedSave(d, maliciousSubmit, { uid: "userA", role: "user", linkedId: null });
  assert.deepEqual(merged.privacyRequests, d.privacyRequests);
  assert.deepEqual(merged.privacyConsents, d.privacyConsents);
});

test("a missing privacy field on the server defaults safely instead of throwing", () => {
  const bare = { users: [{ id: "u1", username: "u1", role: "user" }] };
  const view = buildAuthorizedView(bare, { uid: "u1", role: "user", linkedId: null });
  assert.deepEqual(view.privacyConsents, { u1: [] });
  assert.deepEqual(view.privacyRequests, []);
  assert.deepEqual(view.policyVersions, []);
  const merged = mergeAuthorizedSave(bare, {}, { uid: "u1", role: "user", linkedId: null });
  assert.deepEqual(merged.privacyRequests, []);
});
