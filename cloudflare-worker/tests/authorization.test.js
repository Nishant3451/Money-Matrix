import test from "node:test";
import assert from "node:assert/strict";
import { getDownlineSupervisorIds, buildAuthorizedView, mergeAuthorizedSave } from "../lib/authorization.js";

function sampleData() {
  return {
    settings: { appName: "MM", dataSharing: true },
    permissions: { superadmin: {}, admin: {}, user: {} },
    customSections: [],
    profiles: { sa: {}, sup_a: {}, sup_b: {}, sup_c: {} },
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "sup_a", username: "sup_a", role: "user", linkedId: "supA" },
      { id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" },
      { id: "sup_c", username: "sup_c", role: "user", linkedId: "supC" },
    ],
    activityLog: [
      { ts: 1, user: "sa", action: "add", coll: "members", name: "M1", scopeId: "supA" },
      { ts: 2, user: "sa", action: "add", coll: "members", name: "M2", scopeId: "supC" },
    ],
    shared: {
      transactions: [{ id: "t1", amount: 100 }],
      gifts: [{ id: "g1" }],
      // supA -> supB -> supC (B is downline of A, C is downline of B and A)
      supervisors: [
        { id: "supA", name: "A" },
        { id: "supB", name: "B", supervisorId: "supA" },
        { id: "supC", name: "C", supervisorId: "supB" },
        { id: "supX", name: "X (unrelated)" },
      ],
      coaches: [
        { id: "coachB", supervisorId: "supB" },
        { id: "coachX", supervisorId: "supX" },
      ],
      members: [
        { id: "m1", supervisorId: "supA" },
        { id: "m2", supervisorId: "supB" },
        { id: "m3", supervisorId: "supX" },
        { id: "m4", coachId: "coachB" }, // under B via coach
      ],
    },
    perUser: {
      sa: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [] },
      sup_a: { transactions: [{ id: "pu1" }], members: [], gifts: [], coaches: [], supervisors: [] },
      sup_b: { transactions: [], members: [], gifts: [], coaches: [], supervisors: [] },
    },
    userPermissions: { sup_a: { club: "view" } },
  };
}

test("getDownlineSupervisorIds walks the chain and includes root", () => {
  const d = sampleData();
  const ids = getDownlineSupervisorIds("supA", d.shared.supervisors);
  assert.deepEqual([...ids].sort(), ["supA", "supB", "supC"]);
});

test("getDownlineSupervisorIds guards against circular chains", () => {
  const circular = [
    { id: "x", supervisorId: "y" },
    { id: "y", supervisorId: "x" },
  ];
  const ids = getDownlineSupervisorIds("x", circular);
  assert.deepEqual([...ids].sort(), ["x", "y"]);
});

test("superadmin gets the full unfiltered view", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "sa", role: "superadmin", linkedId: null });
  assert.equal(view.shared.members.length, 4);
  assert.equal(view.shared.supervisors.length, 4);
  assert.equal(view.users.length, 4);
  assert.deepEqual(Object.keys(view.perUser).sort(), ["sa", "sup_a", "sup_b"]);
  assert.equal(view.activityLog.length, 2);
});

test("downline-scoped user only sees their own subtree, not siblings", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "sup_b", role: "user", linkedId: "supB" });
  // supB's downline is {supB, supC} — supA (their own boss) and supX are out of scope.
  assert.deepEqual(view.shared.supervisors.map((s) => s.id).sort(), ["supB", "supC"]);
  assert.deepEqual(view.shared.coaches.map((c) => c.id), ["coachB"]);
  assert.deepEqual(view.shared.members.map((m) => m.id).sort(), ["m2", "m4"]);
  // gifts/transactions are NOT downline-filtered anywhere client-side — preserved as-is.
  assert.equal(view.shared.gifts.length, 1);
  assert.equal(view.shared.transactions.length, 1);
  // Only their own perUser bucket, not sup_a's or sa's.
  assert.deepEqual(Object.keys(view.perUser), ["sup_b"]);
  // Only their own userPermissions override.
  assert.deepEqual(view.userPermissions, { sup_b: {} });
});

test("scoped user's activityLog is filtered to entries in their downline", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "sup_a", role: "user", linkedId: "supA" });
  // supA's downline is {supA, supB, supC} — both log entries qualify (scopeId supA and supC).
  assert.equal(view.activityLog.length, 2);

  const viewB = buildAuthorizedView(d, { uid: "sup_b", role: "user", linkedId: "supB" });
  // supB's downline is {supB, supC} — only the supC entry qualifies.
  assert.equal(viewB.activityLog.length, 1);
  assert.equal(viewB.activityLog[0].scopeId, "supC");
});

test("a non-admin user with no linkedId gets an empty shared/users view, not the full list", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "sup_a", role: "user", linkedId: null });
  assert.deepEqual(view.shared.members, []);
  assert.deepEqual(view.shared.supervisors, []);
  assert.deepEqual(view.users, []);
});

test("users control-plane list is downline-filtered for non-admins", () => {
  const d = sampleData();
  const view = buildAuthorizedView(d, { uid: "sup_a", role: "user", linkedId: "supA" });
  // sup_a (linkedId supA), sup_b (linkedId supB) and sup_c (linkedId supC) are all within
  // supA's downline; only the superadmin's own record (linkedId null) is excluded.
  assert.deepEqual(view.users.map((u) => u.id).sort(), ["sup_a", "sup_b", "sup_c"]);
});

// ---------------------------------------------------------------------------------------------
// mergeAuthorizedSave — the write side
// ---------------------------------------------------------------------------------------------

test("superadmin save is applied wholesale", () => {
  const d = sampleData();
  const submitted = { ...d, settings: { ...d.settings, appName: "Renamed" } };
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sa", role: "superadmin", linkedId: null });
  assert.equal(merged.settings.appName, "Renamed");
});

test("a scoped user's save cannot smuggle in a role escalation via `users`", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users = submitted.users.map((u) => (u.id === "sup_b" ? { ...u, role: "superadmin" } : u));
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  // The submitted `users` array is entirely ignored for a non-privileged caller — server's
  // original users list (with sup_b still role:"user") wins.
  assert.deepEqual(merged.users, d.users);
});

test("a scoped user's save cannot touch out-of-scope shared records", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  // Attempt to delete an out-of-scope member (m3, under supX) and rename an out-of-scope
  // supervisor (supA, their own upline boss).
  submitted.shared.members = submitted.shared.members.filter((m) => m.id !== "m3");
  submitted.shared.supervisors = submitted.shared.supervisors.map((s) =>
    s.id === "supA" ? { ...s, name: "HACKED" } : s
  );
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.ok(merged.shared.members.some((m) => m.id === "m3"), "out-of-scope member must survive");
  assert.equal(merged.shared.supervisors.find((s) => s.id === "supA").name, "A", "out-of-scope supervisor must not be edited");
});

test("a scoped user CAN edit/add records within their own downline", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.shared.members = submitted.shared.members.map((m) => (m.id === "m2" ? { ...m, name: "Edited" } : m));
  submitted.shared.members.push({ id: "m_new", supervisorId: "supB", name: "New" });
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.equal(merged.shared.members.find((m) => m.id === "m2").name, "Edited");
  assert.ok(merged.shared.members.some((m) => m.id === "m_new"));
});

test("a scoped user cannot add a new record claiming to belong to someone else's scope", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.shared.members.push({ id: "m_sneaky", supervisorId: "supX", name: "Sneaky" });
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.ok(!merged.shared.members.some((m) => m.id === "m_sneaky"));
});

test("a scoped user cannot reassign an in-scope record OUT of scope to escape future authorization", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  // m2 (currently under supB, in scope) is reassigned to supX (out of scope) by the client.
  submitted.shared.members = submitted.shared.members.map((m) => (m.id === "m2" ? { ...m, supervisorId: "supX" } : m));
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.equal(merged.shared.members.find((m) => m.id === "m2").supervisorId, "supB", "reassignment out of scope must be rejected");
});

test("a scoped user can only write their own perUser bucket, never someone else's", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.perUser.sup_a.transactions.push({ id: "hack" }); // someone else's bucket
  submitted.perUser.sup_b.transactions.push({ id: "mine" }); // caller's own bucket
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.deepEqual(merged.perUser.sup_a, d.perUser.sup_a, "other user's perUser bucket must be untouched");
  assert.ok(merged.perUser.sup_b.transactions.some((t) => t.id === "mine"));
});

test("activityLog is append-only and scoped: existing entries always survive, new entries must be in-scope", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  // Try to delete an existing entry and add two new ones (one in scope, one not).
  submitted.activityLog = [
    { ts: 3, user: "sup_b", action: "add", coll: "members", name: "New in-scope", scopeId: "supC" },
    { ts: 4, user: "sup_b", action: "add", coll: "members", name: "New out-of-scope", scopeId: "supX" },
  ];
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.equal(merged.activityLog.length, 3, "2 original entries kept + 1 authorized new entry");
  assert.ok(merged.activityLog.some((a) => a.scopeId === "supA")); // original, kept
  assert.ok(merged.activityLog.some((a) => a.scopeId === "supC" && a.name === "New in-scope"));
  assert.ok(!merged.activityLog.some((a) => a.name === "New out-of-scope"));
});

test("a scoped user's own userPermissions override can be changed, but not anyone else's", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.userPermissions = { sup_a: { club: "write" }, sup_b: { dashboard: "write" } };
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.deepEqual(merged.userPermissions.sup_a, { club: "view" }, "must keep server value for someone else");
  assert.deepEqual(merged.userPermissions.sup_b, { dashboard: "write" });
});

test("control-plane sections (settings/permissions/customSections) are untouched by a scoped user's save", () => {
  const d = sampleData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.settings = { appName: "HACKED" };
  submitted.permissions = { user: { dashboard: "write" } };
  submitted.customSections = [{ id: "new" }];
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.deepEqual(merged.settings, d.settings);
  assert.deepEqual(merged.permissions, d.permissions);
  assert.deepEqual(merged.customSections, d.customSections);
});
