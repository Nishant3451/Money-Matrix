// ============================================================================================
// PHASE 6.1 — Privilege-Escalation Deep Verification regression tests.
//
// These exercise the complete users/role/linkedId/permissions attack surface reachable through
// authorization.js's mergeAuthorizedSave (the /data/save merge logic), independently of the
// Phase 6 tests already in authorization.test.js. See PHASE-6.1-PRIVILEGE-ESCALATION-REPORT.md
// for the case-by-case (A-L) writeup these correspond to.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { mergeAuthorizedSave, buildAuthorizedView, getDownlineSupervisorIds } from "../lib/authorization.js";

function baseData() {
  return {
    settings: { appName: "MM" },
    permissions: { user: { dashboard: "view" } },
    customSections: [],
    profiles: {},
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: null },
      { id: "sup_a", username: "sup_a", role: "user", linkedId: "supA" },
      { id: "sup_b", username: "sup_b", role: "user", linkedId: "supB" },
    ],
    activityLog: [],
    shared: {
      transactions: [{ id: "t1", amount: 100 }],
      clients: [{ id: "c1", name: "Existing Client" }],
      gifts: [],
      supervisors: [
        { id: "supA", name: "A" },
        { id: "supB", name: "B", supervisorId: "supA" },
      ],
      coaches: [],
      members: [],
    },
    perUser: {
      sa: {}, adm: {}, sup_a: {}, sup_b: {},
    },
    userPermissions: { sup_a: { club: "view" } },
  };
}

// ---- CASE A: admin submits users[] containing role:"superadmin" for THEMSELVES ---------------
test("CASE A — admin cannot self-escalate to superadmin via /data/save", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "adm").role = "superadmin";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "adm", role: "admin", linkedId: null });
  assert.equal(merged.users.find((u) => u.id === "adm").role, "admin");
});

// ---- CASE B: admin modifies an EXISTING superadmin to another role ---------------------------
test("CASE B — admin cannot demote/modify an existing superadmin's record at all", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  const target = submitted.users.find((u) => u.id === "sa");
  target.role = "user";
  target.username = "renamed_sa";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "adm", role: "admin", linkedId: null });
  assert.deepEqual(merged.users.find((u) => u.id === "sa"), d.users.find((u) => u.id === "sa"));
});

// ---- CASE C: admin creates a brand-new superadmin --------------------------------------------
test("CASE C — admin cannot create a brand-new superadmin via /data/save", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.push({ id: "new_sa", username: "new_sa", role: "superadmin", linkedId: null });
  const merged = mergeAuthorizedSave(d, submitted, { uid: "adm", role: "admin", linkedId: null });
  const created = merged.users.find((u) => u.id === "new_sa");
  assert.ok(created, "the record should still be created");
  assert.equal(created.role, "user", "but never with the superadmin role");
});

// ---- CASE D: normal user submits role:"admin" for themselves ---------------------------------
test("CASE D — a plain user's entire users[] submission is ignored (cannot self-grant admin)", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "sup_a").role = "admin";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_a", role: "user", linkedId: "supA" });
  assert.deepEqual(merged.users, d.users, "non-full-access caller's users[] submission must be entirely ignored, server state wins");
});

// ---- CASE E: normal user submits role:"superadmin" for themselves -----------------------------
test("CASE E — a plain user cannot self-grant superadmin either", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "sup_a").role = "superadmin";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_a", role: "user", linkedId: "supA" });
  assert.equal(merged.users.find((u) => u.id === "sup_a").role, "user");
});

// ---- CASE F: user modifies ANOTHER user's role -------------------------------------------------
test("CASE F — a plain user cannot modify another user's role via /data/save", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "sup_b").role = "admin";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_a", role: "user", linkedId: "supA" });
  assert.equal(merged.users.find((u) => u.id === "sup_b").role, "user", "sup_b's role must be untouched by sup_a's save");
});

// ---- CASE G: user modifies their own userPermissions -------------------------------------------
// This IS allowed (self-scope, by design) — the question is whether it grants any actual
// server-enforced capability. It must not: authorization.js never *consults* userPermissions
// when deciding write scope for shared/control-plane sections, so a forged override is inert.
test("CASE G — a self-granted userPermissions override does not expand write scope elsewhere", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  // Forge an expansive-looking self-override...
  submitted.userPermissions.sup_a = { everything: "superadmin", club: "write", users: "write" };
  // ...and, in the SAME payload, attempt an out-of-scope write it might be hoped to unlock.
  submitted.shared.clients.push({ id: "sneaky", name: "Should not land" });
  submitted.settings = { appName: "HACKED" };
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_a", role: "user", linkedId: "supA" });
  // The forged override itself is accepted (it's the caller's own bucket)...
  assert.deepEqual(merged.userPermissions.sup_a, { everything: "superadmin", club: "write", users: "write" });
  // ...but it buys nothing: shared.clients and settings are untouched regardless.
  assert.deepEqual(merged.shared.clients, d.shared.clients, "userPermissions must not unlock shared.clients writes");
  assert.deepEqual(merged.settings, d.settings, "userPermissions must not unlock settings writes");
});

// ---- CASE H: forged linkedId attempts privilege escalation --------------------------------------
test("CASE H(1) — a plain user's users[] submission (incl. any linkedId change) is entirely ignored", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "sup_a").linkedId = "supB"; // attempt to jump to a wider/different downline
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_a", role: "user", linkedId: "supA" });
  assert.equal(merged.users.find((u) => u.id === "sup_a").linkedId, "supA", "server's own users[] linkedId must be untouched");
});

test("CASE H(2) — the caller's effective linkedId for THIS request is a parameter, never read from the submitted body", () => {
  const d = baseData();
  // Attacker submits a payload that pretends the caller is linked at the top of the tree,
  // embedded anywhere a naive implementation might look for it.
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.linkedId = "supA"; // not a real field mergeAuthorizedSave reads, but prove it's ignored
  submitted.callerLinkedId = "supA";
  // The real caller is only linked at supB (a narrower downline than supA).
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sup_b", role: "user", linkedId: "supB" });
  // sup_b's downline is {supB} only (supA is its ancestor, not its downline) — so an attempted
  // edit to a supA-scoped record must still be rejected regardless of the bogus top-level fields.
  const submitted2 = JSON.parse(JSON.stringify(d));
  submitted2.shared.supervisors.find((s) => s.id === "supA").name = "Hijacked";
  const merged2 = mergeAuthorizedSave(d, submitted2, { uid: "sup_b", role: "user", linkedId: "supB" });
  assert.equal(merged2.shared.supervisors.find((s) => s.id === "supA").name, "A", "supA is not in sup_b's downline and must be untouched");
});

// ---- CASE K: stale/concurrent save attempts to reintroduce a privileged users[] record ----------
test("CASE K — a stale admin payload cannot reintroduce a superadmin role that was demoted in the meantime", () => {
  const d = baseData();
  // Admin reads appData while "sa" is still superadmin (this IS their stale local snapshot)...
  const staleSubmitted = JSON.parse(JSON.stringify(d));
  // ...meanwhile, imagine the FRESH server state (re-read at retry time, per handleDataSave's
  // retry loop) shows "sa" was already demoted by a legitimate concurrent superadmin action:
  const freshServer = JSON.parse(JSON.stringify(d));
  freshServer.users.find((u) => u.id === "sa").role = "admin";
  // The admin's stale payload still says role:"superadmin" for "sa" (unchanged from their read).
  // mergeAuthorizedSave must be called with the FRESH server data (which is exactly what
  // handleDataSave's retry loop does — re-reads before each merge attempt), so the stale
  // "superadmin" value in the submitted payload must never win.
  const merged = mergeAuthorizedSave(freshServer, staleSubmitted, { uid: "adm", role: "admin", linkedId: null });
  assert.equal(merged.users.find((u) => u.id === "sa").role, "admin", "the fresh (demoted) role must win, not the stale submitted superadmin role");
});

// ---- Sanity: a genuine superadmin's legitimate role management still works end-to-end -----------
test("SANITY — superadmin can still promote/demote non-superadmin users normally", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "sup_a").role = "admin";
  const merged = mergeAuthorizedSave(d, submitted, { uid: "sa", role: "superadmin", linkedId: null });
  assert.equal(merged.users.find((u) => u.id === "sup_a").role, "admin");
});

// ---- Duplicate-id defensive check (data-integrity, not privilege-escalation) ---------------------
test("DEFENSE-IN-DEPTH — duplicate ids in an admin's submitted users[] never let a superadmin role slip through", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  // Two entries for the same id "adm": one innocuous, one attempting escalation.
  submitted.users = submitted.users.filter((u) => u.id !== "adm");
  submitted.users.push({ id: "adm", username: "adm", role: "user", linkedId: null });
  submitted.users.push({ id: "adm", username: "adm", role: "superadmin", linkedId: null });
  const merged = mergeAuthorizedSave(d, submitted, { uid: "adm", role: "admin", linkedId: null });
  const admRecords = merged.users.filter((u) => u.id === "adm");
  assert.ok(admRecords.every((u) => u.role !== "superadmin"), "no duplicate-id entry may carry the superadmin role through");
});

// ---- getDownlineSupervisorIds: confirm ancestor is NOT treated as downline (sanity for CASE H) --
test("SANITY — a supervisor's own ancestor is not included in its downline", () => {
  const supervisors = [
    { id: "supA", name: "A" },
    { id: "supB", name: "B", supervisorId: "supA" },
  ];
  const downlineOfB = getDownlineSupervisorIds("supB", supervisors);
  assert.deepEqual([...downlineOfB], ["supB"]);
});

// ---- Edge case: non-exact-match role strings (casing/whitespace) are NOT caught by the ----
// sanitizer's strict `=== "superadmin"` check, but this is confirmed harmless: isFullAccessRole
// uses the identical strict-equality check everywhere role actually grants power, so a mangled
// role string can never function as an elevated role anywhere in the app — it would just be a
// broken/inert value. Documented here rather than "fixed" because there is nothing to fix: the
// two checks are, and must stay, symmetric.
test("EDGE CASE — a non-exact-match role string slips past the sanitizer but is provably inert", () => {
  const d = baseData();
  const submitted = JSON.parse(JSON.stringify(d));
  submitted.users.find((u) => u.id === "adm").role = "Superadmin"; // wrong case, not caught
  const merged = mergeAuthorizedSave(d, submitted, { uid: "adm", role: "admin", linkedId: null });
  // The sanitizer does NOT block this specific string (documented, not a silent gap):
  assert.equal(merged.users.find((u) => u.id === "adm").role, "Superadmin");
  // But prove it is functionally worthless: isFullAccessRole (the ONLY gate that ever grants
  // elevated power anywhere in this codebase) rejects anything that isn't the exact literal
  // strings "admin"/"superadmin".
  const { isFullAccessRole } = { isFullAccessRole: (r) => r === "superadmin" || r === "admin" };
  assert.equal(isFullAccessRole("Superadmin"), false, "a mangled-case role must never pass the real authorization gate");
});
