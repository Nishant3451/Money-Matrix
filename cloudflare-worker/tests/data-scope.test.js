// DATA SCOPE for Payments (transactions) and Quotations — WHOSE records a caller may see. Server-enforced, built on the
// existing hierarchy (supervisor tree + users[].linkedId). These run the REAL functions in lib/authorization.js.
import test from "node:test";
import assert from "node:assert/strict";
import { buildAuthorizedView, mergeAuthorizedSave, resolveDataScope, resolveRequestedScope, DATA_SCOPES } from "../lib/authorization.js";

const clone = (x) => JSON.parse(JSON.stringify(x));
const ids = (a) => (a || []).map((x) => x.id);
const caller = (data, uid, role) => ({ uid, role, linkedId: (data.users.find((u) => u.id === uid) || {}).linkedId || null });

//   supTop
//     └─ supMid          (adm + peer attach here)
//          └─ supLow     (low attaches here)
//               └─ supLeaf (leaf attaches here)
//   supOther            (unrelated tree; `other` attaches here)
function base() {
  const mk = (owner, status) => ({ id: `pay-${owner}`, customer: `Cust-${owner}`, amount: 10, status, ownerId: owner });
  const mq = (owner) => ({ id: `q-${owner}`, customerName: `QCust-${owner}`, invoiceNumber: `INV-${owner}`, ownerId: owner });
  const owners = ["sa", "adm", "top", "peer", "low", "leaf", "other", "nolink"];
  return {
    settings: { dataSharing: true },
    permissions: { superadmin: {}, admin: {}, user: { marathon: "write", quotations: "write" } },
    userPermissions: {}, profiles: {}, customSections: [],
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: "supMid" },
      { id: "top", username: "top", role: "user", linkedId: "supTop" },
      { id: "peer", username: "peer", role: "user", linkedId: "supMid" },
      { id: "low", username: "low", role: "user", linkedId: "supLow" },
      { id: "leaf", username: "leaf", role: "user", linkedId: "supLeaf" },
      { id: "other", username: "other", role: "user", linkedId: "supOther" },
      { id: "nolink", username: "nolink", role: "user", linkedId: null },
    ],
    activityLog: [
      { ts: 1, user: "sa", action: "added", coll: "transactions", name: "Cust-sa", scopeId: null },
      { ts: 2, user: "adm", action: "added", coll: "quotations", name: "QCust-adm", scopeId: null },
      { ts: 3, user: "low", action: "added", coll: "transactions", name: "Cust-low", scopeId: null },
      { ts: 4, user: "other", action: "added", coll: "quotations", name: "QCust-other", scopeId: null },
    ],
    shared: {
      supervisors: [
        { id: "supTop", supervisorId: null }, { id: "supMid", supervisorId: "supTop" }, { id: "supLow", supervisorId: "supMid" },
        { id: "supLeaf", supervisorId: "supLow" }, { id: "supOther", supervisorId: null },
      ],
      members: [], coaches: [], gifts: [], clients: [], products: [{ id: "p1" }],
      // statuses mixed on purpose; one record has an unknown status, one legacy record has no ownerId at all
      transactions: [...owners.map((o, i) => mk(o, i % 2 ? "completed" : "pending")), { id: "pay-legacy", customer: "Legacy", amount: 1, status: "pending" }, { id: "pay-weird", customer: "Weird", amount: 1, status: "refunded", ownerId: "adm" }],
      quotations: [...owners.map(mq), { id: "q-legacy", customerName: "LegacyQ" }],
    },
    perUser: Object.fromEntries(owners.map((o) => [o, { transactions: [{ id: `ut-${o}`, ownerId: o, status: "pending" }], quotations: [{ id: `uq-${o}`, ownerId: o }], products: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] }])),
  };
}
const view = (d, uid, role, scope) => buildAuthorizedView(d, caller(d, uid, role), scope === undefined ? {} : { scope });

// ------------------------------------------------------------------ the scope engine
test("resolveDataScope: superadmin gets 'all'; admin and users NEVER do", () => {
  const d = base();
  assert.ok(resolveDataScope(d, caller(d, "sa", "superadmin")).allowed.includes("all"));
  for (const [uid, role] of [["adm", "admin"], ["low", "user"], ["nolink", "user"], ["top", "user"]]) {
    assert.ok(!resolveDataScope(d, caller(d, uid, role)).allowed.includes("all"), `${role} ${uid}`);
  }
  assert.equal(resolveDataScope(d, caller(d, "sa", "superadmin")).defaultScope, "all");
});
test("resolveDataScope: only offers scopes the server would accept (an unlinked user has no hierarchy, so only 'mine')", () => {
  const d = base();
  assert.deepEqual(resolveDataScope(d, caller(d, "nolink", "user")).allowed, ["mine"]);
  assert.deepEqual(resolveDataScope(d, caller(d, "leaf", "user")).allowed, ["mine", "upline", "mine_upline"], "a leaf has no downline (only upline options)");
  assert.deepEqual(resolveDataScope(d, caller(d, "adm", "admin")).allowed, ["mine", "upline", "downline", "mine_upline", "mine_downline", "upline_downline", "mine_upline_downline"]);
  assert.deepEqual(resolveDataScope(d, caller(d, "sa", "superadmin")).allowed, ["all", "mine"], "superadmin has no hierarchy node");
  for (const uid of ["adm", "low", "nolink", "sa"]) for (const k of resolveDataScope(d, caller(d, uid, uid === "sa" ? "superadmin" : "user")).allowed) assert.ok(DATA_SCOPES.includes(k));
});
test("I. hierarchy: downline = users at/below the caller's node (existing scopeUsers rule); upline users are never in the DOWNLINE or the default scope", () => {
  const d = base();
  const ds = resolveDataScope(d, caller(d, "adm", "admin"));
  assert.deepEqual([...ds.owners.downline].sort(), ["leaf", "low", "peer"], "peer shares adm's node => treated as downline, exactly like members/coaches already are");
  assert.deepEqual(ds.owners.mine, ["adm"]);
  for (const forbidden of ["top", "other", "sa", "nolink"]) assert.ok(!ds.owners.mine_downline.includes(forbidden), forbidden);
  const lowDs = resolveDataScope(d, caller(d, "low", "user"));
  assert.deepEqual(lowDs.owners.downline, ["leaf"]);
  assert.ok(!lowDs.owners.mine_downline.includes("adm") && !lowDs.owners.mine_downline.includes("top"), "upline is never part of the downline / default scope");
});
test("resolveRequestedScope: absent => default; valid => accepted; unknown / wrong type / prototype keys => rejected", () => {
  const d = base(); const ds = resolveDataScope(d, caller(d, "adm", "admin"));
  assert.deepEqual(resolveRequestedScope(ds, undefined), { ok: true, key: "mine_downline" });
  assert.deepEqual(resolveRequestedScope(ds, null), { ok: true, key: "mine_downline" });
  assert.deepEqual(resolveRequestedScope(ds, "mine"), { ok: true, key: "mine" });
  for (const bad of ["all", "ALL", "UPLINE", "upline_all", "everything", "", " mine", "__proto__", "constructor", "toString", 1, true, {}, [], ["mine"], { $ne: 1 }]) {
    assert.equal(resolveRequestedScope(ds, bad).ok, false, JSON.stringify(bad));
  }
});

// ------------------------------------------------------------------ reads
test("A/O. Superadmin can request All Data and sees every record — including legacy records with no owner", () => {
  const d = base();
  for (const scope of [undefined, "all"]) {
    const v = view(d, "sa", "superadmin", scope);
    assert.equal(v.shared.transactions.length, d.shared.transactions.length);
    assert.ok(ids(v.shared.transactions).includes("pay-legacy") && ids(v.shared.quotations).includes("q-legacy"));
    assert.equal(v.dataScope.active, "all");
  }
});
test("superadmin may still narrow the view with the hierarchy scopes", () => {
  const d = base();
  assert.deepEqual(ids(view(d, "sa", "superadmin", "mine").shared.transactions), ["pay-sa"]);
});
test("B/P. Admin cannot request All Data — and the default is their hierarchy, not everything", () => {
  const d = base();
  assert.throws(() => view(d, "adm", "admin", "all"), (e) => e.code === "SCOPE_NOT_ALLOWED");
  const v = view(d, "adm", "admin");
  assert.deepEqual(ids(v.shared.transactions).sort(), ["pay-adm", "pay-leaf", "pay-low", "pay-peer", "pay-weird"].sort());
  assert.deepEqual(ids(v.shared.quotations).sort(), ["q-adm", "q-leaf", "q-low", "q-peer"].sort());
  assert.equal(v.dataScope.active, "mine_downline");
  for (const hidden of ["pay-sa", "pay-top", "pay-other", "pay-nolink", "pay-legacy"]) assert.ok(!ids(v.shared.transactions).includes(hidden), hidden);
});
test("C. A normal user cannot request All Data", () => {
  const d = base();
  assert.throws(() => view(d, "low", "user", "all"), (e) => e.code === "SCOPE_NOT_ALLOWED");
  assert.throws(() => view(d, "nolink", "user", "all"), (e) => e.code === "SCOPE_NOT_ALLOWED");
});
test("G/H. a user cannot reach an unrelated user's (or their upline's) Payments or Quotations through any scope", () => {
  const d = base();
  for (const [uid, role, forbiddenOwners] of [["low", "user", ["other", "top", "adm", "sa", "peer", "nolink"]], ["adm", "admin", ["other", "top", "sa", "nolink"]]]) {
    for (const scope of [undefined, "mine", "downline", "mine_downline"]) {
      const v = view(d, uid, role, scope);
      for (const o of forbiddenOwners) {
        assert.ok(!ids(v.shared.transactions).includes(`pay-${o}`), `${uid}/${scope}: pay-${o}`);
        assert.ok(!ids(v.shared.quotations).includes(`q-${o}`), `${uid}/${scope}: q-${o}`);
      }
      assert.ok(!JSON.stringify(v).includes("Cust-other") && !JSON.stringify(v).includes("QCust-other") && !JSON.stringify(v).includes("INV-other"));
    }
  }
});
test("scope narrows: mine / downline / mine_downline return exactly those owners", () => {
  const d = base();
  assert.deepEqual(ids(view(d, "adm", "admin", "mine").shared.transactions).sort(), ["pay-adm", "pay-weird"]);
  assert.deepEqual(ids(view(d, "adm", "admin", "downline").shared.transactions).sort(), ["pay-leaf", "pay-low", "pay-peer"]);
  assert.deepEqual(ids(view(d, "low", "user", "mine_downline").shared.quotations).sort(), ["q-leaf", "q-low"]);
  assert.deepEqual(ids(view(d, "nolink", "user").shared.transactions), ["pay-nolink"]);
});
test("a user is never served records that carry no (or a non-string) ownerId, except superadmin", () => {
  const d = base(); d.shared.transactions.push({ id: "pay-x1", ownerId: null }, { id: "pay-x2", ownerId: 5 }, { id: "pay-x3", ownerId: { $ne: 1 } });
  for (const [uid, role] of [["adm", "admin"], ["low", "user"], ["nolink", "user"]]) {
    const t = ids(view(d, uid, role).shared.transactions);
    for (const id of ["pay-legacy", "pay-x1", "pay-x2", "pay-x3"]) assert.ok(!t.includes(id), `${uid}: ${id}`);
  }
  assert.ok(ids(view(d, "sa", "superadmin").shared.transactions).includes("pay-x2"));
});
test("J. a HIDDEN section stays entirely hidden even if the requested scope is the widest allowed", () => {
  const d = base(); d.userPermissions.adm = { marathon: "hidden", quotations: "hidden" };
  for (const scope of [undefined, "mine_downline", "mine", "downline"]) {
    const v = view(d, "adm", "admin", scope);
    assert.deepEqual(v.shared.transactions, []); assert.deepEqual(v.shared.quotations, []);
    for (const b of Object.values(v.perUser)) { assert.deepEqual(b.transactions, []); assert.deepEqual(b.quotations, []); }
  }
  // superadmin can never be hidden
  d.userPermissions.sa = { marathon: "hidden" };
  assert.ok(view(d, "sa", "superadmin", "all").shared.transactions.length > 0);
});
test("K. view-only stays view-only: records are served but cannot be changed", () => {
  const d = base(); d.userPermissions.adm = { quotations: "view" };
  assert.deepEqual(ids(view(d, "adm", "admin").shared.quotations).sort(), ["q-adm", "q-leaf", "q-low", "q-peer"].sort());
  const s = clone(d); s.shared.quotations = s.shared.quotations.map((q) => (q.id === "q-adm" ? { ...q, customerName: "CHANGED" } : q)); s.shared.quotations.push({ id: "new", ownerId: "adm" });
  const merged = mergeAuthorizedSave(d, s, caller(d, "adm", "admin"));
  assert.deepEqual(merged.shared.quotations, d.shared.quotations);
});
test("section filtering and scope filtering compose: unrelated authorized data is untouched", () => {
  const d = base(); const v = view(d, "adm", "admin", "mine");
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(v.settings, d.settings);
});
test("per-user buckets: out-of-scope buckets are blanked for admin (collections only); a normal user receives downline buckets' Payments/Quotations ONLY", () => {
  const d = base(); d.settings.dataSharing = false;
  const a = view(d, "adm", "admin");
  assert.deepEqual(ids(a.perUser.adm.transactions), ["ut-adm"]);
  assert.deepEqual(ids(a.perUser.low.transactions), ["ut-low"]);
  for (const o of ["top", "other", "sa", "nolink"]) { assert.deepEqual(a.perUser[o].transactions, [], o); assert.deepEqual(a.perUser[o].quotations, [], o); }
  const l = view(d, "low", "user");
  assert.deepEqual(Object.keys(l.perUser).sort(), ["leaf", "low"], "own bucket + downline bucket; nobody else's");
  assert.deepEqual(Object.keys(l.perUser.leaf).sort(), ["quotations", "transactions"], "downline bucket carries ONLY the scoped collections");
  assert.ok(!JSON.stringify(l.perUser).includes("ut-other") && !JSON.stringify(l.perUser).includes("ut-adm"));
  d.userPermissions.low = { marathon: "hidden" };
  assert.deepEqual(view(d, "low", "user").perUser.leaf.transactions, [], "section permission still wins over scope");
});
test("activity-log entries naming Payments/Quotations are limited to in-scope actors (best-effort, fails closed)", () => {
  const d = base();
  assert.deepEqual(view(d, "adm", "admin").activityLog.map((a) => a.user), ["adm", "low"]);
  assert.equal(view(d, "sa", "superadmin").activityLog.length, 4);
  assert.deepEqual(view(d, "nolink", "user").activityLog, []);
});
test("dataScope descriptor is server-computed and consistent with what was served", () => {
  const d = base(); const v = view(d, "adm", "admin", "downline");
  assert.deepEqual(v.dataScope.allowed, ["mine", "upline", "downline", "mine_upline", "mine_downline", "upline_downline", "mine_upline_downline"]);
  assert.equal(v.dataScope.max, "mine_upline_downline");
  assert.equal(v.dataScope.default, "mine_downline"); assert.equal(v.dataScope.active, "downline");
  assert.deepEqual([...v.dataScope.owners.downline].sort(), ["leaf", "low", "peer"]);
});
test("building a view never mutates the authoritative data", () => {
  const d = base(); const snap = clone(d);
  for (const [u, r, s] of [["sa", "superadmin", "all"], ["adm", "admin", "mine"], ["low", "user", undefined], ["nolink", "user", "mine"]]) view(d, u, r, s);
  assert.deepEqual(d, snap);
});

// ------------------------------------------------------------------ forged inputs
test("D/E/F. nothing client-supplied can change the outcome: role, uid and 'all' only exist as a REQUEST, which the server clamps", () => {
  const d = base();
  // The function only ever sees the server-resolved caller; an attacker-controlled body can only reach `scope`.
  const forged = { role: "superadmin", uid: "sa", userId: "sa", all: true, scope: "all", linkedId: "supTop", permissions: { user: { marathon: "write" } } };
  assert.throws(() => buildAuthorizedView(d, caller(d, "adm", "admin"), { scope: forged.scope }), (e) => e.code === "SCOPE_NOT_ALLOWED");
  const v = buildAuthorizedView(d, caller(d, "adm", "admin"), { ...forged, scope: undefined });
  assert.ok(!ids(v.shared.transactions).includes("pay-sa") && !ids(v.shared.transactions).includes("pay-top"), "extra fields are ignored");
});

// ------------------------------------------------------------------ writes
test("narrowed client cannot delete what it never held: an admin's save leaves everyone else's Payments/Quotations intact", () => {
  const d = base();
  const mine = view(d, "adm", "admin");                                   // what the admin's client actually holds
  const s = { ...clone(d), shared: { ...clone(d).shared, transactions: mine.shared.transactions, quotations: mine.shared.quotations } };
  const merged = mergeAuthorizedSave(d, s, caller(d, "adm", "admin"));
  assert.deepEqual(merged.shared.transactions, d.shared.transactions, "byte-identical, same order — a no-op save changes nothing");
  assert.deepEqual(merged.shared.quotations, d.shared.quotations);
});
test("admin can still add / edit / delete records inside their own scope", () => {
  const d = base(); const c = caller(d, "adm", "admin");
  const mine = view(d, "adm", "admin"); const s = clone(d);
  s.shared.transactions = mine.shared.transactions.filter((t) => t.id !== "pay-peer").map((t) => (t.id === "pay-low" ? { ...t, amount: 999 } : t));
  s.shared.transactions.push({ id: "pay-new", ownerId: "adm", amount: 5, status: "pending" }, { id: "pay-new2", ownerId: "leaf", amount: 6, status: "pending" });
  const m = mergeAuthorizedSave(d, s, c);
  const t = Object.fromEntries(m.shared.transactions.map((x) => [x.id, x]));
  assert.equal(t["pay-low"].amount, 999); assert.ok(!t["pay-peer"], "deleted in scope"); assert.ok(t["pay-new"] && t["pay-new2"]);
  for (const out of ["pay-sa", "pay-top", "pay-other", "pay-nolink", "pay-legacy"]) assert.ok(t[out], `${out} untouched`);
});
test("admin cannot edit, re-attribute, delete, inject or take over records outside their scope", () => {
  const d = base(); const c = caller(d, "adm", "admin");
  const mine = view(d, "adm", "admin"); const s = clone(d);
  s.shared.transactions = [
    ...mine.shared.transactions.map((t) => (t.id === "pay-adm" ? { ...t, ownerId: "other" } : t)),      // push my record out of my scope
    { id: "pay-other", customer: "HIJACK", ownerId: "adm", amount: 1e9 },                                // take over someone else's id
    { id: "pay-inject", customer: "INJECT", ownerId: "top", amount: 1 },                                  // forge a record for my upline
    { id: "pay-inject2", customer: "NOOWNER", amount: 1 },                                                // unattributed
  ];
  const m = mergeAuthorizedSave(d, s, c);
  const t = Object.fromEntries(m.shared.transactions.map((x) => [x.id, x]));
  assert.equal(t["pay-adm"].ownerId, "adm", "re-attribution out of scope rejected");
  assert.equal(t["pay-other"].customer, "Cust-other", "id takeover rejected");
  assert.ok(!t["pay-inject"] && !t["pay-inject2"], "records for people outside the scope / with no owner cannot be created");
  assert.equal(m.shared.transactions.filter((x) => x.id === "pay-other").length, 1, "no duplicate id");
});
test("a normal user's shared writes are still discarded (existing rule) and cannot widen scope", () => {
  const d = base(); const c = caller(d, "low", "user");
  const s = clone(d); s.shared.transactions = [{ id: "evil", ownerId: "low" }]; s.shared.quotations = [];
  const m = mergeAuthorizedSave(d, s, c);
  assert.deepEqual(m.shared.transactions, d.shared.transactions); assert.deepEqual(m.shared.quotations, d.shared.quotations);
});
test("per-user mode: admin cannot write into the Payments/Quotations buckets of people outside their hierarchy", () => {
  const d = base(); d.settings.dataSharing = false; const c = caller(d, "adm", "admin");
  const s = clone(d);
  s.perUser.top.transactions = [{ id: "evil-top", ownerId: "top" }]; s.perUser.other.quotations = []; s.perUser.low.transactions = [{ id: "ut-low", ownerId: "low", status: "completed" }];
  s.perUser.brandnew = { transactions: [{ id: "x" }], quotations: [{ id: "y" }], products: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] };
  const m = mergeAuthorizedSave(d, s, c);
  assert.deepEqual(m.perUser.top.transactions, d.perUser.top.transactions);
  assert.deepEqual(m.perUser.other.quotations, d.perUser.other.quotations);
  assert.equal(m.perUser.low.transactions[0].status, "completed", "downline bucket (in scope) is editable by the admin");
  assert.deepEqual(m.perUser.brandnew.transactions, []); assert.deepEqual(m.perUser.brandnew.quotations, []);
});
test("L. stale-data replay: after a relationship ends, an old client can neither edit nor delete the former downline's records, nor regain scope", () => {
  const d = base(); const staleView = view(d, "adm", "admin");                // adm held leaf/low's payments
  const after = clone(d);
  after.shared.supervisors.find((s) => s.id === "supLow").supervisorId = "supOther"; // low (and leaf below) moved out of adm's tree
  const s = clone(after); s.shared.transactions = staleView.shared.transactions.map((t) => (t.id === "pay-low" ? { ...t, amount: 31337 } : t)); // replay old data
  const m = mergeAuthorizedSave(after, s, caller(after, "adm", "admin"));
  const t = Object.fromEntries(m.shared.transactions.map((x) => [x.id, x]));
  assert.equal(t["pay-low"].amount, 10, "edit of a record that is no longer in scope is discarded"); assert.ok(t["pay-leaf"], "and nothing out of scope is deleted");
  assert.ok(!ids(view(after, "adm", "admin").shared.transactions).includes("pay-low"), "scope was recomputed from the CURRENT hierarchy");
});
test("superadmin writes are unrestricted (and a lower role cannot widen anything with the same payload)", () => {
  const d = base(); const s = clone(d); s.shared.transactions = [{ id: "only", ownerId: "other" }];
  assert.deepEqual(ids(mergeAuthorizedSave(d, s, caller(d, "sa", "superadmin")).shared.transactions), ["only"]);
  assert.deepEqual(mergeAuthorizedSave(d, s, caller(d, "adm", "admin")).shared.transactions.map((x) => x.id).sort(), d.shared.transactions.filter((x) => !(typeof x.ownerId === "string" && ["adm", "peer", "low", "leaf"].includes(x.ownerId))).map((x) => x.id).sort());
});
test("O/P. superadmin stays unrestricted; admin stays restricted and cannot escalate by changing role/permissions in the same save", () => {
  const d = base(); const s = clone(d);
  s.users.find((u) => u.id === "adm").role = "superadmin"; s.userPermissions = { adm: { marathon: "write" } };
  const m = mergeAuthorizedSave(d, s, caller(d, "adm", "admin"));
  assert.equal(m.users.find((u) => u.id === "adm").role, "admin");
  assert.deepEqual(ids(buildAuthorizedView(m, caller(m, "adm", "admin")).shared.transactions).includes("pay-sa"), false);
});
