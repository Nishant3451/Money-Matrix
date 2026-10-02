// Server-side SECTION authorization for the three sensitive datasets: Products, Quotations (incl. the
// invoices generated from them) and Payments (transactions). These run the REAL functions from
// lib/authorization.js — nothing here re-implements the rules under test.
import test from "node:test";
import assert from "node:assert/strict";
import { buildAuthorizedView, mergeAuthorizedSave, resolveSectionPerm, canViewSection, canWriteSection, GATED_SECTIONS } from "../lib/authorization.js";

const clone = (x) => JSON.parse(JSON.stringify(x));
const SA = { uid: "sa", role: "superadmin", linkedId: null };
const ADM = { uid: "adm", role: "admin", linkedId: null };
const U1 = { uid: "u1", role: "user", linkedId: "supA" };
const U2 = { uid: "u2", role: "user", linkedId: "supB" };

function base() {
  return {
    settings: { dataSharing: true },
    // production defaults: role `user` has Payments write; Products/Quotations absent => hidden for `user`.
    permissions: { superadmin: {}, admin: {}, user: { marathon: "write" } },
    userPermissions: {},
    customSections: [], profiles: {},
    users: [
      { id: "sa", username: "sa", role: "superadmin", linkedId: null },
      { id: "adm", username: "adm", role: "admin", linkedId: null },
      { id: "u1", username: "u1", role: "user", linkedId: "supA" },
      { id: "u2", username: "u2", role: "user", linkedId: "supB" },
    ],
    activityLog: [
      { ts: 1, user: "sa", action: "added", coll: "quotations", name: "Secret Customer", scopeId: null },
      { ts: 2, user: "sa", action: "added", coll: "products", name: "Secret Product", scopeId: null },
      { ts: 3, user: "sa", action: "added", coll: "transactions", name: "Secret Payer", scopeId: null },
      { ts: 4, user: "sa", action: "added", coll: "members", name: "M1", scopeId: "supA" },
    ],
    shared: {
      products: [{ id: "p1", name: "P1", defaultPrice: 10 }],
      // Records carry the ownerId the client stamps. u1 owns q1/t1 (u1 is a normal user); adm owns q-adm.
      quotations: [{ id: "q1", customerName: "C1", invoiceNumber: "INV-1", grandTotal: 500, ownerId: "u1" }, { id: "q-adm", customerName: "AdminCust", ownerId: "adm" }],
      transactions: [{ id: "t1", customer: "C1", amount: 100, ownerId: "u1" }],
      gifts: [{ id: "g1" }], clients: [{ id: "c1", name: "Client" }],
      supervisors: [{ id: "supA", name: "A" }, { id: "supB", name: "B" }],
      coaches: [], members: [{ id: "m1", supervisorId: "supA" }, { id: "m2", supervisorId: "supB" }],
    },
    perUser: {
      sa: { transactions: [{ id: "sa-t" }], products: [{ id: "sa-p" }], quotations: [{ id: "sa-q" }], members: [], gifts: [], coaches: [], supervisors: [], clients: [] },
      u1: { transactions: [{ id: "u1-t" }], products: [{ id: "u1-p" }], quotations: [{ id: "u1-q" }], members: [], gifts: [], coaches: [], supervisors: [], clients: [] },
      u2: { transactions: [{ id: "u2-t" }], products: [], quotations: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [] },
    },
  };
}
const ids = (arr) => (arr || []).map((x) => x.id);

// ------------------------------------------------------------------ resolveSectionPerm
test("resolveSectionPerm mirrors getPerm(): superadmin > override > role matrix > role fallback", () => {
  const d = base();
  assert.equal(resolveSectionPerm(d, SA, "products"), "write");
  assert.equal(resolveSectionPerm(d, ADM, "products"), "write", "admin falls back to write when the matrix is silent");
  assert.equal(resolveSectionPerm(d, U1, "products"), "hidden", "user falls back to hidden");
  assert.equal(resolveSectionPerm(d, U1, "marathon"), "write", "role matrix");
  d.userPermissions.u1 = { marathon: "hidden", products: "view" };
  assert.equal(resolveSectionPerm(d, U1, "marathon"), "hidden", "override beats role matrix (down)");
  assert.equal(resolveSectionPerm(d, U1, "products"), "view", "override beats role fallback (up)");
  assert.equal(resolveSectionPerm(d, U2, "marathon"), "write", "another user's override never applies to me");
});
test("resolveSectionPerm fails closed on junk values and hostile keys", () => {
  const d = base();
  d.userPermissions.u1 = { products: "superadmin", quotations: "WRITE", marathon: true };
  assert.equal(resolveSectionPerm(d, U1, "products"), "hidden");
  assert.equal(resolveSectionPerm(d, U1, "quotations"), "hidden", "case-sensitive: only exact 'view'/'write'");
  assert.equal(resolveSectionPerm(d, U1, "marathon"), "hidden", "non-string junk is hidden, not 'fall through to role'");
  assert.equal(resolveSectionPerm(d, { uid: "__proto__", role: "user" }, "products"), "hidden");
  assert.equal(resolveSectionPerm(d, { uid: "u1", role: "constructor" }, "products"), "hidden");
  assert.equal(resolveSectionPerm(d, { uid: "u1", role: "toString" }, "marathon"), "hidden");
  assert.equal(resolveSectionPerm(d, { uid: "u1", role: undefined }, "products"), "hidden");
  assert.equal(resolveSectionPerm({}, U1, "products"), "hidden");
  assert.equal(resolveSectionPerm(null, U1, "products"), "hidden");
  assert.equal(resolveSectionPerm(null, SA, "products"), "write", "superadmin never depends on stored data");
  assert.ok(canViewSection(base(), SA, "products") && canWriteSection(base(), SA, "products"));
});
test("the gate covers exactly Products, Quotations and Payments", () => {
  assert.deepEqual(GATED_SECTIONS.map((s) => [s.permKey, s.collection]), [["products", "products"], ["quotations", "quotations"], ["marathon", "transactions"]]);
});

// ------------------------------------------------------------------ READ: superadmin
test("1-3. Superadmin receives products, quotations and transactions (shared and every per-user bucket)", () => {
  const v = buildAuthorizedView(base(), SA);
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(ids(v.shared.quotations), ["q1", "q-adm"], "superadmin: every owner's quotations");
  assert.deepEqual(ids(v.shared.transactions), ["t1"]);
  assert.deepEqual(ids(v.perUser.u1.products), ["u1-p"]);
  assert.deepEqual(ids(v.perUser.u1.quotations), ["u1-q"]);
  assert.deepEqual(ids(v.perUser.u1.transactions), ["u1-t"]);
  assert.equal(v.activityLog.length, 4);
});
test("12. Superadmin cannot be locked out by an override or the role matrix", () => {
  const d = base();
  d.userPermissions.sa = { products: "hidden", quotations: "hidden", marathon: "hidden" };
  d.permissions.superadmin = { products: "hidden", quotations: "hidden", marathon: "hidden" };
  const v = buildAuthorizedView(d, SA);
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(ids(v.shared.quotations), ["q1", "q-adm"], "superadmin: all owners, whatever the matrix says");
  assert.deepEqual(ids(v.shared.transactions), ["t1"]);
  const saved = mergeAuthorizedSave(d, { ...clone(d), shared: { ...clone(d).shared, products: [{ id: "p1" }, { id: "p-new" }] } }, SA);
  assert.deepEqual(ids(saved.shared.products), ["p1", "p-new"], "superadmin can still write");
});

// ------------------------------------------------------------------ READ: hidden sections
test("4. User with Products hidden receives products=[] (shared AND own bucket)", () => {
  const v = buildAuthorizedView(base(), U1);
  assert.deepEqual(v.shared.products, []);
  assert.deepEqual(v.perUser.u1.products, []);
});
test("5. User with Quotations hidden receives quotations=[] — including invoice records", () => {
  const v = buildAuthorizedView(base(), U1);
  assert.deepEqual(v.shared.quotations, []);
  assert.deepEqual(v.perUser.u1.quotations, []);
  assert.ok(!JSON.stringify(v).includes("INV-1"), "no invoice number leaks anywhere in the payload");
  assert.ok(!JSON.stringify(v).includes("Secret Customer"));
});
test("6. User with Payments hidden receives transactions=[]", () => {
  const d = base(); d.userPermissions.u1 = { marathon: "hidden" };
  const v = buildAuthorizedView(d, U1);
  assert.deepEqual(v.shared.transactions, []);
  assert.deepEqual(v.perUser.u1.transactions, []);
  assert.ok(!JSON.stringify(v).includes("Secret Payer"));
});
test("7. Authorized user receives exactly the permitted sections, and only those", () => {
  const d = base(); d.userPermissions.u1 = { products: "view", quotations: "write" };
  const v = buildAuthorizedView(d, U1);
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(ids(v.shared.quotations), ["q1"]);
  assert.deepEqual(ids(v.shared.transactions), ["t1"], "role-default Payments still delivered");
  assert.deepEqual(ids(v.perUser.u1.products), ["u1-p"]);
});
test("8. Section filtering leaves every unrelated authorized dataset intact", () => {
  const before = buildAuthorizedView(base(), U1);
  const v = buildAuthorizedView(base(), U1);
  for (const k of ["gifts", "clients", "members", "coaches", "supervisors"]) assert.deepEqual(v.shared[k], before.shared[k], k);
  assert.deepEqual(ids(v.shared.members), ["m1"], "downline scoping still applies");
  assert.deepEqual(ids(v.shared.gifts), ["g1"]);
  assert.deepEqual(v.perUser.u1.members, []);
  assert.deepEqual(v.settings, base().settings);
  assert.deepEqual(v.permissions, base().permissions);
});
test("section permission NEVER widens scope: 'view' on Products does not expose other users' buckets or out-of-scope records", () => {
  const d = base(); d.userPermissions.u1 = { products: "write", quotations: "write", marathon: "write" };
  const v = buildAuthorizedView(d, U1);
  assert.deepEqual(Object.keys(v.perUser), ["u1"], "still only my own per-user bucket");
  assert.ok(!JSON.stringify(v.perUser).includes("sa-p") && !JSON.stringify(v.perUser).includes("u2-t"));
  assert.deepEqual(ids(v.shared.members), ["m1"], "still only my downline");
  assert.deepEqual(Object.keys(v.userPermissions), ["u1"]);
});
test("activity-log entries that name hidden-section records are withheld, others kept", () => {
  const d = base();
  const v = buildAuthorizedView(d, ADM); // admin, default section access
  // quotations/payments entries by an actor outside the admin's hierarchy ('sa') are withheld by the DATA SCOPE (not by the
  // section matrix): products + members remain.
  assert.deepEqual(v.activityLog.map((a) => a.coll), ["products", "members"]);
  d.permissions.admin = { quotations: "hidden", products: "hidden", marathon: "hidden" };
  const v2 = buildAuthorizedView(d, ADM);
  assert.deepEqual(v2.activityLog.map((a) => a.coll), ["members"]);
});
test("buildAuthorizedView never mutates the authoritative data it was given", () => {
  const d = base(); const snapshot = clone(d);
  buildAuthorizedView(d, U1); buildAuthorizedView(d, U2); buildAuthorizedView(d, SA);
  d.permissions.admin = { products: "hidden" }; const snap2 = clone(d);
  buildAuthorizedView(d, ADM);
  assert.deepEqual(d, snap2);
  assert.deepEqual(snapshot.shared, base().shared);
});

// ------------------------------------------------------------------ admin / other roles
test("5(model). Admin keeps default section access (Products etc.); Payments/Quotations are limited to their own hierarchy", () => {
  const v = buildAuthorizedView(base(), ADM);
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(ids(v.shared.quotations), ["q-adm"], "admin sees their OWN quotation, not u1's (u1 is outside their hierarchy) — no automatic 'all'");
  assert.deepEqual(Object.keys(v.perUser).sort(), ["sa", "u1", "u2"], "admin still receives every bucket (existing 'view as' model)");
  const d = base(); d.permissions.admin = { products: "hidden" };
  const v2 = buildAuthorizedView(d, ADM);
  assert.deepEqual(v2.shared.products, []);
  for (const b of Object.values(v2.perUser)) assert.deepEqual(b.products, [], "no per-user product leak through the admin's all-buckets view");
  assert.deepEqual(ids(v2.shared.quotations), ["q-adm"], "other sections unaffected (still hierarchy-scoped)");
});

// ------------------------------------------------------------------ forged identity / permissions
test("9. A user cannot forge their role to bypass filtering", () => {
  const d = base();
  const submitted = clone(d);
  submitted.users.find((u) => u.id === "u1").role = "superadmin";
  submitted.users.push({ id: "u1", role: "admin" });
  submitted.role = "superadmin";
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.equal(merged.users.find((u) => u.id === "u1").role, "user");
  const v = buildAuthorizedView(merged, U1);
  assert.deepEqual(v.shared.products, []);
  assert.deepEqual(v.shared.quotations, []);
  // and a caller object claiming a role the server did not verify is the Worker's job to prevent: it
  // only ever builds `caller` from the verified token claims (see login-worker.js resolveAuth).
});
test("10. A user cannot forge permissions (role matrix or own override) to bypass filtering", () => {
  const d = base();
  const submitted = clone(d);
  submitted.permissions.user = { products: "write", quotations: "write", marathon: "write", backup: "write" };
  submitted.userPermissions.u1 = { products: "write", quotations: "write" };
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(merged.permissions, d.permissions);
  assert.deepEqual(merged.userPermissions, d.userPermissions);
  const v = buildAuthorizedView(merged, U1);
  assert.deepEqual(v.shared.products, []);
  assert.deepEqual(v.shared.quotations, []);
});
test("11. A user cannot modify another user's permissions", () => {
  const d = base(); d.userPermissions.u2 = { products: "hidden" };
  const submitted = clone(d);
  submitted.userPermissions.u2 = { products: "write" };
  submitted.userPermissions.sa = { products: "hidden" };
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(merged.userPermissions, d.userPermissions);
});
test("An ADMIN also cannot rewrite the access settings (only a superadmin can)", () => {
  const d = base();
  const submitted = clone(d);
  submitted.userPermissions = { adm: { products: "write" }, u1: { products: "write", quotations: "write" } };
  submitted.permissions = { superadmin: {}, admin: { products: "write" }, user: { products: "write", quotations: "write", marathon: "write" } };
  const merged = mergeAuthorizedSave(d, submitted, ADM);
  assert.deepEqual(merged.userPermissions, d.userPermissions);
  assert.deepEqual(merged.permissions, d.permissions);
  assert.deepEqual(buildAuthorizedView(merged, U1).shared.products, []);
});
test("Superadmin CAN change access settings (Manage Access / Individual Access / Access Control keep working)", () => {
  const d = base();
  const submitted = clone(d);
  submitted.userPermissions = { u1: { products: "view" } };
  submitted.permissions = { ...d.permissions, user: { marathon: "write", quotations: "view" } };
  const merged = mergeAuthorizedSave(d, submitted, SA);
  assert.deepEqual(merged.userPermissions, { u1: { products: "view" } });
  assert.equal(merged.permissions.user.quotations, "view");
  const v = buildAuthorizedView(merged, U1);
  assert.deepEqual(ids(v.shared.products), ["p1"]);
  assert.deepEqual(ids(v.shared.quotations), ["q1"]);
});
test("A lower-level user cannot modify Superadmin's privileges or identity", () => {
  const d = base();
  const submitted = clone(d);
  submitted.users = submitted.users.filter((u) => u.id !== "sa");
  submitted.users.find((u) => u.id === "adm").role = "superadmin";
  const asAdmin = mergeAuthorizedSave(d, submitted, ADM);
  assert.ok(asAdmin.users.some((u) => u.id === "sa" && u.role === "superadmin"), "superadmin cannot be deleted by an admin");
  assert.equal(asAdmin.users.find((u) => u.id === "adm").role, "admin", "admin cannot promote themselves");
  const asUser = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(asUser.users, d.users);
});

// ------------------------------------------------------------------ WRITE
test("Hidden-section user: submitted products/quotations/transactions cannot change or wipe server data (shared or own bucket)", () => {
  const d = base(); d.settings.dataSharing = false; d.userPermissions.u1 = { marathon: "hidden" };
  const submitted = clone(d);
  submitted.shared.products = []; submitted.shared.quotations = [{ id: "evil" }]; submitted.shared.transactions = [];
  submitted.perUser.u1.products = [{ id: "evil-p" }]; submitted.perUser.u1.quotations = []; submitted.perUser.u1.transactions = [{ id: "evil-t" }];
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(merged.shared.products, d.shared.products);
  assert.deepEqual(merged.shared.quotations, d.shared.quotations);
  assert.deepEqual(merged.shared.transactions, d.shared.transactions);
  assert.deepEqual(merged.perUser.u1.products, d.perUser.u1.products);
  assert.deepEqual(merged.perUser.u1.quotations, d.perUser.u1.quotations);
  assert.deepEqual(merged.perUser.u1.transactions, d.perUser.u1.transactions);
});
test("Echoing the filtered view back (products=[]) is a no-op, not a deletion — the normal round trip is safe", () => {
  const d = base();
  const view = buildAuthorizedView(d, U1);             // u1 sees products=[] / quotations=[]
  const submitted = { ...clone(d), shared: view.shared, perUser: { ...clone(d).perUser, u1: view.perUser.u1 } };
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(merged.shared.products, d.shared.products);
  assert.deepEqual(merged.shared.quotations, d.shared.quotations);
  assert.deepEqual(merged.perUser.u1.products, d.perUser.u1.products);
  assert.deepEqual(merged.perUser.u1.quotations, d.perUser.u1.quotations);
});
test("View-only user cannot modify that section; write user can (own bucket, per-user mode)", () => {
  const d = base(); d.settings.dataSharing = false;
  d.userPermissions.u1 = { products: "view", quotations: "write" };
  const submitted = clone(d);
  submitted.perUser.u1.products = [{ id: "u1-p" }, { id: "added" }];
  submitted.perUser.u1.quotations = [{ id: "u1-q" }, { id: "added-q" }];
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(ids(merged.perUser.u1.products), ["u1-p"], "view-only: write discarded");
  assert.deepEqual(ids(merged.perUser.u1.quotations), ["u1-q", "added-q"], "write: honoured for own bucket");
});
test("Stale-data replay: a user whose access was revoked cannot restore it by re-submitting their old view/permissions", () => {
  const granted = base(); granted.userPermissions.u1 = { products: "write" };
  const staleView = buildAuthorizedView(granted, U1);            // what the client last saw, while it had access
  const revoked = base();                                        // superadmin has since revoked (no override)
  const submitted = { ...clone(revoked), userPermissions: { u1: { products: "write" } }, shared: { ...clone(revoked).shared, products: [...staleView.shared.products, { id: "resurrected" }] } };
  const merged = mergeAuthorizedSave(revoked, submitted, U1);
  assert.deepEqual(merged.userPermissions, revoked.userPermissions, "stale grant is not restored");
  assert.deepEqual(merged.shared.products, revoked.shared.products, "stale product write is discarded");
  assert.deepEqual(buildAuthorizedView(merged, U1).shared.products, []);
});
test("Shared-data writes cannot be used to bypass section authorization", () => {
  const d = base();
  const submitted = clone(d);
  submitted.shared = { ...submitted.shared, products: [], quotations: [], transactions: [], clients: [{ id: "c-new" }] };
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(merged.shared.products, d.shared.products);
  assert.deepEqual(merged.shared.quotations, d.shared.quotations);
  assert.deepEqual(merged.shared.transactions, d.shared.transactions);
  assert.deepEqual(merged.shared.clients, d.shared.clients, "existing behaviour retained");
});
test("Admin with only 'view' on a section cannot write it; a brand-new bucket created without write starts empty", () => {
  const d = base(); d.permissions.admin = { products: "view" };
  const submitted = clone(d);
  submitted.shared.products = [{ id: "hax" }];
  submitted.perUser.newbie = { products: [{ id: "x" }], quotations: [{ id: "qq" }], transactions: [] };
  submitted.perUser.adm = { products: [{ id: "x2" }], quotations: [{ id: "qq2" }], transactions: [] };
  const merged = mergeAuthorizedSave(d, submitted, ADM);
  assert.deepEqual(merged.shared.products, d.shared.products);
  assert.deepEqual(merged.perUser.newbie.products, [], "no write on products => new bucket cannot smuggle any in");
  assert.deepEqual(merged.perUser.newbie.quotations, [], "newbie is outside the admin's hierarchy: nothing can be written into their Quotations");
  assert.deepEqual(ids(merged.perUser.adm.quotations), ["qq2"], "quotations is still writable for this admin in their OWN bucket");
  assert.deepEqual(merged.perUser.adm.products, [], "products: view-only => the write is discarded");
});
test("Unrelated sections still save normally for a restricted user (no collateral damage)", () => {
  const d = base(); d.settings.dataSharing = false;
  const submitted = clone(d);
  submitted.perUser.u1.gifts = [{ id: "new-gift" }];
  submitted.perUser.u1.members = [{ id: "mm", supervisorId: "supA" }];
  const merged = mergeAuthorizedSave(d, submitted, U1);
  assert.deepEqual(ids(merged.perUser.u1.gifts), ["new-gift"]);
  assert.deepEqual(ids(merged.perUser.u1.members), ["mm"]);
  assert.deepEqual(ids(merged.perUser.u1.transactions), ["u1-t"], "Payments (role default write) untouched");
});
test("mergeAuthorizedSave does not mutate the server data or the submitted payload", () => {
  const d = base(); const s = clone(d); s.shared.products = [{ id: "z" }];
  const dSnap = clone(d), sSnap = clone(s);
  mergeAuthorizedSave(d, s, U1); mergeAuthorizedSave(d, s, ADM); mergeAuthorizedSave(d, s, SA);
  assert.deepEqual(d, dSnap); assert.deepEqual(s, sSnap);
});
