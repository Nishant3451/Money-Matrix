// ============================================================================================
// RECORD-LEVEL ACL -- DELEGATED EDIT / DELETE / ACL grants for NON-ADMIN users, end to end through the Worker.
//
// Hierarchy (all non-admin except adm/root):
//            n_boss (boss)
//        /       |        \
//   n_mgr (mgr)  n_other   n_adm (adm, admin)
//        |        (other)
//   n_emp (emp)
// From MGR's view: upline = [boss], downline = [emp]; `other` and `adm` are unrelated to mgr.
// Rule under test: an explicit grant extends write access to a specific record ONLY inside the existing Data Scope write
// ceiling (owner in mine+downline) and section permission "write"; it never reaches upline, outsiders, or All Data.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { rec, g, acl, find, makeDoc, makeWorld, call, getView, save, setAcl, stored } from "./helpers/aclWorld.js";

const SUPS = [
  { id: "n_boss", supervisorId: null }, { id: "n_mgr", supervisorId: "n_boss" }, { id: "n_emp", supervisorId: "n_mgr" },
  { id: "n_other", supervisorId: "n_boss" }, { id: "n_adm", supervisorId: "n_boss" },
];
const USERS = [
  { id: "root", username: "root", role: "superadmin", linkedId: null },
  { id: "boss", username: "boss", role: "user", linkedId: "n_boss" },
  { id: "mgr", username: "mgr", role: "user", linkedId: "n_mgr" },
  { id: "emp", username: "emp", role: "user", linkedId: "n_emp" },
  { id: "other", username: "other", role: "user", linkedId: "n_other" },
  { id: "adm", username: "adm", role: "admin", linkedId: "n_adm" },
];
const mk = (o = {}) => makeDoc({ users: USERS, sups: SUPS, ...o });
/** perUser-mode doc: emp's bucket holds `records` in `coll`. */
const bucketDoc = (records, coll = "transactions", o = {}) =>
  mk({ perUser: { emp: { transactions: coll === "transactions" ? records : [], quotations: coll === "quotations" ? records : [] } }, ...o });
const inBucket = (w, id, coll = "transactions") => find(w.state.doc.perUser.emp[coll], id);
const del = (coll, bucket, id) => ({ coll, bucket, id });
const asDelete = (list) => (v) => { v.recordDeletes = list; };
const COLLS = ["transactions", "quotations"];

// --------------------------------------------------------------------------------------------
test("baseline: the OWNER (non-admin) still edits and deletes records in their own bucket through the normal path", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp"), rec("p2", "emp")]));
  await save(w, "emp", (v) => { find(v.perUser.emp.transactions, "p1").customer = "mine"; v.perUser.emp.transactions = v.perUser.emp.transactions.filter((r) => r.id !== "p2"); });
  assert.equal(inBucket(w, "p1").customer, "mine");
  assert.equal(inBucket(w, "p2"), undefined);
});

test("an INHERIT record in another user's bucket stays READ-ONLY for a non-admin (existing behavior); only an explicit grant makes it writable", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp")]));
  const v = await getView(w, "mgr");
  assert.deepEqual(v.perUser.emp.transactions.map((r) => r.id), ["p1"], "in-scope records are readable, exactly as before ACLs");
  await call(w, "mgr", "/data/save", { json: JSON.stringify({ perUser: { emp: { transactions: [{ id: "p1", ownerId: "emp", customer: "HACK" }] } }, recordDeletes: [del("transactions", "emp", "p1")] }) });
  assert.deepEqual(inBucket(w, "p1"), rec("p1", "emp"));
});

for (const coll of COLLS) {
  test(`[${coll}] delegated VIEW: visible with the ACL list hidden; cannot edit or delete`, async () => {
    const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr")]) }), rec("p2", "emp")], coll));
    const v = await getView(w, "mgr");
    assert.deepEqual(v.perUser.emp[coll].map((r) => r.id).sort(), ["p1", "p2"]);
    assert.equal("acl" in find(v.perUser.emp[coll], "p1"), false);
    await save(w, "mgr", (x) => { find(x.perUser.emp[coll], "p1").customer = "HACK"; asDelete([del(coll, "emp", "p1")])(x); });
    assert.equal(inBucket(w, "p1", coll).customer, "cust-p1");
  });

  test(`[${coll}] delegated EDIT: the edit lands; ownerId and acl stay server-owned; EDIT does not imply DELETE or ACL`, async () => {
    const a = acl(1, [g("mgr", "edit")]);
    const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: a })], coll));
    await save(w, "mgr", (x) => { const r = find(x.perUser.emp[coll], "p1"); r.customer = "edited by mgr"; r.amount = 7; r.ownerId = "mgr"; r.acl = acl(9, [g("mgr", "edit", "delete", "acl")]); });
    const r = inBucket(w, "p1", coll);
    assert.equal(r.customer, "edited by mgr");
    assert.equal(r.amount, 7);
    assert.equal(r.ownerId, "emp");
    assert.deepEqual(r.acl, a);
    // not DELETE (explicit or by absence)
    await save(w, "mgr", (x) => { asDelete([del(coll, "emp", "p1")])(x); delete x.perUser.emp; });
    assert.ok(inBucket(w, "p1", coll), "EDIT alone cannot delete");
    // not ACL management
    assert.equal((await call(w, "mgr", "/record/acl", { collection: coll, bucket: "emp", id: "p1", baseRev: 1, grants: [g("mgr", "edit", "acl")] })).status, 403);
    assert.deepEqual(inBucket(w, "p1", coll).acl, a);
  });

  test(`[${coll}] delegated DELETE (without EDIT): explicit delete works, edits are ignored`, async () => {
    const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "delete")]) }), rec("p2", "emp", { acl: acl(1, [g("mgr", "delete")]) })], coll));
    await save(w, "mgr", (x) => { find(x.perUser.emp[coll], "p1").customer = "HACK"; });
    assert.equal(inBucket(w, "p1", coll).customer, "cust-p1", "no EDIT => content unchanged");
    await save(w, "mgr", asDelete([del(coll, "emp", "p1")]));
    assert.equal(inBucket(w, "p1", coll), undefined, "explicit delete honored");
    assert.ok(inBucket(w, "p2", coll), "only the named record is removed");
  });

  test(`[${coll}] delegated ACL management: allowed within the manager's own permissions; cannot edit; cannot escalate`, async () => {
    const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "acl")]) })], coll));
    const body = (baseRev, grants) => ({ collection: coll, bucket: "emp", id: "p1", baseRev, grants });
    // may add a view-only entry (a permission mgr holds)
    assert.equal((await call(w, "mgr", "/record/acl", body(1, [g("mgr", "acl"), g("boss")]))).status, 200);
    // may NOT grant edit/delete (not held), change own entry, or reset to inherit
    for (const grants of [[g("mgr", "acl"), g("boss", "edit")], [g("mgr", "acl"), g("boss", "delete")], [g("mgr", "edit", "acl"), g("boss")], [g("boss")]]) {
      assert.equal((await call(w, "mgr", "/record/acl", body(2, grants))).status, 403, JSON.stringify(grants));
    }
    assert.equal((await call(w, "mgr", "/record/acl", body(2, null))).status, 403);
    // holding `acl` does not allow editing content
    await save(w, "mgr", (x) => { find(x.perUser.emp[coll], "p1").customer = "HACK"; });
    assert.equal(inBucket(w, "p1", coll).customer, "cust-p1");
    assert.deepEqual(inBucket(w, "p1", coll).acl, acl(2, [g("boss"), g("mgr", "acl")]));
  });
}

test("EDIT without DELETE and DELETE without EDIT, side by side", async () => {
  const w = makeWorld(bucketDoc([rec("e", "emp", { acl: acl(1, [g("mgr", "edit")]) }), rec("d", "emp", { acl: acl(1, [g("mgr", "delete")]) })]));
  await save(w, "mgr", (x) => {
    find(x.perUser.emp.transactions, "e").customer = "E!"; find(x.perUser.emp.transactions, "d").customer = "D!";
    x.recordDeletes = [del("transactions", "emp", "e"), del("transactions", "emp", "d")];
  });
  assert.equal(inBucket(w, "e").customer, "E!", "edit-only record: edited, NOT deleted");
  assert.equal(inBucket(w, "d"), undefined, "delete-only record: deleted");
});

test("shared-mode records work the same way (grantee edits a shared record owned by a downline user)", async () => {
  const a = acl(1, [g("mgr", "edit")]);
  const w = makeWorld(mk({ tx: [rec("s1", "emp", { acl: a }), rec("s2", "emp")] }));
  await save(w, "mgr", (x) => { find(x.shared.transactions, "s1").customer = "shared-edit"; find(x.shared.transactions, "s2").customer = "HACK"; });
  assert.equal(stored(w, "s1").customer, "shared-edit");
  assert.equal(stored(w, "s2").customer, "cust-s2", "an un-granted inherit record stays unwritable for a non-admin");
  assert.deepEqual(stored(w, "s1").acl, a);
  assert.equal(stored(w, "s1").ownerId, "emp");
  await save(w, "mgr", (x) => { x.shared.transactions = []; });
  assert.ok(stored(w, "s1") && stored(w, "s2"), "absence is never a delete for non-admin roles");
  const w2 = makeWorld(mk({ tx: [rec("s1", "emp", { acl: acl(1, [g("mgr", "delete")]) })] }));
  await save(w2, "mgr", asDelete([del("transactions", null, "s1")]));
  assert.equal(stored(w2, "s1"), undefined);
});

test("ABSENCE IS NEVER A DELETE for delegated records: a stale client that never received a fresh DELETE grant cannot destroy the record", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp")]));
  const staleView = await getView(w, "mgr"); // loaded BEFORE p9 existed / was granted
  assert.equal(find(staleView.perUser.emp.transactions, "p9"), undefined);
  w.state.doc.perUser.emp.transactions.push(rec("p9", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })); // appears after the client loaded
  const r = await call(w, "mgr", "/data/save", { json: JSON.stringify(staleView) });
  assert.equal(r.status, 200);
  assert.ok(inBucket(w, "p9"), "record the stale client never saw survives");
  assert.equal(inBucket(w, "p9").customer, "cust-p9");
  // and a client that DID receive it but drops it from its blob (no explicit request) also cannot delete it
  const fresh = await getView(w, "mgr");
  fresh.perUser.emp.transactions = fresh.perUser.emp.transactions.filter((x) => x.id !== "p9");
  await call(w, "mgr", "/data/save", { json: JSON.stringify(fresh) });
  assert.ok(inBucket(w, "p9"));
});

for (const coll of COLLS) {
  test(`[${coll}] SHARED mode: a DELETE grant is honored only by an EXPLICIT request; dropping the record from the blob never deletes it`, async () => {
    const opts = coll === "transactions" ? { tx: [rec("s1", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })] } : { q: [rec("s1", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })] };
    const w = makeWorld(mk(opts));
    const read = () => find(w.state.doc.shared[coll], "s1");
    // (a) the grantee's blob simply lacks the record (stale client / partial blob): nothing is deleted
    await save(w, "mgr", (x) => { x.shared[coll] = x.shared[coll].filter((r) => r.id !== "s1"); });
    assert.ok(read(), "absence from the blob must not delete a delegated shared record, even with a DELETE grant");
    // (b) whole collection omitted
    await save(w, "mgr", (x) => { delete x.shared[coll]; });
    assert.ok(read(), "omitting the collection must not delete it either");
    // (c) only the explicit request deletes it
    await save(w, "mgr", asDelete([del(coll, null, "s1")]));
    assert.equal(read(), undefined);
  });
}

// --------------------------------------------------------------------------------------------
test("UPLINE stays read-only for non-admins too: emp is granted edit+delete+acl on its UPLINE mgr's record and can do none of it", async () => {
  for (const mode of ["shared", "bucket"]) {
    const doc = mode === "shared"
      ? mk({ tx: [rec("u1", "mgr", { acl: acl(1, [g("emp", "edit", "delete", "acl")]) })] })
      : mk({ perUser: { mgr: { transactions: [rec("u1", "mgr", { acl: acl(1, [g("emp", "edit", "delete", "acl")]) })], quotations: [] } } });
    const w = makeWorld(doc);
    const v = await getView(w, "emp");
    const delivered = mode === "shared" ? find(v.shared.transactions, "u1") : find((v.perUser.mgr || {}).transactions, "u1");
    assert.ok(delivered, `${mode}: readable`);
    const read = () => (mode === "shared" ? stored(w, "u1") : find(w.state.doc.perUser.mgr.transactions, "u1"));
    await save(w, "emp", (x) => {
      const arr = mode === "shared" ? x.shared.transactions : x.perUser.mgr.transactions;
      find(arr, "u1").customer = "HACK";
      x.recordDeletes = [del("transactions", mode === "shared" ? null : "mgr", "u1")];
    });
    assert.equal(read().customer, "cust-u1", `${mode}: not editable`);
    assert.ok(read(), `${mode}: not deletable`);
    const r = await call(w, "emp", "/record/acl", { collection: "transactions", bucket: mode === "shared" ? null : "mgr", id: "u1", baseRev: 1, grants: [] });
    assert.equal(r.status, 403, `${mode}: ACL not manageable`);
  }
});

test("DOWNLINE: boss (non-admin) granted edit+delete on a deep downline user's record can use it; un-granted downline records stay untouched", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("boss", "edit", "delete")]) }), rec("p2", "emp"), rec("p3", "emp", { acl: acl(1, [g("boss")]) })]));
  const v = await getView(w, "boss");
  assert.deepEqual(v.perUser.emp.transactions.map((r) => r.id).sort(), ["p1", "p2", "p3"]);
  await save(w, "boss", (x) => { find(x.perUser.emp.transactions, "p1").customer = "boss-edit"; find(x.perUser.emp.transactions, "p3").customer = "HACK"; });
  assert.equal(inBucket(w, "p1").customer, "boss-edit");
  assert.equal(inBucket(w, "p3").customer, "cust-p3", "view-only grant");
  await save(w, "boss", asDelete([del("transactions", "emp", "p1"), del("transactions", "emp", "p2"), del("transactions", "emp", "p3")]));
  assert.equal(inBucket(w, "p1"), undefined);
  assert.ok(inBucket(w, "p2") && inBucket(w, "p3"), "no grant / view-only => not deleted");
});

test("GRANT OUTSIDE DATA SCOPE is inert; no ACL ever grants All Data; an admin gains nothing either", async () => {
  const w = makeWorld(mk({ perUser: {
    mgr: { transactions: [rec("m1", "mgr", { acl: acl(1, [g("other", "edit", "delete", "acl")]) })], quotations: [] },
    other: { transactions: [rec("o1", "other", { acl: acl(1, [g("mgr", "edit", "delete", "acl"), g("adm", "edit", "delete", "acl")]) })], quotations: [] },
  } }));
  // other is not in mgr's hierarchy
  assert.equal((await getView(w, "other")).perUser.mgr, undefined);
  await call(w, "other", "/data/save", { json: JSON.stringify({ perUser: { mgr: { transactions: [{ id: "m1", ownerId: "mgr", customer: "HACK" }] } }, recordDeletes: [del("transactions", "mgr", "m1")] }) });
  assert.deepEqual(find(w.state.doc.perUser.mgr.transactions, "m1").customer, "cust-m1");
  // the reverse: mgr granted on other's record
  assert.equal((await getView(w, "mgr")).perUser.other, undefined);
  await call(w, "mgr", "/data/save", { json: JSON.stringify({ perUser: { other: { transactions: [{ id: "o1", ownerId: "other", customer: "HACK" }] } }, recordDeletes: [del("transactions", "other", "o1")] }) });
  assert.equal(find(w.state.doc.perUser.other.transactions, "o1").customer, "cust-o1");
  // an ADMIN granted everything on a record outside its scope: still nothing (and no All Data)
  const admView = await getView(w, "adm");
  assert.deepEqual((admView.perUser.other || {}).transactions || [], [], "out-of-scope bucket arrives with its Payments emptied (existing behavior), grants notwithstanding");
  assert.equal((await call(w, "adm", "/data/get", { scope: "all" })).status, 403);
  await call(w, "adm", "/data/save", { json: JSON.stringify({ perUser: { other: { transactions: [{ id: "o1", ownerId: "other", customer: "HACK" }] } }, recordDeletes: [del("transactions", "other", "o1")] }) });
  assert.ok(find(w.state.doc.perUser.other.transactions, "o1"));
  assert.equal((await call(w, "mgr", "/record/acl", { collection: "transactions", bucket: "other", id: "o1", baseRev: 1, grants: [] })).status, 404);
});

test("HIERARCHY CHANGE after a grant: the moment the owner leaves the grantee's downline the grant stops working (server re-derives scope per request)", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit", "delete", "acl")]) })]));
  await save(w, "mgr", (x) => { find(x.perUser.emp.transactions, "p1").customer = "before"; });
  assert.equal(inBucket(w, "p1").customer, "before");
  w.state.doc.shared.supervisors.find((s) => s.id === "n_emp").supervisorId = "n_other"; // emp moves away from mgr
  assert.equal((await getView(w, "mgr")).perUser.emp, undefined, "the owner left mgr's scope: nothing of that bucket is delivered");
  await call(w, "mgr", "/data/save", { json: JSON.stringify({ perUser: { emp: { transactions: [{ id: "p1", ownerId: "emp", customer: "after" }] } }, recordDeletes: [del("transactions", "emp", "p1")] }) });
  assert.equal(inBucket(w, "p1").customer, "before");
  assert.equal((await call(w, "mgr", "/record/acl", { collection: "transactions", bucket: "emp", id: "p1", baseRev: 1, grants: [] })).status, 404);
});

test("REVOKED grant: later writes are refused, including from a stale client that still holds the record", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })]));
  const stale = await getView(w, "mgr");
  assert.equal((await call(w, "emp", "/record/acl", { collection: "transactions", bucket: "emp", id: "p1", baseRev: 1, grants: [g("mgr")] })).status, 200); // downgrade to view
  find(stale.perUser.emp.transactions, "p1").customer = "stale-edit";
  stale.recordDeletes = [del("transactions", "emp", "p1")];
  await call(w, "mgr", "/data/save", { json: JSON.stringify(stale) });
  assert.equal(inBucket(w, "p1").customer, "cust-p1");
  assert.ok(inBucket(w, "p1"));
  assert.equal((await call(w, "emp", "/record/acl", { collection: "transactions", bucket: "emp", id: "p1", baseRev: 2, grants: [] })).status, 200); // full revoke
  assert.deepEqual(((await getView(w, "mgr")).perUser.emp || {}).transactions || [], [], "a private record is no longer even readable");
});

test("STALE ACL REVISION is refused for delegated managers too", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "acl")]) })]));
  const body = (baseRev, grants) => ({ collection: "transactions", bucket: "emp", id: "p1", baseRev, grants });
  assert.equal((await call(w, "emp", "/record/acl", body(1, [g("mgr", "acl"), g("boss")]))).status, 200); // rev 2 by owner
  const stale = await call(w, "mgr", "/record/acl", body(1, [g("mgr", "acl")]));
  assert.equal(stale.status, 409);
  assert.equal(stale.json.error.code, "ACL_STALE");
  assert.equal(stale.json.error.currentRev, 2);
  assert.deepEqual(inBucket(w, "p1").acl, acl(2, [g("boss"), g("mgr", "acl")]));
});

test("FORGED recordDeletes / blobs: malformed lists, wrong collections, prototype keys and huge lists never delete anything", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr")]) }), rec("p2", "emp")]));
  const lists = [
    "p1", { coll: "transactions", bucket: "emp", id: "p1" }, 5, null,
    [null, 5, "p1", [], { coll: "transactions", bucket: "emp" }, { coll: "members", bucket: "emp", id: "p1" }, { coll: "transactions", bucket: "emp", id: "p1", extra: 1 },
     { coll: "transactions", bucket: "", id: "p1" }, { coll: "transactions", bucket: 5, id: "p1" }, { coll: "transactions", bucket: "emp", id: { $ne: "" } }, { coll: "transactions", bucket: "emp", id: "p1" }],
    Array.from({ length: 5000 }, (_, i) => ({ coll: "transactions", bucket: "emp", id: `x${i}` })),
  ];
  for (const list of lists.slice(0, 4)) await save(w, "mgr", (v) => { v.recordDeletes = list; });
  await save(w, "mgr", (v) => { v.recordDeletes = lists[4]; }); // the only well-formed entry targets p1 where mgr has VIEW only
  await save(w, "mgr", (v) => { v.recordDeletes = lists[5]; });
  assert.ok(inBucket(w, "p1") && inBucket(w, "p2"));
  const raw = '{"perUser":{"emp":{"transactions":[{"id":"p1","__proto__":{"edit":true}}]}},"recordDeletes":[{"coll":"transactions","bucket":"__proto__","id":"p1"},{"coll":"transactions","bucket":"emp","id":"p1","__proto__":{"x":1}}]}';
  await call(w, "mgr", "/data/save", { json: raw });
  assert.ok(inBucket(w, "p1") && inBucket(w, "p2"));
  assert.equal({}.edit, undefined);
});

test("SECTION permission stays mandatory: a Payments-view-only grantee cannot write; a Payments-hidden grantee receives nothing", async () => {
  const doc = bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })], "transactions", { permissions: { user: { marathon: "view", quotations: "write" } } });
  const w = makeWorld(doc);
  assert.equal(((await getView(w, "mgr")).perUser.emp.transactions).length, 1, "view-only section still receives it");
  await save(w, "mgr", (x) => { find(x.perUser.emp.transactions, "p1").customer = "HACK"; x.recordDeletes = [del("transactions", "emp", "p1")]; });
  assert.equal(inBucket(w, "p1").customer, "cust-p1");
  assert.ok(inBucket(w, "p1"));
  const w2 = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit", "delete")]) })], "transactions", { permissions: { user: { marathon: "hidden" } } }));
  const v = await getView(w2, "mgr");
  assert.deepEqual((v.perUser.emp || {}).transactions || [], [], "Payments section hidden => nothing delivered");
  await call(w2, "mgr", "/data/save", { json: JSON.stringify({ perUser: { emp: { transactions: [{ id: "p1", ownerId: "emp", customer: "HACK" }] } }, recordDeletes: [del("transactions", "emp", "p1")] }) });
  assert.equal(inBucket(w2, "p1").customer, "cust-p1");
});

test("the SCOPE the grantee selected is respected: asking for 'mine' does not deliver a granted downline record", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit")]) })]));
  assert.equal((await getView(w, "mgr", "mine")).perUser.emp, undefined);
  assert.equal((await getView(w, "mgr", "downline")).perUser.emp.transactions.length, 1);
  assert.equal((await getView(w, "mgr", "upline")).perUser.emp, undefined);
});

test("superadmin: explicit recordDeletes work for any record (and absence still works as before); nobody else's grants are needed", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, []) }), rec("p2", "emp", { acl: "junk" })]));
  await save(w, "root", asDelete([del("transactions", "emp", "p1")]));
  assert.equal(inBucket(w, "p1"), undefined);
  assert.ok(inBucket(w, "p2"));
});

test("forged ownerId / ACL from a delegated EDITOR through direct API calls (hand-built blobs) change nothing", async () => {
  const a = acl(3, [g("mgr", "edit")]);
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: a })]));
  const blob = { perUser: { emp: { transactions: [{ id: "p1", ownerId: "mgr", customer: "ok", amount: 1, acl: acl(99, [g("mgr", "edit", "delete", "acl"), g("other", "edit")]) }] }, mgr: { transactions: [{ id: "p1", ownerId: "mgr", customer: "planted", acl: acl(1, []) }], quotations: [] } } };
  await call(w, "mgr", "/data/save", { json: JSON.stringify(blob) });
  const r = inBucket(w, "p1");
  assert.equal(r.customer, "ok");
  assert.equal(r.ownerId, "emp");
  assert.deepEqual(r.acl, a);
  const planted = find(w.state.doc.perUser.mgr.transactions, "p1");
  assert.equal("acl" in planted, false, "a record the grantee creates in their OWN bucket is always inherit");
});

// --------------------------------------------------------------------------------------------
test("CONCURRENT: a delegated edit racing the owner's revocation is re-evaluated on retry and refused", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit")]) })]));
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const pending = save(w, "mgr", (x) => { find(x.perUser.emp.transactions, "p1").customer = "racing-edit"; });
  await hit;
  assert.equal((await call(w, "emp", "/record/acl", { collection: "transactions", bucket: "emp", id: "p1", baseRev: 1, grants: [] })).status, 200);
  release();
  assert.equal((await pending).status, 200);
  assert.ok(w.conflicts >= 1, "a real precondition conflict was retried");
  assert.equal(inBucket(w, "p1").customer, "cust-p1", "the revoked grantee's racing edit must not land");
  assert.deepEqual(inBucket(w, "p1").acl, acl(2, []));
});

// --------------------------------------------------------------------------------------------
test("ACTIVITY LOG: grantee entries are stamped with the verified actor; visibility follows the referenced record, never names", async () => {
  const w = makeWorld(bucketDoc([rec("p1", "emp", { acl: acl(1, [g("mgr", "edit")]) })]));
  await save(w, "mgr", (x) => {
    find(x.perUser.emp.transactions, "p1").customer = "SECRET EDIT";
    x.activityLog = [{ ts: Date.now(), user: "boss", action: "updated", coll: "transactions", name: "SECRET EDIT", scopeId: "n_emp", actorUid: "boss", recId: "p1", recBucket: "emp" }, ...x.activityLog];
  });
  const entry = w.state.doc.activityLog.find((e) => e.name === "SECRET EDIT");
  assert.equal(entry.actorUid, "mgr", "forged actorUid replaced by the verified caller");
  const seen = async (uid) => (await getView(w, uid)).activityLog.some((e) => e.name === "SECRET EDIT");
  assert.equal(await seen("mgr"), true, "grantee: actor + can view");
  assert.equal(await seen("emp"), true, "owner");
  assert.equal(await seen("root"), true);
  assert.equal(await seen("boss"), false, "boss (in scope, display-name collision with the forged `user`) cannot view the record => cannot see the entry");
  // once the record is inherit again, anyone in scope may view it, so the entry that REFERENCES it follows that visibility:
  assert.equal((await call(w, "emp", "/record/acl", { collection: "transactions", bucket: "emp", id: "p1", baseRev: 1, grants: null })).status, 200);
  assert.equal(await seen("boss"), true, "boss can now view the (inherit) record, so the referenced entry follows");
});
