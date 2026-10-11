// ============================================================================================
// ASSIGNING Payments and Quotations to specific users ("Assigned To") and keeping ownership server-controlled.
// POST /record/assign + the ownership rules of /data/save, end to end through the real Worker.
//
//   top(admin) -+- mid(admin) -- low(user)      dev = developer, root = superadmin, other = unrelated user
//               +- peer(user)
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { rec, g, acl, find, call, getView, save, makeDevWorld, devDoc, DEV_USERS, DEV_SUPS } from "./helpers/devWorld.js";
import { assignableTargets, buildRecordAccessContext } from "../lib/authorization.js";
import { computeAssignment } from "../lib/recordAssign.js";

const world = (o = {}) => makeDevWorld(devDoc({
  tx: [rec("t_low", "low"), rec("t_mid", "mid"), rec("t_top", "top"), rec("t_peer", "peer"), rec("t_other", "other")],
  q: [rec("q_low", "low"), rec("q_mid", "mid"), rec("q_top", "top")],
  ...o,
}));
const assign = (w, uid, body, coll = "transactions") => call(w, uid, "/record/assign", { collection: coll, bucket: null, ...body });
const owner = (w, id, coll = "transactions") => find(w.state.doc.shared[coll], id).ownerId;
const uids = (list) => list.map((x) => x.uid);
const targetsFor = (w, uid, coll = "transactions") => {
  const u = w.state.doc.users.find((x) => x.id === uid);
  return uids(assignableTargets(w.state.doc, { uid, role: u.role, linkedId: u.linkedId || null }, coll));
};

// ============================================================================================
// 19 / 20. Developer and superadmin assign anywhere (to any ACTIVE user)
// ============================================================================================
test("DEVELOPER assigns a Payment and a Quotation to any eligible active user; the audit trail records it", async () => {
  const w = world();
  const r = await assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid: "other" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.data, { owner: "other", changed: true });
  assert.equal(owner(w, "t_low"), "other");
  const q = await assign(w, "dev", { id: "q_mid", expectedOwner: "mid", targetUid: "root" }, "quotations");
  assert.equal(q.status, 200);
  assert.equal(owner(w, "q_mid", "quotations"), "root");
  const a = w.state.doc.accessAudit[1];
  assert.equal(a.action, "assign");
  assert.equal(a.actor, "dev");
  assert.equal(a.recId, "t_low");
  assert.equal(a.from, "low");
  assert.equal(a.to, "other");
  // the new owner sees it (as My Data), the old owner no longer does
  assert.ok(find((await getView(w, "other", "mine")).shared.transactions, "t_low"));
  assert.equal(find((await getView(w, "low", "mine")).shared.transactions, "t_low"), undefined);
});

test("SUPERADMIN assigns across users under its authority; once the Developer removes its All Data it can only assign inside its hierarchy", async () => {
  const w = world();
  assert.equal((await assign(w, "root", { id: "t_peer", expectedOwner: "peer", targetUid: "mid" })).status, 200);
  assert.equal(owner(w, "t_peer"), "mid");
  assert.equal((await assign(w, "root", { id: "t_other", expectedOwner: "other", targetUid: "dev" })).status, 200, "to the Developer too");
  assert.equal((await call(w, "dev", "/scope/policy", { baseRev: 0, user: { uid: "root", policy: { all: false } } })).status, 200);
  // root now holds only its own data and has no hierarchy
  const refused = await assign(w, "root", { id: "t_low", expectedOwner: "low", targetUid: "root" });
  assert.equal(refused.status, 404, "no longer even able to see other people's records");
  assert.deepEqual(targetsFor(w, "root"), ["root"]);
});

// ============================================================================================
// 21. Everyone else is bound to their own hierarchy and authority
// ============================================================================================
test("ADMIN assigns only inside mine + downline: never to upline, unrelated users, superadmin or developer", async () => {
  const w = world();
  assert.deepEqual(targetsFor(w, "top"), ["low", "mid", "peer", "top"]);
  assert.deepEqual(targetsFor(w, "mid"), ["low", "mid"]);
  assert.equal((await assign(w, "top", { id: "t_low", expectedOwner: "low", targetUid: "peer" })).status, 200);
  assert.equal(owner(w, "t_low"), "peer");
  for (const bad of ["other", "root", "dev", "ghost"]) {
    const r = await assign(w, "top", { id: "t_peer", expectedOwner: "peer", targetUid: bad });
    assert.equal(r.status, 400, bad);
    assert.equal(r.json.error.code, "ASSIGN_TARGET_INVALID");
  }
  assert.equal(owner(w, "t_peer"), "peer");
  // mid cannot hand its record UP, nor touch the upline's record at all (read-only)
  assert.equal((await assign(w, "mid", { id: "t_mid", expectedOwner: "mid", targetUid: "top" })).status, 400);
  const up = await assign(w, "mid", { id: "t_top", expectedOwner: "top", targetUid: "mid" });
  assert.equal(up.status, 403);
  assert.equal(up.json.error.code, "ASSIGN_FORBIDDEN");
  assert.equal(owner(w, "t_top"), "top");
  // an unrelated record does not even reveal that it exists
  const hidden = await assign(w, "mid", { id: "t_other", expectedOwner: "other", targetUid: "mid" });
  assert.equal(hidden.status, 404);
  assert.equal(hidden.json.error.code, "RECORD_NOT_FOUND");
});

test("ORDINARY USER: cannot give a record away or take anyone else's (shared storage: not even edit it); in per-user storage may only keep their own", async () => {
  const w = world();
  assert.deepEqual(targetsFor(w, "low"), ["low"]);
  // Shared storage: a plain user can already not WRITE shared Payments (existing model), so assignment is refused too.
  for (const target of ["low", "peer", "mid", "top", "other", "root"]) assert.equal((await assign(w, "low", { id: "t_low", expectedOwner: "low", targetUid: target })).status, 403, target);
  assert.equal((await assign(w, "low", { id: "t_mid", expectedOwner: "mid", targetUid: "low" })).status, 403, "upline record: visible but read-only");
  assert.equal((await assign(w, "low", { id: "t_peer", expectedOwner: "peer", targetUid: "low" })).status, 404, "unrelated record");
  assert.equal(owner(w, "t_low"), "low");
  assert.equal(owner(w, "t_mid"), "mid");
  // Per-user storage: the user owns their bucket, so keeping a record is a no-op and giving it to anyone outside their hierarchy is refused.
  const bucket = (txs) => ({ transactions: txs, quotations: [], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], clients: [] });
  const w2 = makeDevWorld(devDoc({ perUser: { low: bucket([rec("p1", "low")]), peer: bucket([]) } }));
  const own = await call(w2, "low", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: "low" });
  assert.deepEqual(own.json.data, { owner: "low", changed: false });
  for (const target of ["peer", "mid", "top", "other", "root"]) assert.equal((await call(w2, "low", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: target })).status, 400, target);
  assert.equal((await call(w2, "low", "/record/assign", { collection: "transactions", bucket: "peer", id: "p1", expectedOwner: "peer", targetUid: "low" })).status, 404, "someone else's bucket");
});

test("a mere EDIT grant lets someone change the content of a record but never hand it to somebody else", async () => {
  const users = [...DEV_USERS, { id: "boss", username: "boss", role: "user", linkedId: "n_boss" }, { id: "mgr", username: "mgr", role: "user", linkedId: "n_mgr" }, { id: "emp", username: "emp", role: "user", linkedId: "n_emp" }];
  const sups = [...DEV_SUPS, { id: "n_boss", supervisorId: null }, { id: "n_mgr", supervisorId: "n_boss" }, { id: "n_emp", supervisorId: "n_mgr" }];
  const w = makeDevWorld(devDoc({ users, sups, tx: [rec("t_emp", "emp", { acl: acl(1, [g("mgr", "edit")]) })] }));
  const edited = await save(w, "mgr", (v) => { find(v.shared.transactions, "t_emp").amount = 5; });
  assert.equal(edited.status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_emp").amount, 5, "the grant works for content");
  const r = await assign(w, "mgr", { id: "t_emp", expectedOwner: "emp", targetUid: "mgr" });
  assert.equal(r.status, 403);
  assert.equal(owner(w, "t_emp"), "emp");
  // the owner themselves may (to someone in their hierarchy: only themselves here), and the Developer may
  assert.equal((await assign(w, "dev", { id: "t_emp", expectedOwner: "emp", targetUid: "mgr" })).status, 200);
});

// ============================================================================================
// 22 / 25. Assigned users see their records; edits preserve ownership
// ============================================================================================
test("the assigned user sees the record under My Data, and the person who assigned it keeps visibility only where their scope allows", async () => {
  const w = world();
  assert.equal((await assign(w, "top", { id: "t_mid", expectedOwner: "mid", targetUid: "peer" })).status, 200);
  assert.ok(find((await getView(w, "peer", "mine")).shared.transactions, "t_mid"));
  assert.ok(find((await getView(w, "top", "mine_downline")).shared.transactions, "t_mid"), "peer is in top's downline");
  assert.equal(find((await getView(w, "mid", "mine_upline_downline")).shared.transactions, "t_mid"), undefined, "mid no longer owns it and peer is not in mid's hierarchy");
});

test("EDITING unrelated fields preserves ownership (own record, downline record, Developer edit) in shared storage", async () => {
  const w = world();
  assert.equal((await save(w, "mid", (v) => { const r = find(v.shared.transactions, "t_mid"); r.amount = 11; r.notes = "n"; r.customer = "New Client"; r.status = "completed"; })).status, 200);
  assert.equal(owner(w, "t_mid"), "mid");
  assert.equal(find(w.state.doc.shared.transactions, "t_mid").amount, 11);
  assert.equal((await save(w, "top", (v) => { find(v.shared.transactions, "t_low").amount = 12; })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_low").amount, 12, "the edit landed");
  assert.equal(owner(w, "t_low"), "low", "an admin editing a downline record does not take it over");
  assert.equal((await save(w, "dev", (v) => { find(v.shared.transactions, "t_low").amount = 13; find(v.shared.quotations, "q_low").amount = 14; })).status, 200);
  assert.equal(owner(w, "t_low"), "low");
  assert.equal(owner(w, "q_low", "quotations"), "low");
  assert.equal(find(w.state.doc.shared.quotations, "q_low").amount, 14);
});

test("EDITING in per-user storage keeps the record in its owner's bucket (ownerId untouched)", async () => {
  const bucket = (txs) => ({ transactions: txs, quotations: [], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], clients: [] });
  const w = makeDevWorld(devDoc({ perUser: { low: bucket([rec("p1", "low")]), peer: bucket([]) } }));
  assert.equal((await save(w, "low", (v) => { const r = find(v.perUser.low.transactions, "p1"); r.amount = 21; r.ownerId = "peer"; })).status, 200);
  assert.equal(find(w.state.doc.perUser.low.transactions, "p1").amount, 21);
  assert.equal(find(w.state.doc.perUser.low.transactions, "p1").ownerId, "low");
  assert.equal(find(w.state.doc.perUser.peer.transactions, "p1"), undefined);
});

// ============================================================================================
// 24. Forged ownerId / role / permission data cannot bypass authorization
// ============================================================================================
test("FORGED ownerId on existing records is ignored for every role, in every direction", async () => {
  const w = world();
  for (const uid of ["low", "mid", "top", "root", "dev"]) {
    await save(w, uid, (v) => { for (const r of [...v.shared.transactions, ...v.shared.quotations]) r.ownerId = "other"; });
  }
  const expected = { t_low: "low", t_mid: "mid", t_top: "top", t_peer: "peer", t_other: "other" };
  for (const [id, o] of Object.entries(expected)) assert.equal(owner(w, id), o, id);
  assert.equal(owner(w, "q_low", "quotations"), "low");
});

test("NEW records: only owners inside the caller's authority survive; for an All-Data caller an unknown / disabled owner becomes the creator, never ownerless", async () => {
  const w = world();
  w.state.doc.users.find((u) => u.id === "peer").disabled = true;
  const r = await save(w, "top", (v) => {
    v.shared.transactions.push(
      { id: "n_out", ownerId: "other", customer: "x", amount: 1 },       // outside top's hierarchy
      { id: "n_disabled", ownerId: "peer", customer: "x", amount: 1 },   // inside, but switched off
      { id: "n_ghost", ownerId: "ghost", customer: "x", amount: 1 },
      { id: "n_none", customer: "x", amount: 1 },
      { id: "n_ok", ownerId: "low", customer: "x", amount: 1 },
    );
  });
  assert.equal(r.status, 200);
  const txs = w.state.doc.shared.transactions;
  for (const id of ["n_out", "n_disabled", "n_ghost", "n_none"]) assert.equal(find(txs, id), undefined, `${id} refused`);
  assert.equal(find(txs, "n_ok").ownerId, "low", "assigning a new record to a downline user still works");
  const d = await save(w, "dev", (v) => { v.shared.transactions.push({ id: "d1", ownerId: "other", customer: "x", amount: 1 }, { id: "d2", ownerId: "ghost", customer: "x", amount: 1 }, { id: "d3", ownerId: "peer", customer: "x", amount: 1 }, { id: "d4", customer: "x", amount: 1 }); });
  assert.equal(d.status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "d1").ownerId, "other");
  assert.equal(find(w.state.doc.shared.transactions, "d2").ownerId, "dev", "unknown owner => the creator");
  assert.equal(find(w.state.doc.shared.transactions, "d3").ownerId, "dev", "disabled owner => the creator");
  assert.equal(find(w.state.doc.shared.transactions, "d4").ownerId, "dev", "no owner => the creator");
});

test("FORGED role / permission data in the request body or token cannot assign: authority comes only from the verified, fresh server state", async () => {
  const w = world();
  const body = { id: "t_other", expectedOwner: "other", targetUid: "low", role: "developer", ownerId: "low", permissions: ["acl"], isSuper: true };
  assert.equal((await assign(w, "low", body)).status, 404);
  assert.equal((await call(w, "low", "/record/assign", { collection: "transactions", bucket: null, ...body }, { tokenRole: "developer" })).status, 404, "a forged developer claim is demoted to the stored 'user' role");
  assert.equal((await call(w, "top", "/record/assign", { collection: "transactions", bucket: null, id: "t_other", expectedOwner: "other", targetUid: "top" }, { tokenRole: "superadmin" })).status, 404);
  assert.equal(owner(w, "t_other"), "other");
  // a demotion that lands after the token was minted takes effect immediately
  w.state.doc.users.find((u) => u.id === "root").role = "user";
  assert.equal((await call(w, "root", "/record/assign", { collection: "transactions", bucket: null, id: "t_other", expectedOwner: "other", targetUid: "root" }, { tokenRole: "superadmin" })).status, 404);
  assert.equal(owner(w, "t_other"), "other");
});

// ============================================================================================
// 26. Invalid / ineligible targets and malformed requests are rejected
// ============================================================================================
test("INVALID targets: nonexistent, disabled, a user who cannot see the section, and malformed requests are all refused with nothing changed", async () => {
  const w = world({ extra: { userPermissions: { peer: { marathon: "hidden" } } } });
  w.state.doc.users.push({ id: "off", username: "off", role: "user", linkedId: null, disabled: true });
  const t = (targetUid) => assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid });
  assert.equal((await t("ghost")).status, 400);
  assert.equal((await t("off")).status, 400, "disabled");
  assert.equal((await t("peer")).status, 400, "peer cannot see Payments: the record would vanish for them");
  assert.equal((await assign(w, "dev", { id: "q_low", expectedOwner: "low", targetUid: "peer" }, "quotations")).status, 200, "but Quotations are fine for the same user");
  assert.ok(!uids(assignableTargets(w.state.doc, { uid: "dev", role: "developer", linkedId: null }, "transactions")).includes("peer"));
  assert.ok(!uids(assignableTargets(w.state.doc, { uid: "dev", role: "developer", linkedId: null }, "transactions")).includes("off"));
  for (const body of [
    { id: "t_low", expectedOwner: "low" }, { id: "t_low", expectedOwner: "low", targetUid: "" }, { id: "t_low", expectedOwner: "low", targetUid: 5 },
    { id: "t_low", expectedOwner: "low", targetUid: "x".repeat(200) }, { id: "", expectedOwner: "low", targetUid: "mid" }, { id: "t_low", expectedOwner: 5, targetUid: "mid" },
    { id: "t_low", expectedOwner: "low", targetUid: "mid", bucket: 7 },
  ]) assert.equal((await call(w, "dev", "/record/assign", { collection: "transactions", ...body })).status, 400, JSON.stringify(body));
  assert.equal((await call(w, "dev", "/record/assign", { collection: "products", id: "t_low", expectedOwner: "low", targetUid: "mid" })).status, 400);
  assert.equal((await call(w, "dev", "/record/assign", { collection: "transactions", id: "t_low", targetUid: "mid" })).status, 400, "an omitted expectedOwner is never an implicit claim");
  assert.equal((await call(w, "dev", "/record/assign", { raw: "[1]" }, { raw: "[1]" })).status, 400);
  assert.equal((await assign(w, "dev", { id: "nope", expectedOwner: "low", targetUid: "mid" })).status, 404);
  assert.equal(owner(w, "t_low"), "low");
  assert.equal((await assign(w, "off", { id: "t_low", expectedOwner: "low", targetUid: "off" })).status, 403, "a disabled caller is refused outright");
});

test("section permission: without WRITE on Payments a user can assign nothing, and the picker is empty", async () => {
  const w = world({ extra: { userPermissions: { low: { marathon: "view" } } } });
  assert.deepEqual(targetsFor(w, "low"), []);
  assert.equal((await assign(w, "low", { id: "t_low", expectedOwner: "low", targetUid: "low" })).status, 403);
  assert.deepEqual(targetsFor(w, "low", "quotations"), ["low"], "Quotations are unaffected");
});

// ============================================================================================
// 27. Stale saves, imports and backups cannot restore revoked access or rewrite ownership
// ============================================================================================
test("STALE ownership: a screen that still shows the old owner is refused (409) and nothing changes", async () => {
  const w = world();
  assert.equal((await assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid: "other" })).status, 200);
  const stale = await assign(w, "top", { id: "t_low", expectedOwner: "low", targetUid: "peer" });
  assert.ok([404, 409].includes(stale.status), "top can no longer see it at all");
  const stale2 = await assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid: "peer" });
  assert.equal(stale2.status, 409);
  assert.equal(stale2.json.error.code, "OWNER_STALE");
  assert.equal(stale2.json.error.currentOwner, "other");
  assert.equal(owner(w, "t_low"), "other");
});

test("STALE blobs / backups / restores cannot rewrite ownership or restore a revoked grant", async () => {
  const w = world({ tx: [rec("t_mid", "mid", { acl: acl(1, [g("low", "edit")]) }), rec("t_low", "low")] });
  const oldLow = await getView(w, "low");            // a client that loaded everything BEFORE the changes below
  const backup = await getView(w, "dev", "all");     // a backup taken before the changes below
  assert.equal((await call(w, "mid", "/record/acl", { collection: "transactions", bucket: null, id: "t_mid", baseRev: 1, grants: [] })).status, 200);
  assert.equal((await assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid: "other" })).status, 200);
  // the stale client edits the (now revoked) record and re-posts its old blob
  find(oldLow.shared.transactions, "t_mid").amount = 777;
  find(oldLow.shared.transactions, "t_low").amount = 888;
  await call(w, "low", "/data/save", { json: JSON.stringify(oldLow) });
  assert.equal(find(w.state.doc.shared.transactions, "t_mid").amount, 100, "revoked grant not restored: the stale edit is refused");
  assert.deepEqual(find(w.state.doc.shared.transactions, "t_mid").acl, acl(2, []), "ACL stays at the newer revision");
  assert.equal(owner(w, "t_low"), "other", "ownership stays with the newer assignment");
  // restoring the pre-change backup as the Developer (and as superadmin) changes neither
  for (const uid of ["dev", "root"]) {
    await call(w, uid, "/data/save", { json: JSON.stringify(backup) });
    assert.equal(owner(w, "t_low"), "other", `${uid}: restore cannot rewrite ownership`);
    assert.deepEqual(find(w.state.doc.shared.transactions, "t_mid").acl, acl(2, []), `${uid}: restore cannot restore the revoked grant`);
  }
});

test("STALE per-user-storage blobs cannot copy a record into its old owner's bucket (ownership moves only via /record/assign)", async () => {
  const bucket = (txs) => ({ transactions: txs, quotations: [], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], clients: [] });
  const w = makeDevWorld(devDoc({ perUser: { low: bucket([rec("p1", "low")]), other: bucket([]), dev: bucket([]) } }));
  const backup = await getView(w, "dev", "all");
  const moved = await call(w, "dev", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: "other" });
  assert.equal(moved.status, 200, JSON.stringify(moved.json));
  assert.equal(find(w.state.doc.perUser.other.transactions, "p1").ownerId, "other");
  assert.equal(find(w.state.doc.perUser.low.transactions, "p1"), undefined, "moved out of the old owner's bucket");
  await call(w, "dev", "/data/save", { json: JSON.stringify(backup) });
  assert.equal(find(w.state.doc.perUser.low.transactions, "p1"), undefined, "the stale backup cannot put it back with the old owner");
  assert.equal(Object.values(w.state.doc.perUser).flatMap((b) => b.transactions).filter((r) => r.id === "p1").length <= 1, true, "never duplicated");
  // recipient already holds that id: refused
  const w2 = makeDevWorld(devDoc({ perUser: { low: bucket([rec("p1", "low")]), other: bucket([rec("p1", "other")]) } }));
  const clash = await call(w2, "dev", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: "other" });
  assert.equal(clash.status, 409);
});

// ============================================================================================
// Record ACL interplay: assignment never widens access
// ============================================================================================
test("assignment NEVER makes a record more widely available: restricted stays restricted (revision bumped), the new owner leaves the grant list, inherit stays inherit", async () => {
  const w = world({ tx: [rec("t_priv", "low", { acl: acl(3, [g("peer"), g("mid", "edit")]) }), rec("t_open", "low")] });
  assert.equal((await assign(w, "dev", { id: "t_priv", expectedOwner: "low", targetUid: "peer" })).status, 200);
  const r = find(w.state.doc.shared.transactions, "t_priv");
  assert.equal(r.ownerId, "peer");
  assert.equal(r.acl.rev, 4, "revision moves on so an old captured ACL request cannot replay");
  assert.deepEqual(r.acl.grants.map((x) => x.uid), ["mid"], "the new owner is implicit and leaves the list; nobody gained anything");
  assert.equal(find((await getView(w, "other", "mine")).shared.transactions, "t_priv"), undefined, "an unrelated user still cannot see it");
  assert.equal((await call(w, "low", "/record/acl", { collection: "transactions", bucket: null, id: "t_priv", baseRev: 3, grants: [] })).status, 404, "old owner: gone");
  assert.equal((await assign(w, "dev", { id: "t_open", expectedOwner: "low", targetUid: "other" })).status, 200);
  assert.equal("acl" in find(w.state.doc.shared.transactions, "t_open"), false, "an inherit record gains no ACL");
});

test("VIEW, EDIT and DELETE grants remain distinct", async () => {
  const users = [...DEV_USERS, { id: "boss", username: "boss", role: "user", linkedId: "n_boss" }, { id: "mgr", username: "mgr", role: "user", linkedId: "n_mgr" }, { id: "emp", username: "emp", role: "user", linkedId: "n_emp" }];
  const sups = [...DEV_SUPS, { id: "n_boss", supervisorId: null }, { id: "n_mgr", supervisorId: "n_boss" }, { id: "n_emp", supervisorId: "n_mgr" }];
  const mk = (grant) => makeDevWorld(devDoc({ users, sups, tx: [rec("t_emp", "emp", { acl: acl(1, [grant]) })] }));
  const del = (w) => call(w, "mgr", "/data/save", { json: JSON.stringify({ shared: { transactions: [] }, perUser: {}, recordDeletes: [{ coll: "transactions", bucket: null, id: "t_emp" }] }) });
  // VIEW only: sees it, can neither edit nor delete
  let w = mk(g("mgr"));
  assert.ok(find((await getView(w, "mgr")).shared.transactions, "t_emp"));
  await save(w, "mgr", (v) => { find(v.shared.transactions, "t_emp").amount = 1; });
  await del(w);
  assert.equal(find(w.state.doc.shared.transactions, "t_emp").amount, 100);
  // EDIT: may edit, may not delete
  w = mk(g("mgr", "edit"));
  await save(w, "mgr", (v) => { find(v.shared.transactions, "t_emp").amount = 2; });
  assert.equal(find(w.state.doc.shared.transactions, "t_emp").amount, 2);
  await del(w);
  assert.ok(find(w.state.doc.shared.transactions, "t_emp"), "EDIT does not imply DELETE");
  // DELETE: may delete (explicitly), may not edit
  w = mk(g("mgr", "delete"));
  await save(w, "mgr", (v) => { find(v.shared.transactions, "t_emp").amount = 3; });
  assert.equal(find(w.state.doc.shared.transactions, "t_emp").amount, 100, "DELETE does not imply EDIT");
  await del(w);
  assert.equal(find(w.state.doc.shared.transactions, "t_emp"), undefined);
});

// ============================================================================================
// 28. Legacy unowned records stay compatible without guessing an owner
// ============================================================================================
test("LEGACY records without an owner: hidden from scoped users, Developer/superadmin keep full access, edits never guess an owner, assignment is explicit", async () => {
  const legacy = { id: "t_legacy", customer: "cust-legacy", amount: 100 };
  const w = world({ tx: [legacy, rec("t_low", "low")] });
  assert.equal(find((await getView(w, "low")).shared.transactions, "t_legacy"), undefined);
  assert.equal(find((await getView(w, "top")).shared.transactions, "t_legacy"), undefined);
  assert.ok(find((await getView(w, "dev", "all")).shared.transactions, "t_legacy"));
  assert.ok(find((await getView(w, "root", "all")).shared.transactions, "t_legacy"));
  assert.equal((await save(w, "dev", (v) => { find(v.shared.transactions, "t_legacy").amount = 5; })).status, 200);
  const stored = find(w.state.doc.shared.transactions, "t_legacy");
  assert.equal(stored.amount, 5);
  assert.equal("ownerId" in stored, false, "editing never invents an owner");
  assert.equal((await assign(w, "low", { id: "t_legacy", expectedOwner: null, targetUid: "low" })).status, 404);
  assert.equal((await assign(w, "top", { id: "t_legacy", expectedOwner: null, targetUid: "top" })).status, 404);
  assert.equal((await assign(w, "dev", { id: "t_legacy", expectedOwner: "low", targetUid: "low" })).status, 409, "claiming a wrong current owner is stale");
  assert.equal((await assign(w, "dev", { id: "t_legacy", expectedOwner: null, targetUid: "mid" })).status, 200, "an explicit request by a record-super assigns it");
  assert.equal(owner(w, "t_legacy"), "mid");
});

// ============================================================================================
// Isolated (per-user) storage, concurrency, picker
// ============================================================================================
test("PER-USER storage: assignment moves the record to the new owner's bucket (the bucket IS the owner) and is audited", async () => {
  const bucket = (txs, qs = []) => ({ transactions: txs, quotations: qs, members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], clients: [] });
  const w = makeDevWorld(devDoc({ perUser: { low: bucket([rec("p1", "low")], [rec("pq1", "low")]), peer: bucket([]) } }));
  assert.equal((await call(w, "top", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: "peer" })).status, 200);
  assert.ok(find(w.state.doc.perUser.peer.transactions, "p1"));
  assert.equal(find(w.state.doc.perUser.low.transactions, "p1"), undefined);
  assert.equal((await call(w, "top", "/record/assign", { collection: "quotations", bucket: "low", id: "pq1", expectedOwner: "low", targetUid: "other" })).status, 400, "outside top's hierarchy");
  assert.equal(w.state.doc.accessAudit[0].bucket, "low");
  assert.equal((await call(w, "top", "/record/assign", { collection: "transactions", bucket: "low", id: "p1", expectedOwner: "low", targetUid: "mid" })).status, 404, "already moved");
});

test("CONCURRENT: an assignment racing a competing write is re-evaluated from a fresh read, never applied blindly", async () => {
  const w = world();
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const pending = assign(w, "dev", { id: "t_low", expectedOwner: "low", targetUid: "other" });
  await hit;
  // another admin reassigns the same record while the first request is mid-write
  w.state.doc.shared.transactions.find((r) => r.id === "t_low").ownerId = "peer";
  w.state.version = "vX";
  release();
  const res = await pending;
  assert.equal(res.status, 409, "the retry sees the new owner and refuses the stale expectation");
  assert.equal(res.json.error.code, "OWNER_STALE");
  assert.equal(owner(w, "t_low"), "peer");
  assert.ok(w.conflicts >= 1);
});

test("computeAssignment is pure: it never mutates its input, and a refused call returns no data", () => {
  const doc = devDoc({ tx: [rec("t_low", "low")] });
  const snapshot = JSON.stringify(doc);
  const caller = { uid: "dev", role: "developer", linkedId: null };
  const ctx = buildRecordAccessContext(doc, caller);
  const ok = computeAssignment({ appData: doc, ctx, caller, collection: "transactions", bucket: null, id: "t_low", expectedOwner: "low", targetUid: "mid" });
  assert.equal(ok.result.owner, "mid");
  assert.equal(JSON.stringify(doc), snapshot, "input untouched (copy-on-write)");
  const bad = computeAssignment({ appData: doc, ctx, caller, collection: "transactions", bucket: null, id: "t_low", expectedOwner: "low", targetUid: "ghost" });
  assert.equal(bad.appData, undefined);
  assert.equal(bad.error.status, 400);
});

test("the Assigned-To picker shipped in /data/get matches the server's own rules for each role, and carries only names", async () => {
  const w = world();
  const expected = { dev: ["dev", "low", "mid", "other", "peer", "root", "sa2", "top"], root: ["dev", "low", "mid", "other", "peer", "root", "sa2", "top"], top: ["low", "mid", "peer", "top"], mid: ["low", "mid"], low: ["low"], other: ["other"] };
  for (const [uid, list] of Object.entries(expected)) {
    const v = await getView(w, uid);
    for (const coll of ["transactions", "quotations"]) {
      assert.deepEqual(uids(v.dataScope.assignTargets[coll]).sort(), list, `${uid}/${coll}`);
      for (const p of v.dataScope.assignTargets[coll]) assert.deepEqual(Object.keys(p).sort(), ["name", "uid", "username"]);
    }
  }
  w.state.doc.profiles = { low: { displayName: "Lowell L." } };
  assert.equal((await getView(w, "mid")).dataScope.assignTargets.transactions.find((p) => p.uid === "low").name, "Lowell L.");
});
