// ============================================================================================
// RECORD-LEVEL ACL -- end-to-end through the real Worker (routing, Firebase ID-token verification,
// Firestore optimistic-concurrency preconditions, retry loops). Same fixture hierarchy as
// record-acl.test.js:   top(admin) -> mid(admin) -> low(user);  peer(user) under top;  root = superadmin.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { worker, ORIGIN, SUPS, USERS, rec, g, acl, find, makeDoc, makeWorld, call, getView, save, setAcl, stored } from "./helpers/aclWorld.js";

// ============================================================================================
test("/data/get: private record is served to the owner/superadmin only; ACL list shown only to managers; forged body fields change nothing", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: acl(2, [g("low")]) }), rec("t2", "mid")] }));
  const mid = await getView(w, "mid");
  assert.deepEqual(find(mid.shared.transactions, "t1").acl, acl(2, [g("low")]));
  const low = await getView(w, "low");
  assert.ok(find(low.shared.transactions, "t1"), "granted viewer");
  assert.equal("acl" in find(low.shared.transactions, "t1"), false, "viewer never sees the access list");
  const peer = await getView(w, "peer");
  assert.equal(find(peer.shared.transactions, "t1"), undefined);
  // make it private and re-check as low + a hostile request body
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 2, grants: [] })).status, 200);
  const low2 = await call(w, "low", "/data/get", { scope: "mine_upline", role: "superadmin", uid: "mid", linkedId: "n_mid", acl: { mode: "inherit" }, ownerId: "low" });
  assert.equal(low2.status, 200);
  assert.equal(find(JSON.parse(low2.json.data.json).shared.transactions, "t1"), undefined);
  // an admin asking for All Data is still refused (unchanged)
  const all = await call(w, "mid", "/data/get", { scope: "all" });
  assert.equal(all.status, 403);
  assert.equal(all.json.error.code, "SCOPE_NOT_ALLOWED");
  // superadmin sees everything including the ACL
  const root = await getView(w, "root");
  assert.deepEqual(find(root.shared.transactions, "t1").acl, acl(3, []));
});

test("/data/save direct API: a user with NO access cannot edit, overwrite, re-own, re-ACL or delete a private record", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "low", { acl: acl(1, []) }), rec("t2", "mid")] }));
  // hand-crafted blob (not derived from any view) trying every trick at once
  const blob = {
    shared: { transactions: [{ id: "t1", ownerId: "mid", customer: "FORGED", amount: 0, acl: acl(9, [g("mid", "edit", "delete", "acl")]) }, rec("t2", "mid", { customer: "legit" })] },
    perUser: {}, activityLog: [],
  };
  const r = await call(w, "mid", "/data/save", { json: JSON.stringify(blob) });
  assert.equal(r.status, 200);
  const t1 = stored(w, "t1");
  assert.deepEqual(t1, rec("t1", "low", { acl: acl(1, []) }), "private record untouched");
  assert.equal(stored(w, "t2").customer, "legit", "mid's own edit still lands (no regression)");
  // deletion by omission
  assert.equal((await call(w, "mid", "/data/save", { json: JSON.stringify({ shared: { transactions: [] }, perUser: {} }) })).status, 200);
  assert.ok(stored(w, "t1"), "private record survives an 'empty' blob");
  assert.equal(stored(w, "t2"), undefined, "mid may still delete their own inherit record");
});

test("full lifecycle through the Worker: set -> save keeps ACL -> stale replay refused -> revert -> replay refused -> re-set", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { customer: "Private Person" })], activityLog: [{ ts: 1, user: "low", action: "added", coll: "transactions", name: "Private Person", scopeId: "n_low" }] }));
  const set1 = { id: "t1", baseRev: 0, grants: [{ uid: "low", perms: ["edit"] }] };
  const a = await setAcl(w, "mid", set1);
  assert.equal(a.status, 200);
  assert.deepEqual(a.json.data, { rev: 1, mode: "restricted", changed: true });
  assert.deepEqual(stored(w, "t1").acl, acl(1, [{ uid: "low", perms: ["view", "edit"] }]));
  assert.equal(stored(w, "t1").ownerId, "mid");

  // owner saves through /data/save: ACL survives untouched
  assert.equal((await save(w, "mid", (v) => { find(v.shared.transactions, "t1").amount = 555; })).status, 200);
  assert.equal(stored(w, "t1").amount, 555);
  assert.deepEqual(stored(w, "t1").acl, acl(1, [{ uid: "low", perms: ["view", "edit"] }]));

  // replay of the very same (now stale) request
  const replay = await setAcl(w, "mid", set1);
  assert.equal(replay.status, 409);
  assert.equal(replay.json.error.code, "ACL_STALE");
  assert.equal(replay.json.error.currentRev, 1);

  // revert, then replay both older requests
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: null })).json.data.mode, "inherit");
  assert.deepEqual(stored(w, "t1").acl, { rev: 2, grants: null });
  assert.equal((await setAcl(w, "mid", set1)).status, 409);
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: [] })).status, 409);
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 2, grants: [] })).json.data.rev, 3);

  // activity log: restricted again => Payment entry names are hidden from non-authors, shown to superadmin
  const top = await getView(w, "top");
  assert.equal(top.activityLog.some((e) => e.name === "Private Person"), false);
  assert.equal((await getView(w, "root")).activityLog.some((e) => e.name === "Private Person"), true);
  // audit trail is server-side, ids only
  const audit = w.state.doc.recordAclAudit;
  assert.equal(audit.length, 3, "only the 3 successful changes are audited; rejected replays write nothing");
  assert.equal(JSON.stringify(audit).includes("Private Person"), false);
});

test("/record/acl: authentication, method, body-shape and size handling", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  w.install();
  const noAuth = await worker.fetch(new Request("https://worker.example/record/acl", { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: "{}" }), w.env, {});
  assert.equal(noAuth.status, 401);
  const badToken = await worker.fetch(new Request("https://worker.example/record/acl", { method: "POST", headers: { Origin: ORIGIN, Authorization: "Bearer not.a.jwt" }, body: "{}" }), w.env, {});
  assert.equal(badToken.status, 401);
  const getMethod = await worker.fetch(new Request("https://worker.example/record/acl", { method: "GET", headers: { Origin: ORIGIN } }), w.env, {});
  assert.equal(getMethod.status, 405);
  assert.equal((await call(w, "mid", "/record/acl", null, { raw: "not json" })).status, 400);
  assert.equal((await call(w, "mid", "/record/acl", null, { raw: "[]" })).status, 400);
  assert.equal((await call(w, "mid", "/record/acl", { collection: "transactions", id: "t1", baseRev: 0 })).status, 400, "omitted grants is never an implicit revert");
  assert.equal((await call(w, "mid", "/record/acl", { collection: "members", id: "t1", baseRev: 0, grants: [] })).status, 400);
  const big = await call(w, "mid", "/record/acl", { collection: "transactions", id: "t1", baseRev: 0, grants: [], pad: "x".repeat(20 * 1024) });
  assert.equal(big.status, 413);
  assert.equal(stored(w, "t1").acl, undefined, "nothing was written by any of the rejected requests");
});

test("prototype-pollution / unknown-key payloads on /record/acl are rejected and change nothing", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  const raws = [
    '{"collection":"transactions","id":"t1","baseRev":0,"grants":[{"uid":"low","perms":["view"],"__proto__":{"perms":["acl"]}}]}',
    '{"collection":"transactions","id":"t1","baseRev":0,"grants":[{"uid":"__proto__","perms":["view"]}]}',
    '{"collection":"transactions","id":"t1","baseRev":0,"grants":[{"uid":"constructor","perms":["view"]}]}',
    '{"collection":"transactions","id":"t1","baseRev":0,"grants":{"low":["view"]}}',
    '{"collection":"transactions","id":"__proto__","baseRev":0,"grants":[]}',
    '{"collection":"transactions","id":"t1","bucket":"__proto__","baseRev":0,"grants":[]}',
  ];
  for (const raw of raws) {
    const r = await call(w, "mid", "/record/acl", null, { raw });
    assert.ok([400, 404].includes(r.status), `${r.status} for ${raw}`);
  }
  assert.equal({}.perms, undefined);
  assert.equal(stored(w, "t1").acl, undefined);
  assert.equal(w.state.doc.recordAclAudit, undefined);
});

test("SELF-GRANT and unauthorized ACL modification via /record/acl: viewer, editor, deleter, unlisted, peer, upline-with-grants", async () => {
  const start = () => makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("low"), g("top", "edit", "delete")]) })] }));
  for (const [uid, want] of [["low", 403], ["top", 403], ["peer", 404]]) {
    const w = start();
    const r = await setAcl(w, uid, { id: "t1", baseRev: 1, grants: [g(uid, "edit", "delete", "acl")] });
    assert.equal(r.status, want, uid);
    assert.deepEqual(stored(w, "t1").acl, acl(1, [g("low"), g("top", "edit", "delete")]), `${uid}: ACL unchanged`);
  }
  // via /data/save forging the ACL as a viewer / editor
  for (const uid of ["low", "top"]) {
    const w = start();
    await save(w, uid, (v) => { const r = find(v.shared.transactions, "t1"); r.acl = acl(2, [g(uid, "edit", "delete", "acl")]); r.ownerId = uid; });
    assert.deepEqual(stored(w, "t1").acl, acl(1, [g("low"), g("top", "edit", "delete")]), `${uid} via save`);
    assert.equal(stored(w, "t1").ownerId, "mid");
  }
});

test("OWNERSHIP TRANSFER attempts all fail: via /data/save (any role), and the ACL endpoint has no owner parameter", async () => {
  for (const uid of ["mid", "top", "root"]) {
    const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
    await save(w, uid, (v) => { find(v.shared.transactions, "t1").ownerId = "peer"; });
    assert.equal(stored(w, "t1").ownerId, "mid", `${uid} cannot reassign ownerId`);
  }
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  const r = await call(w, "mid", "/record/acl", { collection: "transactions", id: "t1", baseRev: 0, grants: [g("low")], ownerId: "low", newOwner: "low", owner: "low" });
  assert.equal(r.status, 200);
  assert.equal(stored(w, "t1").ownerId, "mid");
  assert.equal(w.state.doc.users.length, USERS.length);
});

test("the old client re-stamp (editing a downline record writes ownerId = editor) no longer moves ownership", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "low")] }));
  await save(w, "mid", (v) => { const r = find(v.shared.transactions, "t1"); r.customer = "edited-by-mid"; r.ownerId = "mid"; r.lastEditedBy = "mid"; });
  assert.equal(stored(w, "t1").customer, "edited-by-mid");
  assert.equal(stored(w, "t1").lastEditedBy, "mid");
  assert.equal(stored(w, "t1").ownerId, "low");
});

test("UPLINE read-only end to end: mid holds an ACL grant of edit+delete+acl on top's record and still can do none of them", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "top", { acl: acl(1, [g("mid", "edit", "delete", "acl")]) })] }));
  const v = await getView(w, "mid");
  assert.ok(find(v.shared.transactions, "t1"), "readable");
  await save(w, "mid", (x) => { find(x.shared.transactions, "t1").customer = "HACK"; });
  assert.equal(stored(w, "t1").customer, "cust-t1");
  await save(w, "mid", (x) => { x.shared.transactions = []; });
  assert.ok(stored(w, "t1"));
  const r = await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: [g("mid", "edit", "delete", "acl"), g("peer")] });
  assert.equal(r.status, 403);
  assert.deepEqual(stored(w, "t1").acl, acl(1, [g("mid", "edit", "delete", "acl")]));
});

test("DOWNLINE end to end: a parent admin keeps downline access on inherit records; a restricted downline record is closed to them unless granted", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("open", "low"), rec("closed", "low", { acl: acl(1, [g("top")]) })] }));
  const v = await getView(w, "mid");
  assert.deepEqual(v.shared.transactions.map((r) => r.id), ["open"]);
  await save(w, "mid", (x) => { find(x.shared.transactions, "open").customer = "ok"; });
  assert.equal(stored(w, "open").customer, "ok");
  const t = await getView(w, "top");
  assert.deepEqual(t.shared.transactions.map((r) => r.id).sort(), ["closed", "open"]);
});

test("superadmin: unrestricted for view/edit/delete, incl. malformed ACL; can repair via /record/acl; admin gains no implicit All Data", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("a", "low", { acl: acl(1, []) }), rec("b", "peer", { acl: "junk" }), rec("c", "peer")] }));
  assert.deepEqual((await getView(w, "root")).shared.transactions.map((r) => r.id).sort(), ["a", "b", "c"]);
  assert.deepEqual((await getView(w, "mid")).shared.transactions.map((r) => r.id), [], "admin sees none of them");
  assert.equal((await setAcl(w, "peer", { id: "b", baseRev: 0, grants: [] })).status, 404, "owner cannot repair a malformed ACL");
  assert.equal((await setAcl(w, "root", { id: "b", baseRev: 0, grants: [g("low")] })).status, 200);
  assert.deepEqual(stored(w, "b").acl, acl(1, [g("low")]));
  await save(w, "root", (v) => { find(v.shared.transactions, "a").customer = "S"; v.shared.transactions = v.shared.transactions.filter((r) => r.id !== "c"); });
  assert.equal(stored(w, "a").customer, "S");
  assert.equal(stored(w, "c"), undefined);
});

test("role freshness: a demoted admin (stale token says admin) is evaluated as 'user' by the ACL layer", async () => {
  const doc = makeDoc({ tx: [rec("t1", "mid")] });
  doc.users.find((u) => u.id === "mid").role = "user"; // stored role was demoted
  const w = makeWorld(doc);
  const r = await call(w, "mid", "/record/acl", { collection: "transactions", id: "t1", baseRev: 0, grants: [g("low")] }, { tokenRole: "admin" });
  assert.equal(r.status, 403, "a regular user cannot manage ACL on a shared-mode record");
  assert.equal(stored(w, "t1").acl, undefined);
});

test("forged token role does not exist as an attack: a 'user' token cannot become admin/superadmin through a request body", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: acl(1, []) })] }));
  const r = await call(w, "peer", "/record/acl", { collection: "transactions", id: "t1", baseRev: 1, grants: [g("peer", "acl")], role: "superadmin", uid: "mid", linkedId: "n_mid" });
  assert.equal(r.status, 404);
  assert.deepEqual(stored(w, "t1").acl, acl(1, []));
});

test("malformed ACL stored server-side fails closed through every endpoint", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: { rev: 1, grants: [{ uid: "low", perms: ["view", "acl"], role: "admin" }] } })], q: [rec("q1", "mid", { acl: [] })] }));
  for (const uid of ["mid", "low", "top", "peer"]) {
    const v = await getView(w, uid);
    assert.equal(find(v.shared.transactions, "t1"), undefined, uid);
    assert.equal(find(v.shared.quotations, "q1"), undefined, uid);
  }
  assert.equal((await save(w, "mid", (v) => { v.shared.transactions = []; v.shared.quotations = []; })).status, 200);
  assert.ok(stored(w, "t1") && stored(w, "q1", "quotations"), "not deletable by non-superadmin");
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: [] })).status, 404);
});

test("QUOTATIONS: the full flow works identically (restrict, hidden, edit refused, delete refused, restored)", async () => {
  const w = makeWorld(makeDoc({ q: [rec("q1", "low")] }));
  const r = await call(w, "mid", "/record/acl", { collection: "quotations", id: "q1", baseRev: 0, grants: [] });
  assert.equal(r.status, 403, "mid is low's parent: may edit an inherit record but not manage its ACL");
  // low is a regular user: own-bucket record
  const w2 = makeWorld(makeDoc({ perUser: { low: { transactions: [], quotations: [rec("q1", "low")] } } }));
  const s = await call(w2, "low", "/record/acl", { collection: "quotations", bucket: "low", id: "q1", baseRev: 0, grants: [g("top")] });
  assert.equal(s.status, 200);
  const mid = await getView(w2, "mid");
  assert.equal(find(mid.perUser.low.quotations, "q1"), undefined, "mid (parent) lost access");
  const top = await getView(w2, "top");
  assert.ok(find(top.perUser.low.quotations, "q1"), "top was granted view");
  await save(w2, "mid", (v) => { v.perUser = {}; });
  assert.ok(find(w2.state.doc.perUser.low.quotations, "q1"), "survives mid wiping perUser");
  await save(w2, "top", (v) => { find(v.perUser.low.quotations, "q1").customer = "HACK"; });
  assert.equal(find(w2.state.doc.perUser.low.quotations, "q1").customer, "cust-q1", "top is view-only");
});

test("per-user (isolated) mode end to end: regular user manages own bucket record; cannot forge ACL via save", async () => {
  const w = makeWorld(makeDoc({ perUser: { low: { transactions: [rec("p1", "low")], quotations: [] } } }));
  assert.equal((await call(w, "low", "/record/acl", { collection: "transactions", bucket: "low", id: "p1", baseRev: 0, grants: [] })).status, 200);
  assert.equal(find((await getView(w, "mid")).perUser.low.transactions, "p1"), undefined);
  await save(w, "low", (v) => { const r = find(v.perUser.low.transactions, "p1"); r.customer = "mine"; r.acl = acl(7, [g("mid", "edit")]); r.ownerId = "mid"; });
  const p1 = find(w.state.doc.perUser.low.transactions, "p1");
  assert.equal(p1.customer, "mine");
  assert.deepEqual(p1.acl, acl(1, []));
  assert.equal(p1.ownerId, "low");
});

test("/privacy/export: an owner's export omits records with malformed ACL and hides the access list when they cannot manage it", async () => {
  const doc = makeDoc({ perUser: { low: { transactions: [rec("p1", "low", { acl: acl(1, [g("mid")]) }), rec("p2", "low", { acl: "junk" })], quotations: [] } } });
  doc.permissions = { user: { marathon: "view", quotations: "write" } }; // low: Payments view-only => cannot manage
  const w = makeWorld(doc);
  const r = await call(w, "low", "/privacy/export", {});
  assert.equal(r.status, 200);
  const own = r.json.data.export.ownRecords.transactions;
  assert.deepEqual(own.map((x) => x.id), ["p1"], "malformed-ACL record is not exported");
  assert.equal("acl" in own[0], false, "view-only owner never receives the grant list");
  assert.ok(w.state.doc.privacyAuditLog.length >= 1, "export audit write still happens");
});

test("/privacy/export cannot be used to read other people's records or restricted activity", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "low", { acl: acl(1, []), customer: "SECRET" })], activityLog: [{ ts: 5, user: "mid", action: "added", coll: "transactions", name: "SECRET", scopeId: "n_low" }] }));
  const text = JSON.stringify((await call(w, "peer", "/privacy/export", {})).json);
  assert.equal(text.includes("SECRET"), false);
  const text2 = JSON.stringify((await call(w, "top", "/privacy/export", {})).json);
  assert.equal(text2.includes("SECRET"), false);
});

test("recordAclAudit survives /privacy/* writes and /data/save by other users", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  await setAcl(w, "mid", { id: "t1", baseRev: 0, grants: [] });
  await call(w, "low", "/privacy/export", {});
  await save(w, "low", () => {});
  await save(w, "root", (v) => { v.recordAclAudit = []; });
  assert.equal(w.state.doc.recordAclAudit.length, 1);
});

test("rate limiting: /record/acl fails closed (503) when the KV binding is missing", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }), { kv: false });
  const r = await setAcl(w, "mid", { id: "t1", baseRev: 0, grants: [] });
  assert.equal(r.status, 503);
  assert.equal(stored(w, "t1").acl, undefined);
});

test("rate limiting: /record/acl returns 429 once the per-user window is exhausted", async () => {
  const store = new Map();
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  w.env.RATE_LIMIT_KV = { async get(k) { return store.has(k) ? JSON.parse(store.get(k)) : null; }, async put(k, v) { store.set(k, v); } };
  let last;
  for (let i = 0; i < 40; i++) last = await setAcl(w, "mid", { id: "t1", baseRev: 99, grants: [] }); // 409s still consume the budget
  assert.equal(last.status, 429);
});

test("no regression: ordinary save of inherit records (create, edit, delete) behaves as before", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("a", "mid"), rec("b", "mid")] }));
  await save(w, "mid", (v) => {
    find(v.shared.transactions, "a").amount = 1;
    v.shared.transactions = v.shared.transactions.filter((r) => r.id !== "b");
    v.shared.transactions.push(rec("c", "mid"));
  });
  assert.deepEqual(w.state.doc.shared.transactions.map((r) => r.id).sort(), ["a", "c"]);
  assert.equal(stored(w, "a").amount, 1);
  assert.equal(stored(w, "c").acl, undefined);
  // out-of-scope owner on create is still refused by the existing Data Scope gate
  await save(w, "mid", (v) => { v.shared.transactions.push(rec("evil", "peer")); });
  assert.equal(stored(w, "evil"), undefined);
});

// ============================================================================================
// CONCURRENCY / STALE STATE
// ============================================================================================
test("CONCURRENT: a stale /data/save racing an ACL restriction is re-evaluated against the NEW ACL (edit dropped, ACL intact)", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  // top (mid's parent admin) edits t1 -- legal under INHERIT -- and pauses right before committing
  const pending = save(w, "top", (v) => { find(v.shared.transactions, "t1").customer = "top-edit"; });
  await hit;
  // meanwhile the owner makes t1 private; this lands first and invalidates top's precondition
  const r = await setAcl(w, "mid", { id: "t1", baseRev: 0, grants: [] });
  assert.equal(r.status, 200);
  release();
  const res = await pending;
  assert.equal(res.status, 200);
  assert.ok(w.conflicts >= 1, "a real precondition conflict happened and was retried");
  assert.equal(stored(w, "t1").customer, "cust-t1", "top's stale edit must not land on a record that is now private to them");
  assert.deepEqual(stored(w, "t1").acl, acl(1, []));
});

test("CONCURRENT: a stale /data/save cannot clobber an ACL change made in between (acl is server-owned)", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid"), rec("t2", "top")] }));
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const pending = save(w, "mid", (v) => { find(v.shared.transactions, "t1").amount = 42; find(v.shared.transactions, "t2").customer = "ignored"; });
  await hit;
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 0, grants: [g("low")] })).status, 200);
  release();
  assert.equal((await pending).status, 200);
  assert.equal(stored(w, "t1").amount, 42, "the save's own change landed");
  assert.deepEqual(stored(w, "t1").acl, acl(1, [g("low")]), "...and the ACL set in between survived");
  assert.equal(stored(w, "t2").customer, "cust-t2", "upline record still read-only");
});

test("CONCURRENT: two ACL updates from the same base rev -- exactly one wins, the other gets ACL_STALE", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid")] }));
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const first = setAcl(w, "mid", { id: "t1", baseRev: 0, grants: [g("low")] });
  await hit;
  const second = await setAcl(w, "root", { id: "t1", baseRev: 0, grants: [g("top", "edit")] });
  assert.equal(second.status, 200, "the un-paused request commits first");
  release();
  const loser = await first;
  assert.equal(loser.status, 409);
  assert.equal(loser.json.error.code, "ACL_STALE");
  assert.deepEqual(stored(w, "t1").acl, acl(1, [{ uid: "top", perms: ["view", "edit"] }]));
});

test("CONCURRENT: an ACL update whose authority is revoked in between is refused on retry (re-derived from fresh data)", async () => {
  // top is a delegated manager (holds acl). While top's request is paused, the owner removes top's grant.
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("low"), g("top", "acl")]) })] }));
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const pending = setAcl(w, "top", { id: "t1", baseRev: 1, grants: [g("low"), g("top", "acl"), g("peer")] });
  await hit;
  assert.equal((await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: [g("low")] })).status, 200); // top removed
  release();
  const res = await pending;
  assert.ok([404, 409].includes(res.status), `got ${res.status}`);
  assert.deepEqual(stored(w, "t1").acl, acl(2, [g("low")]), "top's stale change never lands");
});

test("stale client data: a client holding an old copy of a restricted-then-opened record cannot resurrect old ACL or ownership", async () => {
  const w = makeWorld(makeDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("low", "edit")]) })] }));
  const staleView = await getView(w, "mid"); // client loads at rev 1
  await setAcl(w, "mid", { id: "t1", baseRev: 1, grants: null }); // revert (tombstone rev 2)
  await setAcl(w, "mid", { id: "t1", baseRev: 2, grants: [g("top")] }); // rev 3
  // the stale client now saves its old blob (rev-1 acl embedded)
  find(staleView.shared.transactions, "t1").customer = "from-stale-client";
  const r = await call(w, "mid", "/data/save", { json: JSON.stringify(staleView) });
  assert.equal(r.status, 200);
  assert.equal(stored(w, "t1").customer, "from-stale-client");
  assert.deepEqual(stored(w, "t1").acl, acl(3, [g("top")]), "the stale embedded ACL is ignored");
});
