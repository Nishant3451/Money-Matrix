// ============================================================================================
// DATA SCOPE for Payments and Quotations -- independent per-collection scopes, the Developer-controlled scope policy,
// hierarchy fail-closed behaviour, and "a requested scope never exceeds the server-authorized maximum".
//
//   top(admin, n_top) -+- mid(admin, n_mid) -- low(user, n_low)        dev = developer, root / sa2 = superadmins
//                      +- peer(user, n_peer)                           other(user, n_other) = unrelated tree
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { rec, g, acl, find, call, getView, save, makeDevWorld, devDoc, makeDoc, DEV_USERS, DEV_SUPS } from "./helpers/devWorld.js";
import { resolveDataScope, resolveRequestedScopes, buildAuthorizedView } from "../lib/authorization.js";
import { effectivePolicyFor, parseScopePolicy, validateUserPolicyInput } from "../lib/scopePolicy.js";

const OWNERS = ["dev", "root", "top", "mid", "low", "peer", "other"];
const TX = OWNERS.map((o) => rec(`t_${o}`, o));
const Q = OWNERS.map((o) => rec(`q_${o}`, o));
const world = (o = {}) => makeDevWorld(devDoc({ tx: TX, q: Q, ...o }));
const ids = (arr) => (arr || []).map((r) => r.id).sort();
const t = (...owners) => owners.map((o) => `t_${o}`).sort();
const q = (...owners) => owners.map((o) => `q_${o}`).sort();
const get = (w, uid, scope) => call(w, uid, "/data/get", scope === undefined ? {} : { scope });
const view = async (w, uid, scope) => { const r = await get(w, uid, scope); assert.equal(r.status, 200, JSON.stringify(r.json)); return JSON.parse(r.json.data.json); };
const policy = (w, body, uid = "dev") => call(w, uid, "/scope/policy", body);

// ============================================================================================
// 10-13. The scope options, one by one (admin `mid` has an upline AND a downline)
// ============================================================================================
test("SCOPES: My Data / Upline / Downline / combined unions return exactly the right owners (admin with both directions)", async () => {
  const w = world();
  const expect = {
    mine: ["mid"],
    upline: ["top"],
    downline: ["low"],
    mine_upline: ["mid", "top"],
    mine_downline: ["mid", "low"],
    upline_downline: ["top", "low"],
    mine_upline_downline: ["mid", "top", "low"],
  };
  assert.deepEqual((await view(w, "mid")).dataScope.allowed, ["mine", "upline", "downline", "mine_upline", "mine_downline", "upline_downline", "mine_upline_downline"]);
  for (const [key, owners] of Object.entries(expect)) {
    const v = await view(w, "mid", key);
    assert.deepEqual(ids(v.shared.transactions), t(...owners), `payments, ${key}`);
    assert.deepEqual(ids(v.shared.quotations), q(...owners), `quotations, ${key}`);
    assert.equal(v.dataScope.active, key);
  }
});

test("MY DATA returns only the caller's own records, and a forged owner id in the request body changes nothing", async () => {
  const w = world();
  const r = await call(w, "low", "/data/get", { scope: "mine", uid: "mid", ownerId: "mid", linkedId: "n_mid", role: "admin" });
  assert.equal(r.status, 200);
  const v = JSON.parse(r.json.data.json);
  assert.deepEqual(ids(v.shared.transactions), t("low"));
  assert.deepEqual(ids(v.shared.quotations), q("low"));
});

test("DEFAULT scope is unchanged: My Data + Downline when downline relationships exist, otherwise My Data; superadmin / developer default to All Data", async () => {
  const w = world();
  assert.equal((await view(w, "top")).dataScope.active, "mine_downline");
  assert.equal((await view(w, "mid")).dataScope.active, "mine_downline");
  assert.equal((await view(w, "low")).dataScope.active, "mine");
  assert.equal((await view(w, "other")).dataScope.active, "mine");
  assert.equal((await view(w, "root")).dataScope.active, "all");
  assert.equal((await view(w, "dev")).dataScope.active, "all");
  assert.deepEqual(ids((await view(w, "mid")).shared.transactions), t("mid", "low"));
});

test("UPLINE is verified-hierarchy only and READ-ONLY: selecting it (even with an explicit grant) never allows editing or deleting", async () => {
  const w = world({ tx: [rec("t_top", "top"), rec("t_mid", "mid", { acl: acl(1, [g("low", "edit", "delete", "acl")]) }), rec("t_low", "low"), rec("t_other", "other")] });
  const v = await view(w, "low", "mine_upline");
  assert.deepEqual(ids(v.shared.transactions), ["t_low", "t_mid", "t_top"], "upline = mid and top (the ancestors), never other / peer");
  const r = await save(w, "low", (x) => {
    find(x.shared.transactions, "t_top").amount = 1;
    find(x.shared.transactions, "t_mid").amount = 2;
    x.shared.transactions = x.shared.transactions.filter((rr) => rr.id !== "t_mid");
  });
  assert.equal(r.status, 200);
  const stored = (id) => find(w.state.doc.shared.transactions, id);
  assert.equal(stored("t_top").amount, 100, "upline record untouched");
  assert.ok(stored("t_mid"), "upline record not deletable");
  assert.equal(stored("t_mid").amount, 100, "even an explicit edit/delete grant cannot make an upline record writable");
  // explicit recordDeletes cannot reach it either
  await call(w, "low", "/data/save", { json: JSON.stringify({ shared: { transactions: [] }, perUser: {}, recordDeletes: [{ coll: "transactions", bucket: null, id: "t_mid" }] }) });
  assert.ok(stored("t_mid"));
});

test("DOWNLINE uses the verified supervisor tree, and downline visibility does not bypass record-level EDIT/DELETE restrictions", async () => {
  const w = world({ tx: [rec("t_low", "low", { acl: acl(1, []) }), rec("t_peer", "peer"), rec("t_mid", "mid"), rec("t_top", "top")] });
  const topView = await view(w, "top", "downline");
  assert.deepEqual(ids(topView.shared.transactions), ["t_mid", "t_peer"], "mid and peer (low is private); top itself and unrelated people are excluded");
  assert.equal(find(topView.shared.transactions, "t_low"), undefined, "private downline record not served");
  const r = await save(w, "top", (x) => { find(x.shared.transactions, "t_peer").amount = 7; x.shared.transactions = x.shared.transactions.filter((rr) => rr.id !== "t_mid"); });
  assert.equal(r.status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_peer").amount, 7, "in-scope edit still works");
  assert.equal(find(w.state.doc.shared.transactions, "t_mid"), undefined, "in-scope delete still works");
  assert.deepEqual(find(w.state.doc.shared.transactions, "t_low"), rec("t_low", "low", { acl: acl(1, []) }));
});

test("NO invented hierarchy: a user with no upline / downline (or no linked node) only ever gets My Data", async () => {
  const w = world();
  const v = await view(w, "other");
  assert.deepEqual(v.dataScope.allowed, ["mine"]);
  for (const bad of ["upline", "downline", "mine_upline", "mine_downline", "upline_downline", "mine_upline_downline", "all"]) {
    assert.equal((await get(w, "other", bad)).status, 403, bad);
  }
  const w2 = world({ users: [...DEV_USERS, { id: "free", username: "free", role: "user", linkedId: null }] });
  assert.deepEqual((await view(w2, "free")).dataScope.allowed, ["mine"]);
  const ds = resolveDataScope(w2.state.doc, { uid: "dev", role: "developer", linkedId: null });
  assert.deepEqual(ds.owners.upline, []);
  assert.deepEqual(ds.owners.downline, []);
});

test("disabled users are never scope members (no downline / upline exposure of switched-off accounts)", async () => {
  const w = world();
  w.state.doc.users.find((u) => u.id === "low").disabled = true;
  const ds = resolveDataScope(w.state.doc, { uid: "mid", role: "admin", linkedId: "n_mid" });
  assert.deepEqual(ds.owners.downline, []);
  assert.deepEqual(ds.allowed, ["mine", "upline", "mine_upline"]);
  const dsLow = resolveDataScope(w.state.doc, { uid: "top", role: "admin", linkedId: "n_top" });
  assert.ok(!dsLow.owners.downline.includes("low"));
});

// ============================================================================================
// 15. Malformed hierarchy data fails closed
// ============================================================================================
test("HIERARCHY: cycles, dangling parents, duplicate nodes and missing nodes fail closed for hierarchy-derived scopes", () => {
  const users = [
    { id: "a", username: "a", role: "user", linkedId: "n_a" }, { id: "b", username: "b", role: "user", linkedId: "n_b" },
    { id: "c", username: "c", role: "user", linkedId: "n_c" }, { id: "d", username: "d", role: "user", linkedId: "n_d" },
  ];
  const run = (sups, uid) => {
    const u = users.find((x) => x.id === uid);
    return resolveDataScope({ users, shared: { supervisors: sups } }, { uid, role: "user", linkedId: u.linkedId });
  };
  const closed = (ds) => { assert.deepEqual(ds.owners.upline, []); assert.deepEqual(ds.owners.downline, []); assert.deepEqual(ds.allowed, ["mine"]); assert.equal(ds.maxScope, "mine"); };
  // sanity: a clean tree works
  const ok = run([{ id: "n_a", supervisorId: null }, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: "n_b" }, { id: "n_d", supervisorId: null }], "b");
  assert.deepEqual(ok.owners.upline, ["a"]);
  assert.deepEqual(ok.owners.downline, ["c"]);
  // cycle a -> b -> a
  for (const uid of ["a", "b"]) closed(run([{ id: "n_a", supervisorId: "n_b" }, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], uid));
  // self-parent
  closed(run([{ id: "n_a", supervisorId: "n_a" }, { id: "n_b", supervisorId: null }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "a"));
  // dangling parent
  closed(run([{ id: "n_a", supervisorId: "n_ghost" }, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "a"));
  closed(run([{ id: "n_a", supervisorId: "n_ghost" }, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "b"));
  // duplicate node ids (ambiguous tree)
  for (const uid of ["a", "b", "c"]) closed(run([{ id: "n_a", supervisorId: null }, { id: "n_a", supervisorId: "n_b" }, { id: "n_b", supervisorId: null }, { id: "n_c", supervisorId: "n_a" }, { id: "n_d", supervisorId: null }], uid));
  // caller's own node missing / malformed entries / non-string parent
  closed(run([{ id: "n_b", supervisorId: null }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "a"));
  closed(run([{ id: "n_a", supervisorId: 7 }, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "b"));
  closed(run([{ id: "n_a", supervisorId: null }, null, { id: "n_b", supervisorId: "n_a" }, { id: "n_c", supervisorId: null }, { id: "n_d", supervisorId: null }], "b"));
});

test("HIERARCHY: a cyclic tree through the Worker serves only My Data and refuses hierarchy scopes (no records leak)", async () => {
  const sups = [{ id: "n_top", supervisorId: "n_low" }, { id: "n_mid", supervisorId: "n_top" }, { id: "n_low", supervisorId: "n_mid" }, { id: "n_peer", supervisorId: "n_top" }, { id: "n_other", supervisorId: null }];
  const w = makeDevWorld(devDoc({ tx: TX, q: Q, sups }));
  const v = await view(w, "mid");
  assert.deepEqual(ids(v.shared.transactions), t("mid"));
  const r = await get(w, "mid", "mine_upline_downline");
  assert.equal(r.status, 403);
  assert.ok(!JSON.stringify(r.json).includes("cust-"), "a refused scope returns no record data");
});

// ============================================================================================
// 6 / 16. Payments and Quotations scopes are independent
// ============================================================================================
test("INDEPENDENT scopes: Payments and Quotations are filtered by their own scope in one request, and one never moves the other", async () => {
  const w = world();
  const r = await call(w, "mid", "/data/get", { scope: { transactions: "mine", quotations: "mine_upline_downline" } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const v = JSON.parse(r.json.data.json);
  assert.deepEqual(ids(v.shared.transactions), t("mid"));
  assert.deepEqual(ids(v.shared.quotations), q("top", "mid", "low"));
  assert.deepEqual(v.dataScope.activeBy, { transactions: "mine", quotations: "mine_upline_downline" });
  // flip them
  const r2 = await call(w, "mid", "/data/get", { scope: { transactions: "downline", quotations: "mine" } });
  const v2 = JSON.parse(r2.json.data.json);
  assert.deepEqual(ids(v2.shared.transactions), t("low"));
  assert.deepEqual(ids(v2.shared.quotations), q("mid"));
  // an omitted key takes the default for THAT collection only
  const v3 = JSON.parse((await call(w, "mid", "/data/get", { scope: { quotations: "upline" } })).json.data.json);
  assert.deepEqual(ids(v3.shared.transactions), t("mid", "low"), "payments stay on the default");
  assert.deepEqual(ids(v3.shared.quotations), q("top"));
  // a single string still applies to both (original behaviour)
  const v4 = JSON.parse((await call(w, "mid", "/data/get", { scope: "upline" })).json.data.json);
  assert.deepEqual(ids(v4.shared.transactions), t("top"));
  assert.deepEqual(ids(v4.shared.quotations), q("top"));
});

test("INDEPENDENT scopes: each one is validated on its own, so a bad entry for one collection refuses the whole request without data", async () => {
  const w = world();
  for (const bad of [{ transactions: "mine", quotations: "all" }, { transactions: "all" }, { transactions: "nope" }, { cheques: "mine" }, { transactions: 5 }, ["mine"], 7, true]) {
    const r = await call(w, "mid", "/data/get", { scope: bad });
    assert.equal(r.status, 403, JSON.stringify(bad));
    assert.equal(r.json.error.code, "SCOPE_NOT_ALLOWED");
    assert.equal(r.json.data, undefined);
  }
  // pure form
  const ds = resolveDataScope(world().state.doc, { uid: "mid", role: "admin", linkedId: "n_mid" });
  assert.deepEqual(resolveRequestedScopes(ds, { transactions: "mine" }), { ok: true, keys: { transactions: "mine", quotations: "mine_downline" } });
  assert.deepEqual(resolveRequestedScopes(ds, undefined), { ok: true, keys: { transactions: "mine_downline", quotations: "mine_downline" } });
  assert.equal(resolveRequestedScopes(ds, { transactions: "all" }).ok, false);
});

test("INDEPENDENT scopes in per-user storage: each collection's buckets follow that collection's own scope", async () => {
  const per = {};
  for (const o of OWNERS) per[o] = { transactions: [rec(`p_${o}`, o)], quotations: [rec(`pq_${o}`, o)], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], clients: [] };
  const w = makeDevWorld(devDoc({ perUser: per }));
  const v = await view(w, "mid", { transactions: "mine", quotations: "mine_upline_downline" });
  const txIn = Object.entries(v.perUser).filter(([, b]) => (b.transactions || []).length).map(([k]) => k).sort();
  const qIn = Object.entries(v.perUser).filter(([, b]) => (b.quotations || []).length).map(([k]) => k).sort();
  assert.deepEqual(txIn, ["mid"]);
  assert.deepEqual(qIn, ["low", "mid", "top"]);
  const low = await view(w, "low", { transactions: "mine", quotations: "mine_upline" });
  assert.deepEqual(Object.entries(low.perUser).filter(([, b]) => (b.transactions || []).length).map(([k]) => k), ["low"]);
  assert.deepEqual(Object.entries(low.perUser).filter(([, b]) => (b.quotations || []).length).map(([k]) => k).sort(), ["low", "mid", "top"]);
});

// ============================================================================================
// 8 / 9 / 17 / 18. All Data, forged requests, ceilings, leaks
// ============================================================================================
test("ALL DATA: developer and superadmin may choose it; every other role is refused server-side, however the request is shaped", async () => {
  const w = world();
  for (const uid of ["dev", "root", "sa2"]) assert.deepEqual(ids((await view(w, uid, "all")).shared.transactions), t(...OWNERS), uid);
  for (const uid of ["top", "mid", "low", "peer", "other"]) {
    for (const body of [{ scope: "all" }, { scope: { transactions: "all", quotations: "all" } }, { scope: { quotations: "all" } }]) {
      const r = await call(w, uid, "/data/get", body);
      assert.equal(r.status, 403, `${uid} ${JSON.stringify(body)}`);
    }
    // role / permission smuggling in the body or token
    for (const extra of [{ role: "superadmin" }, { role: "developer" }, { allowed: ["all"] }, { dataScope: { allowed: ["all"] } }, { policy: { all: true } }]) {
      assert.equal((await call(w, uid, "/data/get", { scope: "all", ...extra })).status, 403);
    }
    assert.equal((await call(w, uid, "/data/get", { scope: "all" }, { tokenRole: "developer" })).status, 403);
    assert.equal((await call(w, uid, "/data/get", { scope: "all" }, { tokenRole: "superadmin" })).status, 403);
  }
});

test("CEILING: a requested scope never exceeds the server-authorized maximum, and the served data never exceeds it either", async () => {
  const w = world();
  const cases = { low: "mine_upline", peer: "mine_upline", top: "mine_downline", mid: "mine_upline_downline", other: "mine" };
  for (const [uid, max] of Object.entries(cases)) {
    const v = await view(w, uid, max);
    assert.equal(v.dataScope.max, max, uid);
    const allowed = new Set(v.dataScope.allowed);
    for (const key of ["all", "mine", "upline", "downline", "mine_upline", "mine_downline", "upline_downline", "mine_upline_downline"]) {
      const r = await get(w, uid, key);
      assert.equal(r.status, allowed.has(key) ? 200 : 403, `${uid} ${key}`);
    }
    // whatever was requested, every served record is owned by someone inside the ceiling
    const inside = new Set(v.dataScope.owners[max]);
    for (const key of allowed) {
      const sv = await view(w, uid, key);
      for (const r of [...sv.shared.transactions, ...sv.shared.quotations]) assert.ok(inside.has(r.ownerId), `${uid}/${key} leaked ${r.id}`);
    }
  }
});

test("NO LEAKS: refused scopes, other people's records, names and activity never reach a scoped caller (views, errors, exports)", async () => {
  const log = (name, actor, coll, owner) => ({ ts: Date.now() + Math.random(), user: actor, action: "added", coll, name, scopeId: `n_${actor}`, actorUid: actor, recId: `${coll === "transactions" ? "t" : "q"}_${owner}`, recBucket: null });
  const w = world({ activityLog: [log("Secret Other", "other", "transactions", "other"), log("Secret Peer", "peer", "quotations", "peer"), log("Mine Low", "low", "transactions", "low")] });
  const raw = JSON.stringify(await view(w, "low", "mine_upline"));
  for (const hidden of ["cust-t_other", "cust-t_peer", "cust-t_root", "cust-t_dev", "cust-q_other", "Secret Other", "Secret Peer"]) assert.ok(!raw.includes(hidden), `leaked ${hidden}`);
  assert.ok(raw.includes("Mine Low"));
  const refused = await get(w, "low", "all");
  assert.ok(!JSON.stringify(refused.json).match(/cust-|Secret|ownerId|"id":"t_/), "error body carries no record data");
  const exp = await call(w, "low", "/privacy/export", {});
  assert.equal(exp.status, 200);
  const expRaw = JSON.stringify(exp.json);
  for (const hidden of ["cust-t_other", "cust-t_peer", "cust-t_top", "cust-t_mid", "Secret"]) assert.ok(!expRaw.includes(hidden), `export leaked ${hidden}`);
  // narrowing the scope narrows the activity log too (per collection)
  const narrow = await view(w, "mid", { transactions: "mine", quotations: "mine" });
  assert.ok(!JSON.stringify(narrow.activityLog).includes("Secret"));
});

// ============================================================================================
// 7. Developer configures the permitted scope options per user and for superadmins
// ============================================================================================
test("POLICY: Developer can narrow what a user may use (upline / downline) and it limits real authority, not just the dropdown", async () => {
  const w = world();
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "mid", policy: { downline: false } } })).status, 200);
  const v = await view(w, "mid");
  assert.deepEqual(v.dataScope.allowed, ["mine", "upline", "mine_upline"], "no downline options left");
  assert.equal((await get(w, "mid", "mine_downline")).status, 403);
  assert.deepEqual(ids(v.shared.transactions), t("mid"), "default is now My Data");
  // the write ceiling shrank too: mid can no longer edit low's records
  const blob = await view(w, "mid", "mine_upline"); // (the helper save() asks for the old maximum, which is no longer allowed)
  blob.shared.transactions.push(rec("t_low", "low", { amount: 1 }));
  const r = await call(w, "mid", "/data/save", { json: JSON.stringify(blob) });
  assert.equal(r.status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_low").amount, 100, "low's record is outside mid's write ceiling now");
  // low: upline removed
  assert.equal((await policy(w, { baseRev: 1, user: { uid: "low", policy: { upline: false } } })).status, 200);
  const low = await view(w, "low");
  assert.deepEqual(low.dataScope.allowed, ["mine"]);
  assert.deepEqual(ids(low.shared.transactions), t("low"));
  assert.equal((await get(w, "low", "mine_upline")).status, 403);
  // reset one user back to the default
  assert.equal((await policy(w, { baseRev: 2, user: { uid: "low", policy: null } })).status, 200);
  assert.deepEqual((await view(w, "low")).dataScope.allowed, ["mine", "upline", "mine_upline"]);
});

test("POLICY: Developer can take All Data away from one superadmin, or from all of them; the Developer itself is never affected", async () => {
  const w = world();
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "root", policy: { all: false } } })).status, 200);
  assert.equal((await get(w, "root", "all")).status, 403, "root lost All Data");
  const root = await view(w, "root");
  assert.deepEqual(root.dataScope.allowed, ["mine"]);
  assert.deepEqual(ids(root.shared.transactions), t("root"), "and now behaves like any hierarchy-scoped account");
  const sa2 = await view(w, "sa2", "all");
  assert.deepEqual(ids(sa2.shared.transactions), t(...OWNERS), "the other superadmin is untouched");
  // root's record-level authority narrowed with it (not just the dropdown)
  const rootBlob = await view(w, "root");
  rootBlob.shared.transactions.push(rec("t_other", "other", { amount: 1 }));
  assert.equal((await call(w, "root", "/data/save", { json: JSON.stringify(rootBlob) })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_other").amount, 100, "root can no longer write other people's records");
  assert.ok(find(w.state.doc.shared.transactions, "t_root"));
  // global switch
  assert.equal((await policy(w, { baseRev: 1, global: { superadminAll: false } })).status, 200);
  assert.equal((await get(w, "sa2", "all")).status, 403);
  assert.deepEqual((await view(w, "dev", "all")).dataScope.allowed[0], "all");
  assert.deepEqual(ids((await view(w, "dev", "all")).shared.transactions), t(...OWNERS));
  // and back
  assert.equal((await policy(w, { baseRev: 2, global: { superadminAll: true } })).status, 200);
  assert.equal((await policy(w, { baseRev: 3, user: { uid: "root", policy: null } })).status, 200);
  assert.deepEqual(ids((await view(w, "root", "all")).shared.transactions), t(...OWNERS));
});

test("POLICY: it can only narrow -- no option is ever added, All Data never reaches admins/users, the Developer cannot be restricted", async () => {
  const w = world();
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "top", policy: { all: true } } })).status, 400, "all is not configurable for an admin");
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "low", policy: { all: false } } })).status, 400);
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "dev", policy: { downline: false } } })).status, 403, "Developer cannot be locked out");
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "ghost", policy: { downline: false } } })).status, 404);
  for (const bad of [{}, { baseRev: 0 }, { baseRev: "0", global: { superadminAll: false } }, { baseRev: -1, global: { superadminAll: false } }, { baseRev: 0, global: { superadminAll: "no" } }, { baseRev: 0, global: { superadminAll: false, extra: 1 } },
    { baseRev: 0, user: { uid: "top" } }, { baseRev: 0, user: { uid: "top", policy: { upline: "x" } } }, { baseRev: 0, user: { uid: "top", policy: { bogus: false } } }, { baseRev: 0, user: { uid: "top", policy: {} } }, { baseRev: 0, global: { superadminAll: false }, extra: 1 }]) {
    assert.equal((await policy(w, bad)).status, 400, JSON.stringify(bad));
  }
  assert.equal(w.state.doc.scopePolicy, undefined, "nothing was written");
  // `true` means "default": it never widens what the hierarchy allows
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "low", policy: { downline: true, upline: true } } })).status, 200);
  assert.equal(w.state.doc.scopePolicy, undefined, "an all-default policy is a no-op and writes nothing");
  assert.deepEqual((await view(w, "low")).dataScope.allowed, ["mine", "upline", "mine_upline"], "low still has no downline: nothing was invented");
  assert.deepEqual(effectivePolicyFor({ rev: 1, global: { superadminAll: true }, users: { top: { downline: false } } }, "top", "admin"), { upline: true, downline: false, allAllowed: false });
  assert.deepEqual(effectivePolicyFor(undefined, "top", "admin"), { upline: true, downline: true, allAllowed: false });
  assert.deepEqual(validateUserPolicyInput({ upline: true, downline: true }, "admin"), { ok: true, entry: null });
});

test("POLICY: only the Developer may change it; stale revisions are refused, changes are audited, and /data/save can never carry it", async () => {
  const w = world();
  for (const uid of ["root", "sa2", "top", "mid", "low", "other"]) {
    const r = await policy(w, { baseRev: 0, global: { superadminAll: false } }, uid);
    assert.equal(r.status, 403, uid);
  }
  assert.equal((await policy(w, { baseRev: 0, user: { uid: "mid", policy: { upline: false } } })).status, 200);
  const stale = await policy(w, { baseRev: 0, user: { uid: "mid", policy: null } });
  assert.equal(stale.status, 409);
  assert.equal(stale.json.error.code, "POLICY_STALE");
  assert.equal(stale.json.error.currentRev, 1);
  assert.deepEqual(w.state.doc.scopePolicy, { rev: 1, global: { superadminAll: true }, users: { mid: { upline: false } } });
  const audit = w.state.doc.accessAudit[0];
  assert.equal(audit.action, "scope_policy");
  assert.equal(audit.actor, "dev");
  assert.equal(audit.target, "mid");
  assert.equal(audit.rev, 1);
  // a blob (even the Developer's own full save, or a superadmin's) cannot overwrite the stored policy or the audit trail
  for (const uid of ["dev", "root", "top"]) {
    await save(w, uid, (v) => { v.scopePolicy = { rev: 99, global: { superadminAll: false }, users: {} }; v.accessAudit = []; });
  }
  assert.equal(w.state.doc.scopePolicy.rev, 1);
  assert.equal(w.state.doc.accessAudit.length, 1);
  // only the Developer's view carries the policy and the audit trails
  assert.deepEqual((await view(w, "dev")).dataScope.control.scopePolicy, w.state.doc.scopePolicy);
  assert.equal((await view(w, "dev")).dataScope.control.accessAudit.length, 1);
  for (const uid of ["root", "top", "low"]) assert.equal((await view(w, uid)).dataScope.control, undefined, uid);
});

test("POLICY: a stored policy that is malformed FAILS CLOSED (no upline / downline / superadmin All Data) and the Developer can repair it", async () => {
  const w = world({ extra: { scopePolicy: { rev: "x", oops: true } } });
  assert.equal(parseScopePolicy({ rev: "x" }).kind, "invalid");
  assert.equal((await get(w, "root", "all")).status, 403);
  assert.deepEqual((await view(w, "mid")).dataScope.allowed, ["mine"]);
  assert.deepEqual(ids((await view(w, "dev", "all")).shared.transactions), t(...OWNERS), "the Developer is unaffected");
  assert.equal((await view(w, "dev")).dataScope.control.scopePolicy.invalid, true);
  assert.equal((await policy(w, { baseRev: 0, global: { superadminAll: true } })).status, 200, "repair");
  assert.deepEqual(ids((await view(w, "root", "all")).shared.transactions), t(...OWNERS));
  assert.deepEqual((await view(w, "mid")).dataScope.allowed.length, 7);
});

test("POLICY: concurrent policy changes cannot both win (optimistic concurrency + revision check)", async () => {
  const w = world();
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const first = policy(w, { baseRev: 0, user: { uid: "mid", policy: { upline: false } } });
  await hit;
  const second = await policy(w, { baseRev: 0, user: { uid: "low", policy: { upline: false } } });
  release();
  const firstRes = await first;
  assert.deepEqual([firstRes.status, second.status].sort(), [200, 409]);
  assert.equal(w.state.doc.scopePolicy.rev, 1);
});

test("ROLE-DEMOTION freshness: an old developer / superadmin token loses All Data the moment the stored role drops", async () => {
  const w = world();
  assert.equal((await get(w, "root", "all")).status, 200);
  w.state.doc.users.find((u) => u.id === "root").role = "admin";
  assert.equal((await call(w, "root", "/data/get", { scope: "all" }, { tokenRole: "superadmin" })).status, 403);
  assert.equal((await call(w, "root", "/scope/policy", { baseRev: 0, global: { superadminAll: false } }, { tokenRole: "developer" })).status, 403);
});

test("buildAuthorizedView exposes only the server-authorized 'Assigned To' people (no PINs, hierarchy ids or roles)", () => {
  const doc = devDoc({ tx: TX, q: Q });
  const v = buildAuthorizedView(doc, { uid: "mid", role: "admin", linkedId: "n_mid" });
  const targets = v.dataScope.assignTargets.transactions;
  assert.deepEqual(targets.map((x) => x.uid), ["low", "mid"]);
  for (const x of targets) assert.deepEqual(Object.keys(x).sort(), ["name", "uid", "username"]);
});
