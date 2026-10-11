// ============================================================================================
// DEVELOPER > SUPERADMIN > ADMIN > SUPERVISORS/USERS -- role hierarchy, account management, Developer bootstrap,
// disabled accounts. Everything runs through the real Worker (routing, Firebase ID-token verification, Firestore
// optimistic concurrency) with a fake Firestore, credentials doc and Identity Toolkit (helpers/devWorld.js).
//
// Fixture (helpers/devWorld.js):  dev = developer, root + sa2 = superadmins, top -> mid -> low (+ peer under top), other.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { rec, find, call, getView, save, makeDevWorld, devDoc, callPublic, credFor, DEV_USERS } from "./helpers/devWorld.js";
import { effectiveRole, mergeAuthorizedSave } from "../lib/authorization.js";
import { authorizeSetUserPin } from "../lib/userPin.js";

const ALL_TX = [rec("t_dev", "dev"), rec("t_root", "root"), rec("t_top", "top"), rec("t_mid", "mid"), rec("t_low", "low"), rec("t_peer", "peer"), rec("t_other", "other")];
const ALL_Q = ALL_TX.map((r) => rec(r.id.replace("t_", "q_"), r.ownerId));
const world = (o = {}, w = {}) => makeDevWorld(devDoc({ tx: ALL_TX, q: ALL_Q, ...o }), w);
const userRow = (w, id) => w.state.doc.users.find((u) => u.id === id);
const ids = (arr) => (arr || []).map((r) => r.id).sort();

// ============================================================================================
// 1. Developer has every Superadmin capability and can manage Superadmin accounts
// ============================================================================================
test("DEVELOPER: sees every Payment and Quotation under All Data, exactly like a superadmin", async () => {
  const w = world();
  for (const uid of ["dev", "root"]) {
    const v = await getView(w, uid, "all");
    assert.deepEqual(ids(v.shared.transactions), ids(ALL_TX), `${uid}: every payment`);
    assert.deepEqual(ids(v.shared.quotations), ids(ALL_Q), `${uid}: every quotation`);
    assert.deepEqual(v.dataScope.allowed[0], "all");
  }
});

test("DEVELOPER: can edit, delete and create any record, and set record-level access, regardless of owner", async () => {
  const w = world();
  assert.equal((await save(w, "dev", (v) => { find(v.shared.transactions, "t_other").amount = 999; })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_other").amount, 999);
  assert.equal((await save(w, "dev", (v) => { v.shared.transactions = v.shared.transactions.filter((r) => r.id !== "t_low"); })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_low"), undefined);
  assert.equal((await save(w, "dev", (v) => { v.shared.transactions.push({ id: "t_new", ownerId: "other", customer: "n", amount: 1 }); })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_new").ownerId, "other");
  const a = await call(w, "dev", "/record/acl", { collection: "transactions", bucket: null, id: "t_mid", baseRev: 0, grants: [{ uid: "low", perms: ["edit"] }] });
  assert.equal(a.status, 200);
});

test("DEVELOPER: creates, promotes, demotes, resets credentials of and removes SUPERADMIN accounts (secure setPin path)", async () => {
  const w = world({}, { credentials: { root: credFor("111222", "superadmin"), sa2: credFor("333444", "superadmin"), top: credFor("555666", "admin") } });
  // create a new superadmin
  let r = await call(w, "dev", "/user/setPin", { targetUserId: "sa3", newPin: "55667788", role: "superadmin" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(userRow(w, "sa3").role, "superadmin");
  assert.equal(w.creds.sa3.role, "superadmin");
  assert.ok(await bcrypt.compare("55667788", w.creds.sa3.pinHash), "stored as a bcrypt hash");
  // promote an admin to superadmin, then demote a superadmin to admin
  r = await call(w, "dev", "/user/setPin", { targetUserId: "top", role: "superadmin" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(userRow(w, "top").role, "superadmin");
  assert.equal(w.creds.top.role, "superadmin");
  r = await call(w, "dev", "/user/setPin", { targetUserId: "sa2", role: "admin" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(userRow(w, "sa2").role, "admin");
  assert.equal(w.creds.sa2.role, "admin");
  // reset a superadmin's PIN (sessions revoked through the existing mechanism)
  const before = w.identity.length;
  r = await call(w, "dev", "/user/setPin", { targetUserId: "root", newPin: "99887766" });
  assert.equal(r.status, 200);
  assert.ok(await bcrypt.compare("99887766", w.creds.root.pinHash));
  assert.ok(w.identity.slice(before).some((c) => c.body && c.body.validSince), "refresh tokens revoked");
  // remove a superadmin
  r = await call(w, "dev", "/user/setPin", { targetUserId: "sa3", delete: true });
  assert.equal(r.status, 200);
  assert.equal(userRow(w, "sa3"), undefined);
});

test("DEVELOPER: manages superadmins through /data/save too (promote, demote, disable, remove); superadmin rows are no longer superadmin-editable", async () => {
  const w = world();
  assert.equal((await save(w, "dev", (v) => { v.users.find((u) => u.id === "sa2").role = "admin"; })).status, 200);
  assert.equal(userRow(w, "sa2").role, "admin", "demoted");
  assert.equal((await save(w, "dev", (v) => { v.users.find((u) => u.id === "mid").role = "superadmin"; })).status, 200);
  assert.equal(userRow(w, "mid").role, "superadmin", "promoted");
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "root", disabled: true })).status, 200);
  assert.equal(userRow(w, "root").disabled, true, "disabled (only through the dedicated endpoint)");
  assert.equal((await save(w, "dev", (v) => { v.users = v.users.filter((u) => u.id !== "mid"); })).status, 200);
  assert.equal(userRow(w, "mid"), undefined, "removed");
});

test("DEVELOPER: a disabled superadmin can neither read, write nor sign in (checked against fresh server state)", async () => {
  const w = world({}, { credentials: { root: credFor("111222", "superadmin") } });
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "root", disabled: true })).status, 200);
  const get = await call(w, "root", "/data/get", {});
  assert.equal(get.status, 403);
  assert.equal(get.json.error.message, "Account disabled");
  assert.equal((await call(w, "root", "/data/save", { json: JSON.stringify({}) })).status, 403);
  assert.equal((await call(w, "root", "/record/acl", { collection: "transactions", id: "t_low", baseRev: 0, grants: [] })).status, 403);
  assert.equal((await call(w, "root", "/privacy/export", {})).status, 403);
  const login = await callPublic(w, "/login", { username: "root", pin: "111222" });
  assert.equal(login.status, 401, "same generic failure as a wrong PIN");
  // re-enabled: works again
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "root", disabled: false })).status, 200);
  assert.equal((await callPublic(w, "/login", { username: "root", pin: "111222" })).status, 200);
});

test("DEVELOPER: cannot be disabled or demoted by anyone, not even by a save that carries the Developer's own id", async () => {
  const w = world();
  for (const uid of ["dev"]) {
    assert.equal((await save(w, uid, (v) => { const d = v.users.find((u) => u.id === "dev"); d.disabled = true; d.role = "user"; })).status, 200);
  }
  assert.equal(userRow(w, "dev").role, "developer");
  assert.notEqual(userRow(w, "dev").disabled, true);
  assert.equal((await call(w, "dev", "/data/get", {})).status, 200);
});

// ============================================================================================
// 2. Superadmin: full business-record access
// ============================================================================================
test("SUPERADMIN: full Payment and Quotation access under All Data, regardless of owner, hierarchy or record ACL", async () => {
  const w = world({ tx: [...ALL_TX, rec("t_priv", "low", { acl: { rev: 1, grants: [] } })] });
  const v = await getView(w, "root", "all");
  assert.deepEqual(ids(v.shared.transactions), ids([...ALL_TX, rec("t_priv", "low")]));
  assert.deepEqual(find(v.shared.transactions, "t_priv").acl, { rev: 1, grants: [] }, "superadmin sees the access list");
  assert.equal((await save(w, "root", (x) => { find(x.shared.transactions, "t_priv").amount = 5; })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_priv").amount, 5, "can edit a private record of a lower user");
  assert.equal((await save(w, "root", (x) => { x.shared.transactions.push({ id: "t_r2", ownerId: "mid", customer: "c", amount: 1 }); })).status, 200);
  assert.equal(find(w.state.doc.shared.transactions, "t_r2").ownerId, "mid", "creates for another user");
});

// ============================================================================================
// 3. Superadmin cannot change or remove Developer, nor impersonate it
// ============================================================================================
test("SUPERADMIN cannot change, disable, reset or delete the Developer, nor create / promote a Developer (setPin)", async () => {
  const w = world({}, { credentials: { dev: credFor("DevPin#1234", "developer") } });
  const dev = (payload) => call(w, "root", "/user/setPin", payload);
  assert.equal((await dev({ targetUserId: "dev", newPin: "hacked99" })).status, 403, "reset");
  assert.equal((await dev({ targetUserId: "dev", role: "user" })).status, 403, "demote");
  assert.equal((await dev({ targetUserId: "dev", delete: true })).status, 403, "delete");
  assert.equal((await dev({ targetUserId: "newdev", newPin: "12345678", role: "developer" })).status, 403, "create developer");
  assert.equal((await dev({ targetUserId: "low", role: "developer" })).status, 403, "promote to developer");
  assert.ok(await bcrypt.compare("DevPin#1234", w.creds.dev.pinHash), "credentials untouched");
  assert.equal(userRow(w, "dev").role, "developer");
  // Nobody -- not even the Developer -- can mint a second Developer or delete the Developer through setPin.
  assert.equal((await call(w, "dev", "/user/setPin", { targetUserId: "low", role: "developer" })).status, 403);
  assert.equal((await call(w, "dev", "/user/setPin", { targetUserId: "n2", newPin: "12345678", role: "developer" })).status, 403);
  assert.equal((await call(w, "dev", "/user/setPin", { targetUserId: "dev", delete: true })).status, 403);
});

test("SUPERADMIN cannot alter, remove or forge the Developer through /data/save (users blob), nor grant itself Developer", async () => {
  const w = world();
  const edits = [
    (v) => { const d = v.users.find((u) => u.id === "dev"); d.role = "user"; d.disabled = true; d.username = "pwned"; d.linkedId = "n_top"; },
    (v) => { v.users = v.users.filter((u) => u.id !== "dev"); },
    (v) => { v.users.find((u) => u.id === "root").role = "developer"; },
    (v) => { v.users.push({ id: "fake", username: "fake", role: "developer", linkedId: null }); },
    (v) => { v.users.find((u) => u.id === "low").role = "developer"; },
  ];
  for (const edit of edits) assert.equal((await save(w, "root", edit)).status, 200);
  assert.deepEqual(userRow(w, "dev"), DEV_USERS.find((u) => u.id === "dev"), "Developer row byte-for-byte unchanged");
  assert.equal(userRow(w, "root").role, "superadmin");
  assert.equal(userRow(w, "fake").role, "user", "a forged developer row is demoted to an ordinary user");
  assert.equal(userRow(w, "low").role, "user");
  assert.equal(w.state.doc.users.filter((u) => u.role === "developer").length, 1, "exactly one Developer, ever");
});

test("SUPERADMIN cannot impersonate the Developer: a forged developer claim is demoted to the stored role", async () => {
  const w = world();
  // token says developer, stored record says superadmin -> effective role superadmin: the Developer-only route refuses
  const r = await call(w, "root", "/scope/policy", { baseRev: 0, global: { superadminAll: false } }, { tokenRole: "developer" });
  assert.equal(r.status, 403);
  assert.equal(w.state.doc.scopePolicy, undefined);
  assert.equal(effectiveRole("developer", { role: "superadmin" }), "superadmin");
  assert.equal(effectiveRole("developer", { role: "admin" }), "admin");
  assert.equal(effectiveRole("superadmin", { role: "developer" }), "superadmin", "a stored role never RAISES the token's role");
});

test("login never mints Developer from a users[] row alone: only a credentials entry written by the bootstrap does", async () => {
  const w = world({ users: [...DEV_USERS, { id: "sneak", username: "sneak", role: "developer", linkedId: null }] }, {
    credentials: { sneak: { pinHash: bcrypt.hashSync("424242", 4) }, dev: credFor("DevPin#1234", "developer") },
  });
  const sneak = await callPublic(w, "/login", { username: "sneak", pin: "424242" });
  assert.equal(sneak.status, 200);
  assert.equal(sneak.json.user.role, "user", "no developer credentials entry => ordinary user");
  const dev = await callPublic(w, "/login", { username: "dev", pin: "DevPin#1234" });
  assert.equal(dev.status, 200);
  assert.equal(dev.json.user.role, "developer");
});

// ============================================================================================
// 4. Only the Developer can promote or demote a Superadmin
// ============================================================================================
test("ONLY the Developer promotes / demotes / removes superadmins; superadmin and admin are refused on every path", async () => {
  const w = world({}, { credentials: { root: credFor("111222", "superadmin"), sa2: credFor("333444", "superadmin") } });
  for (const caller of ["root", "top"]) {
    assert.equal((await call(w, caller, "/user/setPin", { targetUserId: "sa2", role: "admin" })).status, 403, `${caller}: demote`);
    assert.equal((await call(w, caller, "/user/setPin", { targetUserId: "sa2", newPin: "77889900" })).status, 403, `${caller}: reset`);
    assert.equal((await call(w, caller, "/user/setPin", { targetUserId: "sa2", delete: true })).status, 403, `${caller}: delete`);
    assert.equal((await call(w, caller, "/user/setPin", { targetUserId: "low", role: "superadmin" })).status, 403, `${caller}: promote`);
    assert.equal((await call(w, caller, "/user/setPin", { targetUserId: "brandnew", newPin: "12345678", role: "superadmin" })).status, 403, `${caller}: create`);
  }
  assert.equal(userRow(w, "sa2").role, "superadmin");
  assert.equal(userRow(w, "low").role, "user");
  // /data/save: promotion, demotion, disabling and removal of a superadmin row are all ignored for a superadmin caller
  assert.equal((await save(w, "root", (v) => {
    v.users.find((u) => u.id === "low").role = "superadmin";
    const s2 = v.users.find((u) => u.id === "sa2"); s2.role = "user"; s2.disabled = true;
  })).status, 200);
  assert.equal(userRow(w, "low").role, "user");
  assert.equal(userRow(w, "sa2").role, "superadmin");
  assert.notEqual(userRow(w, "sa2").disabled, true);
  assert.equal((await save(w, "root", (v) => { v.users = v.users.filter((u) => u.id !== "sa2"); })).status, 200);
  assert.ok(userRow(w, "sa2"), "a superadmin row cannot be removed by omission");
  // a superadmin keeps managing ordinary users and admins, and can edit its OWN profile fields but not its role
  assert.equal((await save(w, "root", (v) => { v.users.find((u) => u.id === "peer").username = "peer2"; v.users.find((u) => u.id === "mid").role = "user"; })).status, 200);
  assert.equal(userRow(w, "peer").username, "peer2");
  assert.equal(userRow(w, "mid").role, "user");
  assert.equal((await save(w, "root", (v) => { const me = v.users.find((u) => u.id === "root"); me.role = "admin"; me.disabled = true; me.linkedId = "n_top"; })).status, 200);
  assert.equal(userRow(w, "root").role, "superadmin");
  assert.notEqual(userRow(w, "root").disabled, true);
  assert.equal(userRow(w, "root").linkedId, "n_top", "ordinary profile edits of its own row still work");
});

test("authorizeSetUserPin matrix: developer > superadmin > admin", () => {
  const sa = { id: "s", role: "superadmin" }, adm = { id: "a", role: "admin" }, dev = { id: "d", role: "developer" };
  const as = (callerRole, target, payload) => authorizeSetUserPin({ uid: "caller", role: callerRole }, target, { targetUserId: target ? target.id : "new", ...payload }).ok;
  assert.equal(as("developer", sa, { newPin: "x" }), true);
  assert.equal(as("developer", sa, { role: "admin" }), true);
  assert.equal(as("developer", sa, { delete: true }), true);
  assert.equal(as("developer", dev, { newPin: "x" }), false);
  assert.equal(as("developer", dev, { delete: true }), false);
  assert.equal(as("developer", null, { newPin: "x", role: "developer" }), false);
  assert.equal(as("superadmin", adm, { newPin: "x", role: "user" }), true, "superadmin still manages admins");
  assert.equal(as("superadmin", adm, { delete: true }), true);
  assert.equal(as("superadmin", sa, { newPin: "x" }), false);
  assert.equal(as("superadmin", dev, { newPin: "x" }), false);
  assert.equal(as("superadmin", null, { newPin: "x", role: "superadmin" }), false);
  assert.equal(as("admin", adm, { delete: true }), false);
  assert.equal(as("admin", null, { newPin: "x", role: "superadmin" }), false);
  assert.equal(as("admin", null, { newPin: "x", role: "user" }), true);
  assert.equal(as("user", null, { newPin: "x" }), false);
});

// ============================================================================================
// 5. Admin cannot access All Data or grant itself higher privileges
// ============================================================================================
test("ADMIN: cannot request All Data, self-promote, edit permissions, or touch Developer-owned policy", async () => {
  const w = world();
  for (const uid of ["top", "mid"]) {
    const r = await call(w, uid, "/data/get", { scope: "all" });
    assert.equal(r.status, 403, `${uid}: All Data refused`);
    assert.equal(r.json.error.code, "SCOPE_NOT_ALLOWED");
    assert.equal(r.json.data, undefined, "no data on a refused scope");
    const forged = await call(w, uid, "/data/get", { scope: "all" }, { tokenRole: "superadmin" });
    assert.equal(forged.status, 403, "a forged superadmin token claim is demoted to the stored role");
    const forgedDev = await call(w, uid, "/data/get", { scope: "all" }, { tokenRole: "developer" });
    assert.equal(forgedDev.status, 403);
  }
  assert.ok(!(await getView(w, "top")).dataScope.allowed.includes("all"));
  // self-promotion and policy / permission tampering through a blob
  const r = await save(w, "top", (v) => {
    v.users.find((u) => u.id === "top").role = "superadmin";
    v.permissions = { admin: { marathon: "hidden" } };
    v.userPermissions = { top: { marathon: "write" } };
    v.scopePolicy = { rev: 5, global: { superadminAll: false }, users: {} };
    v.accessAudit = [{ forged: true }];
  });
  assert.equal(r.status, 200);
  assert.equal(userRow(w, "top").role, "admin");
  assert.deepEqual(w.state.doc.permissions, { user: { marathon: "write", quotations: "write" } });
  assert.equal(w.state.doc.scopePolicy, undefined);
  assert.deepEqual(w.state.doc.accessAudit || [], [], "a blob cannot plant audit entries");
  assert.equal((await call(w, "top", "/scope/policy", { baseRev: 0, global: { superadminAll: false } })).status, 403);
  assert.equal((await call(w, "top", "/scope/policy", { baseRev: 0, global: { superadminAll: false } }, { tokenRole: "developer" })).status, 403, "forged developer claim");
  assert.equal((await call(w, "top", "/user/setPin", { targetUserId: "mid", role: "superadmin" })).status, 403);
  assert.equal((await call(w, "top", "/user/setPin", { targetUserId: "dev", newPin: "12345678" })).status, 403);
});

test("ordinary users: no All Data, no developer/superadmin powers, no setPin on others", async () => {
  const w = world();
  for (const uid of ["low", "peer", "other"]) {
    assert.equal((await call(w, uid, "/data/get", { scope: "all" })).status, 403);
    assert.equal((await call(w, uid, "/data/get", { scope: "all" }, { tokenRole: "developer" })).status, 403);
    assert.equal((await call(w, uid, "/scope/policy", { baseRev: 0, global: { superadminAll: false } }, { tokenRole: "developer" })).status, 403);
    assert.equal((await call(w, uid, "/user/setPin", { targetUserId: "root", newPin: "12345678" })).status, 403);
  }
  assert.equal((await save(w, "low", (v) => { v.users.find((u) => u.id === "low").role = "developer"; })).status, 200);
  assert.equal(userRow(w, "low").role, "user");
});

test("merge-level: imports / backups / stale saves cannot create or keep a Developer or a superadmin grant", () => {
  const server = devDoc();
  const backup = JSON.parse(JSON.stringify(server));
  backup.users.push({ id: "ghost", username: "ghost", role: "developer", linkedId: null });
  backup.users.find((u) => u.id === "low").role = "superadmin";
  const asSuper = mergeAuthorizedSave(server, backup, { uid: "root", role: "superadmin", linkedId: null });
  assert.equal(asSuper.users.find((u) => u.id === "ghost").role, "user");
  assert.equal(asSuper.users.find((u) => u.id === "low").role, "user");
  const asDev = mergeAuthorizedSave(server, backup, { uid: "dev", role: "developer", linkedId: null });
  assert.equal(asDev.users.find((u) => u.id === "ghost").role, "user", "even the Developer cannot mint a second Developer through a blob");
  assert.equal(asDev.users.find((u) => u.id === "low").role, "superadmin", "but can promote to superadmin");
});

// ============================================================================================
// Developer bootstrap (Part 7): secure, one-time, no built-in credential
// ============================================================================================
const SECRET = "bootstrap-secret-0123456789-abcdefghij";
const bootWorld = (w = {}) => makeDevWorld(devDoc({ users: DEV_USERS.filter((u) => u.role !== "developer") }), { env: { DEVELOPER_BOOTSTRAP_TOKEN: SECRET }, ...w });

test("BOOTSTRAP: disabled unless the deployer set the DEVELOPER_BOOTSTRAP_TOKEN secret; no default credential exists", async () => {
  const w = makeDevWorld(devDoc({ users: DEV_USERS.filter((u) => u.role !== "developer") }));
  const r = await callPublic(w, "/developer/bootstrap", { token: "anything", username: "me", newPin: "Str0ngPin!" });
  assert.equal(r.status, 404);
  assert.equal(w.state.doc.users.some((u) => u.role === "developer"), false);
  const short = makeDevWorld(devDoc(), { env: { DEVELOPER_BOOTSTRAP_TOKEN: "short" } });
  assert.equal((await callPublic(short, "/developer/bootstrap", { token: "short", username: "me", newPin: "Str0ngPin!" })).status, 404, "a weak secret is treated as not configured");
});

test("BOOTSTRAP: wrong token, weak PIN and bad payloads create nothing", async () => {
  const w = bootWorld();
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: "wrong", username: "me", newPin: "Str0ngPin!" })).status, 403);
  assert.equal((await callPublic(w, "/developer/bootstrap", { username: "me", newPin: "Str0ngPin!" })).status, 403);
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "me", newPin: "1234" })).status, 400, "too short");
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "me", newPin: "11111111" })).status, 400, "trivial repeat");
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "me", newPin: "x".repeat(40) })).status, 400, "too long");
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, newPin: "Str0ngPin!" })).status, 400, "username required");
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "root", newPin: "Str0ngPin!" })).status, 409, "username taken");
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, userId: "root", currentPin: "wrong", newPin: "Str0ngPin!" })).status, 403);
  assert.equal(w.state.doc.users.some((u) => u.role === "developer"), false);
  assert.deepEqual(w.creds, {});
});

test("BOOTSTRAP: creates the Developer once, stores only a bcrypt hash, returns no secret, then refuses forever", async () => {
  const w = bootWorld();
  const r = await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "owner", newPin: "My-Own-Pin-77" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const body = JSON.stringify(r.json);
  assert.ok(!body.includes("My-Own-Pin-77") && !body.includes(SECRET) && !body.includes("$2"), "no PIN, secret or hash in the response");
  const dev = w.state.doc.users.find((u) => u.role === "developer");
  assert.equal(dev.username, "owner");
  assert.equal(dev.linkedId, null);
  assert.equal(r.json.data.userId, dev.id);
  assert.equal(w.creds[dev.id].role, "developer");
  assert.ok(await bcrypt.compare("My-Own-Pin-77", w.creds[dev.id].pinHash));
  assert.ok(!JSON.stringify(w.state.doc).includes("My-Own-Pin-77"), "plaintext PIN never reaches appData");
  assert.ok(w.identity.some((c) => c.body && String(c.body.customAttributes || "").includes("developer")), "claims set");
  // second attempt, even with the right secret
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "owner2", newPin: "Another-Pin-88" })).status, 409);
  assert.equal(w.state.doc.users.filter((u) => u.role === "developer").length, 1);
  // the new Developer signs in with their own PIN and gets the Developer role; the old default does not exist
  const login = await callPublic(w, "/login", { username: "owner", pin: "My-Own-Pin-77" });
  assert.equal(login.status, 200);
  assert.equal(login.json.user.role, "developer");
  assert.equal((await callPublic(w, "/login", { username: "owner", pin: "1234" })).status, 401);
  // and holds Developer powers immediately
  assert.equal((await getView(w, dev.id, "all")).dataScope.allowed[0], "all");
});

test("BOOTSTRAP: can instead promote an EXISTING account, but only with that account's current PIN as well", async () => {
  const w = bootWorld({ credentials: { root: credFor("111222", "superadmin") } });
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, userId: "root", currentPin: "999999", newPin: "My-Own-Pin-77" })).status, 403);
  assert.equal((await callPublic(w, "/developer/bootstrap", { token: SECRET, userId: "nobody", currentPin: "111222", newPin: "My-Own-Pin-77" })).status, 403);
  const r = await callPublic(w, "/developer/bootstrap", { token: SECRET, userId: "root", currentPin: "111222", newPin: "My-Own-Pin-77" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(userRow(w, "root").role, "developer");
  assert.equal(w.creds.root.role, "developer");
  assert.ok(await bcrypt.compare("My-Own-Pin-77", w.creds.root.pinHash), "the Developer's PIN is the fresh one, not the old PIN");
});

test("BOOTSTRAP: two racing requests produce exactly one Developer", async () => {
  const w = bootWorld();
  let release;
  const hit = new Promise((resolve) => { w.beforePatch = async () => { resolve(); await new Promise((r) => { release = r; }); }; });
  const first = callPublic(w, "/developer/bootstrap", { token: SECRET, username: "owner", newPin: "My-Own-Pin-77" });
  await hit;
  const second = await callPublic(w, "/developer/bootstrap", { token: SECRET, username: "owner-b", newPin: "Another-Pin-88" });
  release();
  const firstRes = await first;
  const statuses = [firstRes.status, second.status].sort();
  assert.ok(statuses.includes(200), "one winner");
  assert.equal(w.state.doc.users.filter((u) => u.role === "developer").length, 1, "never two Developers");
});

test("BOOTSTRAP: rate limited per IP", async () => {
  const w = bootWorld();
  const buckets = new Map();
  w.env.RATE_LIMIT_KV = { async get(k) { return buckets.get(k) ? JSON.parse(buckets.get(k)) : null; }, async put(k, v) { buckets.set(k, v); } };
  let last;
  for (let i = 0; i < 7; i++) last = await callPublic(w, "/developer/bootstrap", { token: "wrong", username: "x", newPin: "Str0ngPin!" });
  assert.equal(last.status, 429);
});
