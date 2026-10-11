// ============================================================================================
// DISABLED ACCOUNTS -- end-to-end through the real Worker (routing, ID-token verification, Firestore optimistic concurrency).
// `disabled` is SERVER-OWNED: only the Developer changes it, through POST /user/disable; no /data/save blob can set or clear it.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { find, call, save, makeDevWorld, devDoc, callPublic, credFor, rec } from "./helpers/devWorld.js";

const TX = [rec("t_low", "low"), rec("t_mid", "mid"), rec("t_other", "other")];
const world = () => makeDevWorld(devDoc({ tx: TX }), {
  credentials: { dev: credFor("DevPin#1234", "developer"), root: credFor("111222", "superadmin"), mid: credFor("222333", "admin"), low: credFor("333444", "user") },
});
const row = (w, id) => w.state.doc.users.find((u) => u.id === id);
const disable = (w, by, target, disabled = true, opts) => call(w, by, "/user/disable", { targetUserId: target, disabled }, opts);

test("DISABLE: the Developer can disable and re-enable an eligible account (admin, user, superadmin); the change is audited", async () => {
  const w = world();
  for (const id of ["low", "mid", "root"]) {
    const r = await disable(w, "dev", id);
    assert.equal(r.status, 200, `${id}: ${JSON.stringify(r.json)}`);
    assert.equal(row(w, id).disabled, true);
  }
  assert.equal((await disable(w, "dev", "low", false)).status, 200);
  assert.notEqual(row(w, "low").disabled, true, "re-enabled");
  const audit = w.state.doc.accessAudit;
  assert.ok(audit.some((a) => a.action === "disable_account" && a.target === "mid" && a.actor === "dev"));
  assert.ok(audit.some((a) => a.action === "enable_account" && a.target === "low"));
  const again = await disable(w, "dev", "mid"); // already disabled: nothing changes
  assert.equal(again.status, 200); assert.equal(again.json.data.changed, false);
});

test("DISABLE: the Developer itself can never be disabled (not by itself, not by anyone)", async () => {
  const w = world();
  const self = await disable(w, "dev", "dev");
  assert.equal(self.status, 403); assert.equal(self.json.error.code, "TARGET_DEVELOPER");
  for (const by of ["root", "mid", "low"]) assert.equal((await disable(w, by, "dev")).status, 403, `${by} cannot disable the Developer`);
  assert.notEqual(row(w, "dev").disabled, true);
  assert.equal((await call(w, "dev", "/data/get", {})).status, 200);
});

test("DISABLE: Superadmin, Admin and ordinary users cannot disable anybody through the endpoint, even with a forged developer claim", async () => {
  const w = world();
  for (const by of ["root", "mid", "low"]) {
    assert.equal((await disable(w, by, "other")).status, 403, `${by}: plain`);
    assert.equal((await disable(w, by, "other", true, { tokenRole: "developer" })).status, 403, `${by}: forged developer claim`);
    assert.equal((await disable(w, by, "sa2", true, { tokenRole: "developer" })).status, 403, `${by}: protected superadmin`);
  }
  assert.ok(w.state.doc.users.every((u) => u.disabled !== true), "nobody was disabled");
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "other" })).status, 400, "malformed body");
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "other", disabled: "yes" })).status, 400);
  assert.equal((await call(w, "dev", "/user/disable", { targetUserId: "nobody", disabled: true })).status, 404);
});

test("DISABLE: no /data/save blob can disable or protect-bypass: client-submitted `disabled` flags are ignored", async () => {
  const w = world();
  for (const by of ["dev", "root", "mid"]) {
    await save(w, by, (v) => { for (const u of v.users) if (u.id === "other" || u.id === "dev" || u.id === "sa2") u.disabled = true; });
  }
  assert.ok(w.state.doc.users.every((u) => u.disabled !== true), "the flag is server-owned: blobs never set it");
});

test("DISABLED ACCOUNT cannot log in (same generic failure as a wrong PIN) and can again once re-enabled", async () => {
  const w = world();
  assert.equal((await callPublic(w, "/login", { username: "mid", pin: "222333" })).status, 200);
  await disable(w, "dev", "mid");
  const bad = await callPublic(w, "/login", { username: "mid", pin: "222333" });
  const wrong = await callPublic(w, "/login", { username: "mid", pin: "000000" });
  assert.equal(bad.status, 401);
  assert.equal(JSON.stringify(bad.json), JSON.stringify(wrong.json), "indistinguishable from a wrong PIN");
  await disable(w, "dev", "mid", false);
  assert.equal((await callPublic(w, "/login", { username: "mid", pin: "222333" })).status, 200);
});

test("DISABLED ACCOUNT is refused by every protected endpoint even with a previously valid ID token (fresh state wins over claims)", async () => {
  const w = world();
  await disable(w, "dev", "mid");
  await disable(w, "dev", "root");
  for (const [uid, claim] of [["mid", "admin"], ["root", "superadmin"], ["mid", "developer"]]) {
    for (const [path, body] of [
      ["/data/get", {}], ["/data/save", { json: "{}" }],
      ["/record/acl", { collection: "transactions", id: "t_low", baseRev: 0, grants: [] }],
      ["/record/assign", { collection: "transactions", id: "t_low", bucket: null, expectedOwner: "low", targetUid: "mid" }],
      ["/user/setPin", { targetUserId: "low", newPin: "99887766" }],
      ["/privacy/export", {}],
    ]) {
      const r = await call(w, uid, path, body, { tokenRole: claim });
      assert.equal(r.status, 403, `${uid}(${claim}) ${path}: ${JSON.stringify(r.json)}`);
    }
  }
  assert.equal(find(w.state.doc.shared.transactions, "t_low").ownerId, "low", "nothing was changed by the disabled accounts");
});

test("DISABLED ACCOUNT: client-submitted role / uid / permissions cannot bypass enforcement", async () => {
  const w = world();
  await disable(w, "dev", "mid");
  // another (enabled) admin submits a blob that tries to re-enable / re-grade mid, or forges the Developer's id
  const r = await save(w, "top", (v) => {
    const m = v.users.find((u) => u.id === "mid"); delete m.disabled; m.disabled = false; m.role = "superadmin";
    v.permissions = { ...(v.permissions || {}), mid: { marathon: "write" } };
  });
  assert.ok([200, 403].includes(r.status));
  assert.equal(row(w, "mid").disabled, true, "still disabled");
  assert.notEqual(row(w, "mid").role, "superadmin");
  const as = await call(w, "mid", "/data/get", { scope: "all" }, { tokenRole: "developer" });
  assert.equal(as.status, 403);
  const forged = await call(w, "mid", "/data/save", { json: JSON.stringify({ users: [{ id: "dev", role: "developer" }, { id: "mid", role: "developer" }] }) }, { tokenRole: "developer" });
  assert.equal(forged.status, 403);
});

test("DISABLED ACCOUNT: a stale save (from before the account was disabled) cannot re-enable it, even from the Developer", async () => {
  const w = world();
  const stale = JSON.parse((await call(w, "dev", "/data/get", { scope: "all" })).json.data.json); // snapshot BEFORE the disable
  await disable(w, "dev", "low");
  for (const by of ["dev", "root", "top"]) {
    const r = await call(w, by, "/data/save", { json: JSON.stringify(stale) });
    assert.ok([200, 403].includes(r.status), `${by}: ${r.status}`);
    assert.equal(row(w, "low").disabled, true, `${by}'s stale save did not re-enable the account`);
  }
  assert.equal((await call(w, "low", "/data/get", {})).status, 403);
  // a stale save also cannot DISABLE someone who was enabled afterwards
  await disable(w, "dev", "low", false);
  const stale2 = JSON.parse((await call(w, "dev", "/data/get", { scope: "all" })).json.data.json);
  await disable(w, "dev", "low");
  await disable(w, "dev", "low", false);
  stale2.users.find((u) => u.id === "low").disabled = true;
  await call(w, "dev", "/data/save", { json: JSON.stringify(stale2) });
  assert.notEqual(row(w, "low").disabled, true);
});

test("DISABLED ACCOUNT: disabled users never appear as assignment targets or ACL grantees", async () => {
  const w = world();
  await disable(w, "dev", "peer");
  const v = JSON.parse((await call(w, "dev", "/data/get", { scope: "all" })).json.data.json);
  const targets = v.dataScope.assignTargets.transactions.map((t) => t.uid || t.id || t);
  assert.ok(targets.includes("low") && !targets.includes("peer"), JSON.stringify(targets));
  const a = await call(w, "dev", "/record/acl", { collection: "transactions", bucket: null, id: "t_mid", baseRev: 0, grants: [{ uid: "peer", perms: ["view"] }] });
  assert.equal(a.status, 400);
  const asg = await call(w, "dev", "/record/assign", { collection: "transactions", id: "t_mid", bucket: null, expectedOwner: "mid", targetUid: "peer" });
  assert.equal(asg.status, 400);
});
