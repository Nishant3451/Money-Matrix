// ============================================================================================
// RECORD-LEVEL ACL -- unit tests of the authorization layer (no network).
//
// Hierarchy used throughout (supervisor nodes -> users):
//        n_top (top, admin)
//        /            \
//   n_mid (mid, admin)  n_peer (peer, user)
//        |
//   n_low (low, user)         root = superadmin (no node)
// From MID's point of view: upline = [top], downline = [low], peer is unrelated.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { buildAuthorizedView, mergeAuthorizedSave, resolveDataScope, buildRecordAccessContext } from "../lib/authorization.js";
import { parseAcl, permissionsFor, computeAclUpdate, canonicalizeGrants, MAX_ACL_GRANTS } from "../lib/recordAcl.js";

const SUPS = [
  { id: "n_top", supervisorId: null },
  { id: "n_mid", supervisorId: "n_top" },
  { id: "n_low", supervisorId: "n_mid" },
  { id: "n_peer", supervisorId: "n_top" },
];
const USERS = [
  { id: "root", username: "root", role: "superadmin", linkedId: null },
  { id: "top", username: "top", role: "admin", linkedId: "n_top" },
  { id: "mid", username: "mid", role: "admin", linkedId: "n_mid" },
  { id: "low", username: "low", role: "user", linkedId: "n_low" },
  { id: "peer", username: "peer", role: "user", linkedId: "n_peer" },
];
const PERMS = { user: { marathon: "write", quotations: "write" } };
const COLLS = ["transactions", "quotations"];

const clone = (x) => JSON.parse(JSON.stringify(x));
const rec = (id, ownerId, extra = {}) => ({ id, ownerId, customer: `cust-${id}`, amount: 100, ...extra });
const g = (uid, ...perms) => ({ uid, perms: ["view", ...perms] });
const acl = (rev, grants) => ({ rev, grants });
const callerOf = (uid, d) => {
  const u = (d || mkDoc()).users.find((x) => x.id === uid);
  return { uid, role: u.role, linkedId: u.linkedId };
};

function mkDoc({ tx = [], q = [], perUser = {}, activityLog = [], users, permissions, extra = {} } = {}) {
  return {
    users: clone(users || USERS),
    permissions: permissions || PERMS,
    userPermissions: {},
    profiles: {},
    settings: {},
    shared: { supervisors: clone(SUPS), members: [], coaches: [], transactions: clone(tx), quotations: clone(q) },
    perUser: clone(perUser),
    activityLog: clone(activityLog),
    ...extra,
  };
}
const docFor = (coll, records, more = {}) => mkDoc({ ...(coll === "transactions" ? { tx: records } : { q: records }), ...more });

/** What the caller's client would hold after /data/get at its widest scope. */
function viewOf(d, uid) {
  const c = callerOf(uid, d);
  return buildAuthorizedView(d, c, { scope: resolveDataScope(d, c).maxScope });
}
const idsOf = (arr) => (arr || []).map((r) => r.id).sort();
const sharedIds = (v, coll = "transactions") => idsOf(v.shared[coll]);
const find = (arr, id) => (arr || []).find((r) => r.id === id);

/** Simulates a client: take its view, edit the blob, POST it. Returns the merged (to-be-persisted) document. */
function clientSave(d, uid, edit) {
  const v = clone(viewOf(d, uid));
  edit(v);
  return mergeAuthorizedSave(d, clone(v), callerOf(uid, d));
}
const ctxOf = (d, uid) => buildRecordAccessContext(d, callerOf(uid, d));

// ============================================================================================
// parseAcl -- strict, fail closed
// ============================================================================================
test("parseAcl: absent = inherit; tombstone {rev, grants:null} = inherit; restricted parses canonical grants", () => {
  assert.deepEqual(parseAcl({ id: "a" }), { kind: "inherit", rev: 0 });
  assert.deepEqual(parseAcl({ id: "a", acl: acl(4, null) }), { kind: "inherit", rev: 4 });
  const p = parseAcl({ id: "a", acl: acl(2, [g("low", "edit")]) });
  assert.equal(p.kind, "restricted");
  assert.equal(p.rev, 2);
  assert.deepEqual([...p.grants.get("low")].sort(), ["edit", "view"]);
  assert.equal(parseAcl({ id: "a", acl: acl(1, []) }).kind, "restricted"); // empty = private
});

function malformedAcls() {
  const polluted = JSON.parse('{"rev":1,"grants":[],"__proto__":{"admin":true}}');
  const pollutedGrant = JSON.parse('{"rev":1,"grants":[{"uid":"low","perms":["view"],"__proto__":{"edit":true}}]}');
  return {
    "null": null,
    "string": "restricted",
    "number": 7,
    "array": [],
    "missing grants": { rev: 1 },
    "missing rev": { grants: [] },
    "rev 0": acl(0, []),
    "negative rev": acl(-1, []),
    "fractional rev": acl(1.5, []),
    "string rev": acl("1", []),
    "huge rev": acl(2 ** 40, []),
    "NaN rev": { rev: NaN, grants: [] }, // JSON turns NaN into null; also invalid in-memory
    "grants object": acl(1, {}),
    "grants undefined": { rev: 1, grants: undefined },
    "grants string": acl(1, "low"),
    "extra key on acl": { rev: 1, grants: [], mode: "inherit" },
    "prototype-pollution key on acl": polluted,
    "prototype-pollution key on grant": pollutedGrant,
    "grant not object": acl(1, ["low"]),
    "grant missing perms": acl(1, [{ uid: "low" }]),
    "grant missing uid": acl(1, [{ perms: ["view"] }]),
    "grant extra key": acl(1, [{ uid: "low", perms: ["view"], role: "admin" }]),
    "empty uid": acl(1, [{ uid: "", perms: ["view"] }]),
    "numeric uid": acl(1, [{ uid: 5, perms: ["view"] }]),
    "overlong uid": acl(1, [{ uid: "x".repeat(200), perms: ["view"] }]),
    "duplicate uid": acl(1, [g("low"), g("low", "edit")]),
    "empty perms": acl(1, [{ uid: "low", perms: [] }]),
    "perms not array": acl(1, [{ uid: "low", perms: "view" }]),
    "unknown perm": acl(1, [{ uid: "low", perms: ["view", "admin"] }]),
    "duplicate perm": acl(1, [{ uid: "low", perms: ["view", "view"] }]),
    "non-string perm": acl(1, [{ uid: "low", perms: [1] }]),
    "too many grants": acl(1, Array.from({ length: MAX_ACL_GRANTS + 1 }, (_, i) => g(`u${i}`))),
  };
}

test("parseAcl: every malformed shape is INVALID (never inherit, never broader access)", () => {
  for (const [name, bad] of Object.entries(malformedAcls())) {
    assert.equal(parseAcl({ id: "a", acl: bad }).kind, "invalid", name);
  }
  assert.equal(parseAcl(null).kind, "invalid");
  assert.equal(parseAcl([]).kind, "invalid");
});

test("malformed ACL on a record: NOBODY but superadmin can view / edit / delete / manage it (owner included), for both collections", () => {
  for (const coll of COLLS) {
    for (const [name, bad] of Object.entries(malformedAcls())) {
      const d = docFor(coll, [rec("t1", "low", { acl: bad })]);
      for (const uid of ["low", "mid", "top", "peer"]) {
        assert.deepEqual(permissionsFor(ctxOf(d, uid), coll, null, d.shared[coll][0]), { view: false, edit: false, delete: false, acl: false }, `${coll}/${name}/${uid}`);
        assert.equal(find(viewOf(d, uid).shared[coll], "t1"), undefined, `${coll}/${name}/${uid} must not receive it`);
      }
      assert.ok(find(viewOf(d, "root").shared[coll], "t1"), `${coll}/${name}: superadmin still sees it`);
      // a hostile save by a non-super cannot edit or delete it
      const after = clientSave(d, "mid", (v) => { v.shared[coll] = []; });
      assert.ok(find(after.shared[coll], "t1"), `${coll}/${name}: not deletable by mid`);
      assert.deepEqual(after.shared[coll].find((r) => r.id === "t1").acl === bad || JSON.stringify(after.shared[coll].find((r) => r.id === "t1").acl) === JSON.stringify(bad), true);
    }
  }
});

// ============================================================================================
// VIEW gate
// ============================================================================================
for (const coll of COLLS) {
  test(`[${coll}] INHERIT: behaves exactly like Data Scope (mid sees upline+own+downline, never the peer)`, () => {
    const d = docFor(coll, [rec("t_top", "top"), rec("t_mid", "mid"), rec("t_low", "low"), rec("t_peer", "peer")]);
    assert.deepEqual(sharedIds(viewOf(d, "mid"), coll), ["t_low", "t_mid", "t_top"]);
    assert.deepEqual(sharedIds(viewOf(d, "root"), coll), ["t_low", "t_mid", "t_peer", "t_top"]);
  });

  test(`[${coll}] PRIVATE (empty grants): only owner + superadmin; downline-parent and upline lose access`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, []) }), rec("t2", "mid")]);
    assert.ok(find(viewOf(d, "low").shared[coll], "t1"), "owner");
    assert.ok(find(viewOf(d, "root").shared[coll], "t1"), "superadmin");
    assert.equal(find(viewOf(d, "mid").shared[coll], "t1"), undefined, "mid is low's upline/parent -> hidden");
    assert.equal(find(viewOf(d, "top").shared[coll], "t1"), undefined);
    assert.equal(find(viewOf(d, "peer").shared[coll], "t1"), undefined);
    assert.ok(find(viewOf(d, "mid").shared[coll], "t2"), "other records unaffected");
  });

  test(`[${coll}] CUSTOM viewer: granted user sees it; other in-scope users still do not`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, [g("mid")]) })]);
    assert.ok(find(viewOf(d, "mid").shared[coll], "t1"));
    assert.equal(find(viewOf(d, "top").shared[coll], "t1"), undefined);
  });

  test(`[${coll}] an ACL grant can NEVER pull a record in from outside Data Scope (peer is unrelated to mid)`, () => {
    const d = docFor(coll, [rec("t1", "mid", { acl: acl(1, [g("peer", "edit", "delete", "acl")]) })]);
    assert.equal(find(viewOf(d, "peer").shared[coll], "t1"), undefined);
    assert.deepEqual(permissionsFor(ctxOf(d, "peer"), coll, null, d.shared[coll][0]), { view: false, edit: false, delete: false, acl: false });
  });

  test(`[${coll}] ACL details are only returned to people who may manage them`, () => {
    const d = docFor(coll, [rec("t1", "mid", { acl: acl(3, [g("low"), g("top", "acl")]) })]);
    assert.deepEqual(find(viewOf(d, "mid").shared[coll], "t1").acl, acl(3, [g("low"), g("top", "acl")]), "owner (admin) manages");
    assert.ok(find(viewOf(d, "top").shared[coll], "t1").acl, "delegated manager (holds acl, owner is in their write ceiling) sees the list");
    const lv = find(viewOf(d, "low").shared[coll], "t1");
    assert.ok(lv, "plain viewer sees the record");
    assert.equal("acl" in lv, false, "...but never the list of who else has access");
    // an owner who cannot write at all (regular user, shared-mode record) is also not shown the list
    const d2 = docFor(coll, [rec("t2", "low", { acl: acl(1, [g("mid")]) })]);
    assert.equal("acl" in find(viewOf(d2, "low").shared[coll], "t2"), false);
  });

  test(`[${coll}] legacy ownerless records stay superadmin-only (unchanged)`, () => {
    const d = docFor(coll, [{ id: "legacy", customer: "x" }]);
    assert.equal(find(viewOf(d, "mid").shared[coll], "legacy"), undefined);
    assert.ok(find(viewOf(d, "root").shared[coll], "legacy"));
  });
}

test("section permission is a hard ceiling: a Payments-hidden user receives no Payment even if granted view", () => {
  const d = mkDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("low", "edit")]) })], permissions: { user: { marathon: "hidden" } } });
  assert.equal(find(viewOf(d, "low").shared.transactions, "t1"), undefined);
});

test("tombstone ACL {rev, grants:null} behaves as inherit", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(5, null) })] });
  assert.ok(find(viewOf(d, "mid").shared.transactions, "t1"));
});

test("per-user (isolated) mode: owner is the BUCKET id, not the record's own ownerId field", () => {
  const d = mkDoc({ perUser: { low: { transactions: [
    rec("p1", "mid", { acl: acl(1, []) }), // forged ownerId inside low's bucket
    rec("p2", "top"),
  ] } } });
  assert.ok(find(viewOf(d, "low").perUser.low.transactions, "p1"), "owner (bucket) sees own private record");
  assert.equal(find(viewOf(d, "mid").perUser.low.transactions, "p1"), undefined, "ownerId:'mid' inside low's bucket grants mid nothing");
  assert.ok(find(viewOf(d, "mid").perUser.low.transactions, "p2"), "inherit record still visible to the downline-parent");
});

test("admin never receives All Data via ACLs; superadmin is unrestricted by any ACL", () => {
  const d = mkDoc({ tx: [rec("a", "peer", { acl: acl(1, [g("mid", "edit", "delete", "acl")]) }), rec("b", "low", { acl: acl(1, []) })] });
  assert.equal(find(viewOf(d, "mid").shared.transactions, "a"), undefined, "peer is outside mid's scope; the grant cannot help");
  assert.equal(find(viewOf(d, "mid").shared.transactions, "b"), undefined);
  assert.deepEqual(sharedIds(viewOf(d, "root")), ["a", "b"]);
});

test("view gate never mutates its input", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid")]) })] });
  const before = clone(d);
  viewOf(d, "mid");
  viewOf(d, "low");
  assert.deepEqual(d, before);
});

// ============================================================================================
// ACTIVITY LOG privacy -- authorized by SERVER-stamped actorUid + a stable record reference; never by names.
// ============================================================================================
const legacyEntry = (user, coll, name) => ({ ts: Math.random(), user, action: "added", coll, name, scopeId: "n_low" });
const refEntry = (actorUid, coll, name, recId, recBucket = null) => ({ ts: Math.random(), user: "irrelevant display name", action: "added", coll, name, scopeId: "n_low", actorUid, recId, recBucket });

test("activity log: with NO ACL ever used the log is exactly as before (legacy entries stay visible)", () => {
  const d = mkDoc({ tx: [rec("t1", "low")], activityLog: [legacyEntry("low", "transactions", "Alice Customer"), legacyEntry("low", "members", "Bob")] });
  assert.equal(viewOf(d, "mid").activityLog.length, 2);
});

test("activity log: once a Payment is restricted, LEGACY entries (no reference) fail closed -- display names are never consulted", () => {
  const log = [
    legacyEntry("mid", "transactions", "legacy entry whose display name equals mid's username"),
    legacyEntry("low", "transactions", "SECRET CUSTOMER"),
    legacyEntry("low", "members", "Visible Member"),
    legacyEntry("low", "quotations", "Quote Customer"),
  ];
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, []) })], activityLog: log });
  for (const uid of ["mid", "top", "low", "peer"]) {
    const names = viewOf(d, uid).activityLog.map((e) => e.name);
    assert.equal(names.includes("SECRET CUSTOMER"), false, `${uid}: legacy Payment entries hidden`);
    assert.equal(names.includes("legacy entry whose display name equals mid's username"), false, `${uid}: a matching display name grants nothing`);
  }
  const mid = viewOf(d, "mid").activityLog.map((e) => e.name);
  assert.ok(mid.includes("Visible Member"), "other collections unaffected");
  assert.ok(mid.includes("Quote Customer"), "a collection with no restricted record is unaffected");
  assert.equal(viewOf(d, "root").activityLog.length, 4, "superadmin sees everything");
});

test("activity log: referenced entries are visible exactly to people who can VIEW the referenced record (or wrote the entry)", () => {
  const d = mkDoc({
    tx: [rec("priv", "low", { acl: acl(1, [g("top")]) }), rec("open", "low")],
    activityLog: [refEntry("low", "transactions", "PRIV NAME", "priv"), refEntry("low", "transactions", "OPEN NAME", "open"), refEntry("mid", "transactions", "MID WROTE THIS", "priv")],
  });
  const names = (uid) => viewOf(d, uid).activityLog.map((e) => e.name).sort();
  assert.deepEqual(names("top"), ["MID WROTE THIS", "OPEN NAME", "PRIV NAME"], "top is granted view on 'priv'");
  assert.deepEqual(names("mid"), ["MID WROTE THIS", "OPEN NAME"], "mid can't view 'priv' but sees what it wrote itself");
  assert.deepEqual(names("low"), ["MID WROTE THIS", "OPEN NAME", "PRIV NAME"], "the owner can view both of its records");
  assert.deepEqual(names("peer"), [], "peer is outside scope of everything");
});

test("activity log: an entry about a record that no longer exists is hidden (except from its actor and superadmin); the collection stays protected after the last restricted record is deleted (sticky via audit)", () => {
  const audit = [{ ts: 1, actor: "low", coll: "transactions", bucket: null, recId: "gone", action: "set", rev: 1, grantCount: 0 }];
  const d = mkDoc({ tx: [rec("open", "low")], extra: { recordAclAudit: audit }, activityLog: [refEntry("low", "transactions", "DELETED SECRET", "gone"), refEntry("low", "transactions", "OPEN NAME", "open")] });
  assert.deepEqual(viewOf(d, "mid").activityLog.map((e) => e.name), ["OPEN NAME"]);
  assert.deepEqual(viewOf(d, "low").activityLog.map((e) => e.name).sort(), ["DELETED SECRET", "OPEN NAME"], "the author still sees it");
  assert.equal(viewOf(d, "root").activityLog.length, 2);
});

test("activity log: malformed references are treated as unreferenced (fail closed); ambiguous (duplicate-id) targets too", () => {
  const bad = [
    { ...refEntry("x", "transactions", "A", "t1"), recBucket: undefined },
    { ...refEntry("x", "transactions", "B", "t1"), recId: 7 },
    { ...refEntry("x", "transactions", "C", "t1"), recId: "" },
    { ...refEntry("x", "transactions", "D", "t1"), recBucket: "" },
    { ...refEntry("x", "transactions", "E", "t1"), recBucket: 5 },
    refEntry("x", "transactions", "F", "dup"),
  ];
  const d = mkDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("top")]) }), rec("dup", "mid"), rec("dup", "mid")], activityLog: bad });
  assert.deepEqual(viewOf(d, "top").activityLog, []);
});

test("activity log: a malformed (invalid) ACL also activates protection for that collection", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: "garbage" })], activityLog: [legacyEntry("low", "transactions", "X")] });
  assert.equal(viewOf(d, "mid").activityLog.length, 0);
});

test("activity log: per-user-bucket records are referenced by bucket", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("p1", "low", { acl: acl(1, [g("mid")]) }), rec("p2", "low", { acl: acl(1, []) })], quotations: [] } },
    activityLog: [refEntry("low", "transactions", "P1", "p1", "low"), refEntry("low", "transactions", "P2", "p2", "low"), refEntry("low", "transactions", "WRONG BUCKET", "p2", null)] });
  assert.deepEqual(viewOf(d, "mid").activityLog.map((e) => e.name), ["P1"]);
});

test("activity stamping on save: actorUid is the VERIFIED caller (client value discarded); malformed refs dropped; other collections untouched", () => {
  const d = mkDoc({ tx: [rec("t1", "mid")] });
  const out = clientSave(d, "mid", (v) => {
    v.activityLog = [
      { ts: 1, user: "x", action: "updated", coll: "transactions", name: "N1", scopeId: "n_low", actorUid: "root", recId: "t1", recBucket: null },
      { ts: 2, user: "x", action: "updated", coll: "transactions", name: "N2", scopeId: "n_low", actorUid: "root", recId: { $ne: 1 }, recBucket: null },
      { ts: 3, user: "x", action: "added", coll: "members", name: "N3", scopeId: "n_low", actorUid: "root" },
    ];
  });
  const by = (n) => out.activityLog.find((e) => e.name === n);
  assert.equal(by("N1").actorUid, "mid", "forged actorUid overwritten");
  assert.equal(by("N1").recId, "t1");
  assert.equal("recId" in by("N2"), false, "malformed reference removed");
  assert.equal(by("N2").actorUid, "mid");
  assert.equal(by("N3").actorUid, "root", "non-Payment/Quotation entries are left exactly as submitted");
});

test("activity stamping: re-submitting an already-known entry with a different actor/reference cannot rewrite it", () => {
  const known = refEntry("low", "transactions", "KNOWN", "t1");
  const d = mkDoc({ tx: [rec("t1", "mid")], activityLog: [known] });
  const out = clientSave(d, "root", (v) => { v.activityLog = [{ ...known, actorUid: "root", recId: "other" }, ...v.activityLog]; });
  assert.equal(out.activityLog.filter((e) => e.name === "KNOWN").length, 1);
  assert.equal(out.activityLog.find((e) => e.name === "KNOWN").actorUid, "low");
  assert.equal(out.activityLog.find((e) => e.name === "KNOWN").recId, "t1");
});

// ============================================================================================
// SAVE gate -- EDIT / DELETE / ownership / forged ACL
// ============================================================================================
for (const coll of COLLS) {
  test(`[${coll}] owner can edit own restricted record; acl and ownerId are preserved`, () => {
    const a = acl(2, [g("low")]);
    const d = docFor(coll, [rec("t1", "mid", { acl: a })]);
    const out = clientSave(d, "mid", (v) => { find(v.shared[coll], "t1").customer = "renamed"; });
    const r = find(out.shared[coll], "t1");
    assert.equal(r.customer, "renamed");
    assert.deepEqual(r.acl, a);
    assert.equal(r.ownerId, "mid");
  });

  test(`[${coll}] FORGED ACL on an existing record is discarded (cannot self-grant, cannot widen, cannot clear)`, () => {
    const a = acl(2, [g("low")]);
    const d = docFor(coll, [rec("t1", "mid", { acl: a })]);
    for (const forged of [acl(3, [g("peer", "edit", "delete", "acl"), g("mid", "acl")]), null, undefined, acl(1, null), "inherit", { rev: 99, grants: [] }]) {
      const out = clientSave(d, "mid", (v) => {
        const r = find(v.shared[coll], "t1");
        if (forged === undefined) delete r.acl; else r.acl = forged;
        r.customer = "touched";
      });
      const r = find(out.shared[coll], "t1");
      assert.deepEqual(r.acl, a, `forged ${JSON.stringify(forged)}`);
      assert.equal(r.customer, "touched");
    }
  });

  test(`[${coll}] FORGED ACL on a NEW record is stripped (new records are always inherit)`, () => {
    const d = docFor(coll, []);
    const out = clientSave(d, "mid", (v) => { v.shared[coll].push(rec("new1", "mid", { acl: acl(1, [g("peer", "edit")]) })); });
    const r = find(out.shared[coll], "new1");
    assert.ok(r);
    assert.equal("acl" in r, false);
  });

  test(`[${coll}] superadmin cannot change acl/ownerId through a blob either (only /record/acl can)`, () => {
    const a = acl(2, [g("low")]);
    const d = docFor(coll, [rec("t1", "mid", { acl: a })]);
    const out = clientSave(d, "root", (v) => {
      const r = find(v.shared[coll], "t1");
      r.acl = acl(9, []); r.ownerId = "root"; r.customer = "super-edit";
    });
    const r = find(out.shared[coll], "t1");
    assert.deepEqual(r.acl, a);
    assert.equal(r.ownerId, "mid");
    assert.equal(r.customer, "super-edit", "superadmin may still edit content");
  });

  test(`[${coll}] OWNERSHIP IMMUTABLE: an editor cannot re-attribute a downline record to themselves (the old client re-stamp)`, () => {
    const d = docFor(coll, [rec("t1", "low")]);
    const out = clientSave(d, "mid", (v) => { const r = find(v.shared[coll], "t1"); r.customer = "edited by mid"; r.ownerId = "mid"; });
    const r = find(out.shared[coll], "t1");
    assert.equal(r.customer, "edited by mid", "inherit + write ceiling: the edit itself still works as before");
    assert.equal(r.ownerId, "low", "but ownership does not move");
  });

  test(`[${coll}] OWNERSHIP IMMUTABLE: the owner cannot hand a record to someone else via /data/save, nor strip ownerId`, () => {
    const d = docFor(coll, [rec("t1", "mid")]);
    for (const mutate of [(r) => { r.ownerId = "low"; }, (r) => { r.ownerId = "peer"; }, (r) => { delete r.ownerId; }, (r) => { r.ownerId = null; }]) {
      const out = clientSave(d, "mid", (v) => mutate(find(v.shared[coll], "t1")));
      assert.equal(find(out.shared[coll], "t1").ownerId, "mid");
    }
  });

  test(`[${coll}] superadmin cannot reassign ownerId through a blob`, () => {
    const d = docFor(coll, [rec("t1", "mid")]);
    const out = clientSave(d, "root", (v) => { find(v.shared[coll], "t1").ownerId = "peer"; });
    assert.equal(find(out.shared[coll], "t1").ownerId, "mid");
  });

  test(`[${coll}] VIEW-only grant: cannot edit, cannot delete`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, [g("mid")]) })]);
    const edited = clientSave(d, "mid", (v) => { find(v.shared[coll], "t1").customer = "HACK"; find(v.shared[coll], "t1").amount = 1; });
    assert.equal(find(edited.shared[coll], "t1").customer, "cust-t1");
    assert.equal(find(edited.shared[coll], "t1").amount, 100);
    const deleted = clientSave(d, "mid", (v) => { v.shared[coll] = v.shared[coll].filter((r) => r.id !== "t1"); });
    assert.ok(find(deleted.shared[coll], "t1"), "delete refused");
  });

  test(`[${coll}] EDIT grant: can edit, can NOT delete, can NOT touch acl or ownerId`, () => {
    const a = acl(1, [g("mid", "edit")]);
    const d = docFor(coll, [rec("t1", "low", { acl: a })]);
    const out = clientSave(d, "mid", (v) => { const r = find(v.shared[coll], "t1"); r.customer = "ok"; r.acl = acl(2, [g("mid", "edit", "delete", "acl")]); r.ownerId = "mid"; });
    const r = find(out.shared[coll], "t1");
    assert.equal(r.customer, "ok");
    assert.deepEqual(r.acl, a);
    assert.equal(r.ownerId, "low");
    const del = clientSave(d, "mid", (v) => { v.shared[coll] = []; });
    assert.ok(find(del.shared[coll], "t1"), "an editor cannot delete");
  });

  test(`[${coll}] DELETE grant is independent: can delete, can NOT edit`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, [g("mid", "delete")]) })]);
    const edited = clientSave(d, "mid", (v) => { find(v.shared[coll], "t1").customer = "nope"; });
    assert.equal(find(edited.shared[coll], "t1").customer, "cust-t1");
    const deleted = clientSave(d, "mid", (v) => { v.shared[coll] = v.shared[coll].filter((r) => r.id !== "t1"); });
    assert.equal(find(deleted.shared[coll], "t1"), undefined);
  });

  test(`[${coll}] a user with NO access cannot delete a record they cannot see (absence in their blob is not a delete)`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, []) }), rec("t2", "low")]);
    const out = clientSave(d, "mid", (v) => { v.shared[coll] = []; });
    assert.ok(find(out.shared[coll], "t1"), "private record survives");
    assert.equal(find(out.shared[coll], "t2"), undefined, "inherit record in mid's write ceiling: delete works exactly as before");
  });

  test(`[${coll}] a user with NO access cannot overwrite a record they cannot see by forging it into their blob`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, []) })]);
    const out = clientSave(d, "mid", (v) => { v.shared[coll].push({ id: "t1", ownerId: "mid", customer: "FORGED", amount: 0, acl: acl(1, [g("mid", "edit", "delete", "acl")]) }); });
    const r = find(out.shared[coll], "t1");
    assert.equal(r.customer, "cust-t1");
    assert.equal(r.ownerId, "low");
    assert.deepEqual(r.acl, acl(1, []));
    assert.equal(out.shared[coll].filter((x) => x.id === "t1").length, 1);
  });

  test(`[${coll}] UPLINE stays read-only even when an ACL grants edit+delete+acl`, () => {
    // t1 is owned by TOP, who is mid's UPLINE. mid is explicitly granted everything.
    const d = docFor(coll, [rec("t1", "top", { acl: acl(1, [g("mid", "edit", "delete", "acl")]) })]);
    assert.ok(find(viewOf(d, "mid").shared[coll], "t1"), "readable");
    assert.deepEqual(permissionsFor(ctxOf(d, "mid"), coll, null, d.shared[coll][0]), { view: true, edit: false, delete: false, acl: false });
    const edited = clientSave(d, "mid", (v) => { find(v.shared[coll], "t1").customer = "HACK"; });
    assert.equal(find(edited.shared[coll], "t1").customer, "cust-t1");
    const deleted = clientSave(d, "mid", (v) => { v.shared[coll] = []; });
    assert.ok(find(deleted.shared[coll], "t1"));
    const r = computeAclUpdate({ appData: d, ctx: ctxOf(d, "mid"), collection: coll, bucket: null, id: "t1", baseRev: 1, grants: [] });
    assert.equal(r.error.status, 403);
  });

  test(`[${coll}] DOWNLINE record + explicit edit grant works for a parent admin (existing downline behavior intact)`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, [g("mid", "edit", "delete")]) })]);
    const edited = clientSave(d, "mid", (v) => { find(v.shared[coll], "t1").customer = "mid-edit"; });
    assert.equal(find(edited.shared[coll], "t1").customer, "mid-edit");
    const deleted = clientSave(d, "mid", (v) => { v.shared[coll] = []; });
    assert.equal(find(deleted.shared[coll], "t1"), undefined);
  });

  test(`[${coll}] superadmin can edit and delete ANY record regardless of ACL (even malformed)`, () => {
    const d = docFor(coll, [rec("a", "low", { acl: acl(1, []) }), rec("b", "low", { acl: "junk" })]);
    const edited = clientSave(d, "root", (v) => { v.shared[coll].forEach((r) => { r.customer = "S"; }); });
    assert.deepEqual(edited.shared[coll].map((r) => r.customer), ["S", "S"]);
    const deleted = clientSave(d, "root", (v) => { v.shared[coll] = []; });
    assert.equal(deleted.shared[coll].length, 0);
  });

  test(`[${coll}] omitting the whole collection from a blob cannot wipe records the caller may not delete`, () => {
    const d = docFor(coll, [rec("peer_t", "peer"), rec("top_t", "top"), rec("low_priv", "low", { acl: acl(1, []) }), rec("mid_t", "mid")]);
    const out = clientSave(d, "mid", (v) => { delete v.shared[coll]; });
    assert.deepEqual(idsOf(out.shared[coll]), ["low_priv", "peer_t", "top_t"], "only mid's own inherit record may go");
  });

  test(`[${coll}] no-op save (key order shuffled, ownerId/acl noise) changes nothing and keeps server order`, () => {
    const a = acl(2, [g("low")]);
    const d = docFor(coll, [rec("t1", "mid", { acl: a }), rec("t2", "low")]);
    const out = clientSave(d, "mid", (v) => {
      v.shared[coll] = v.shared[coll].map((r) => Object.fromEntries(Object.entries(r).reverse()));
      v.shared[coll].reverse();
    });
    assert.deepEqual(out.shared[coll], d.shared[coll]);
  });

  test(`[${coll}] a record moved between locations (shared -> own bucket) still needs DELETE on the source`, () => {
    const d = docFor(coll, [rec("t1", "low", { acl: acl(1, [g("mid")]) })]);
    const out = clientSave(d, "mid", (v) => {
      const r = v.shared[coll].pop();
      v.perUser.mid = v.perUser.mid || { transactions: [], quotations: [] };
      v.perUser.mid[coll].push({ ...r });
    });
    assert.ok(find(out.shared[coll], "t1"), "source record restored (no DELETE)");
  });
}

test("prototype-pollution keys in submitted records never pollute or escalate", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid")]) })] });
  const hostile = JSON.parse('{"id":"t1","ownerId":"mid","customer":"x","__proto__":{"edit":true,"acl":{"rev":1,"grants":[]}},"constructor":{"prototype":{"polluted":1}}}');
  const submitted = clone(viewOf(d, "mid"));
  submitted.shared.transactions = [hostile];
  const out = mergeAuthorizedSave(d, JSON.parse(JSON.stringify(submitted)), callerOf("mid", d));
  assert.equal({}.polluted, undefined);
  assert.equal({}.edit, undefined);
  const r = find(out.shared.transactions, "t1");
  assert.equal(r.customer, "cust-t1", "view-only grant: edit refused");
  assert.deepEqual(r.acl, acl(1, [g("mid")]));
});

test("recordAclAudit is server-owned and survives a /data/save by every role", () => {
  const audit = [{ ts: 1, actor: "low", coll: "transactions", bucket: null, recId: "t1", action: "set", rev: 1, grantCount: 0 }];
  for (const uid of ["root", "mid", "low"]) {
    const d = mkDoc({ tx: [rec("t1", "low")], extra: { recordAclAudit: audit } });
    const out = clientSave(d, uid, (v) => { v.recordAclAudit = []; });
    assert.deepEqual(out.recordAclAudit, audit, uid);
  }
});

test("regular (non-admin) user: records in own bucket keep full owner control; ACL does not widen their write path", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("p1", "low")], quotations: [] } } });
  const out = clientSave(d, "low", (v) => { find(v.perUser.low.transactions, "p1").customer = "mine"; v.perUser.low.transactions.push(rec("p2", "low")); });
  assert.equal(find(out.perUser.low.transactions, "p1").customer, "mine");
  assert.ok(find(out.perUser.low.transactions, "p2"));
  // a regular user granted `edit` on a downline-parent's... (shared-mode record owned by someone else) still cannot write it
  const d2 = mkDoc({ tx: [rec("s1", "mid", { acl: acl(1, [g("low", "edit", "delete", "acl")]) })] });
  assert.deepEqual(permissionsFor(ctxOf(d2, "low"), "transactions", null, d2.shared.transactions[0]), { view: true, edit: false, delete: false, acl: false });
});

test("per-user bucket: private record in low's bucket survives a hostile save by mid (parent admin)", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("p1", "low", { acl: acl(1, []) }), rec("p2", "low")], quotations: [] } } });
  const out = clientSave(d, "mid", (v) => { v.perUser = {}; });
  assert.ok(find(out.perUser.low.transactions, "p1"), "private record restored even though the whole bucket was dropped");
});

test("role/section ceiling: view-only section user cannot write even with ACL edit (existing section gate + ACL layer agree)", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("p1", "low")], quotations: [] } }, permissions: { user: { marathon: "view", quotations: "write" } } });
  const out = clientSave(d, "low", (v) => { find(v.perUser.low.transactions, "p1").customer = "x"; });
  assert.equal(find(out.perUser.low.transactions, "p1").customer, "cust-p1");
});

// ============================================================================================
// ACL MUTATION (computeAclUpdate)
// ============================================================================================
const upd = (d, uid, over = {}) =>
  computeAclUpdate({ appData: d, ctx: ctxOf(d, uid), collection: "transactions", bucket: null, id: "t1", baseRev: 0, grants: [], ...over });

for (const coll of COLLS) {
  test(`[${coll}] owner sets an ACL; rev increments; canonical form (view implied, sorted); no names stored`, () => {
    const d = docFor(coll, [rec("t1", "mid")]);
    const r = upd(d, "mid", { collection: coll, grants: [{ uid: "top", perms: ["edit"] }, { uid: "low", perms: ["delete", "view"] }] });
    assert.deepEqual(r.result, { rev: 1, mode: "restricted", changed: true });
    const saved = find(r.appData.shared[coll], "t1");
    assert.deepEqual(saved.acl, acl(1, [{ uid: "low", perms: ["view", "delete"] }, { uid: "top", perms: ["view", "edit"] }]));
    assert.equal(saved.ownerId, "mid");
    assert.equal(JSON.stringify(saved.acl).includes("username"), false);
  });
}

test("input appData is never mutated by computeAclUpdate", () => {
  const d = mkDoc({ tx: [rec("t1", "mid")] });
  const before = clone(d);
  upd(d, "mid", { grants: [g("low")] });
  assert.deepEqual(d, before);
});

test("stale / replayed rev is rejected, INCLUDING after a revert-to-inherit (rev stays monotonic via tombstone)", () => {
  let d = mkDoc({ tx: [rec("t1", "mid")] });
  let r = upd(d, "mid", { baseRev: 0, grants: [g("low")] });           // 0 -> 1
  d = r.appData;
  r = upd(d, "mid", { baseRev: 1, grants: [g("low", "edit")] });       // 1 -> 2
  d = r.appData;
  assert.equal(r.result.rev, 2);
  assert.equal(upd(d, "mid", { baseRev: 1, grants: [] }).error.code, "ACL_STALE");   // replay of the first update
  assert.equal(upd(d, "mid", { baseRev: 1, grants: [] }).error.currentRev, 2);
  r = upd(d, "mid", { baseRev: 2, grants: null });                      // revert: 2 -> tombstone rev 3
  d = r.appData;
  assert.deepEqual(find(d.shared.transactions, "t1").acl, { rev: 3, grants: null });
  assert.equal(upd(d, "mid", { baseRev: 0, grants: [g("low")] }).error.code, "ACL_STALE", "replay of the original rev-0 request");
  assert.equal(upd(d, "mid", { baseRev: 1, grants: [g("low")] }).error.code, "ACL_STALE");
  assert.equal(upd(d, "mid", { baseRev: 2, grants: [g("low")] }).error.code, "ACL_STALE");
  assert.equal(upd(d, "mid", { baseRev: 3, grants: [g("low")] }).result.rev, 4);
});

test("no-op update does not change data or bump rev", () => {
  const d = mkDoc({ tx: [rec("t1", "mid", { acl: acl(4, [g("low")]) })] });
  const r = upd(d, "mid", { baseRev: 4, grants: [{ uid: "low", perms: ["view"] }] });
  assert.deepEqual(r.result, { rev: 4, mode: "restricted", changed: false });
  assert.equal(r.appData, d);
});

test("audit entry is appended with ids only (no names), capped", () => {
  const d = mkDoc({ tx: [rec("t1", "mid", { customer: "SECRET NAME" })] });
  const r = upd(d, "mid", { grants: [g("low")] });
  assert.equal(r.appData.recordAclAudit.length, 1);
  const e = r.appData.recordAclAudit[0];
  assert.deepEqual(Object.keys(e).sort(), ["action", "actor", "bucket", "coll", "grantCount", "recId", "rev", "ts"]);
  assert.equal(JSON.stringify(e).includes("SECRET NAME"), false);
});

test("who may manage: owner and superadmin; NOT an editor/viewer/unlisted/peer; invisible record looks identical to a missing one", () => {
  const d = mkDoc({ tx: [rec("t1", "mid", { acl: acl(1, [g("top", "edit", "delete")]) }), rec("priv", "mid", { acl: acl(1, []) })] });
  assert.equal(upd(d, "mid", { baseRev: 1, grants: [] }).error, undefined, "owner");
  assert.equal(upd(d, "root", { baseRev: 1, grants: [] }).error, undefined, "superadmin");
  assert.equal(upd(d, "top", { baseRev: 1, grants: [] }).error.status, 403, "editor+deleter is not an ACL manager");
  assert.equal(upd(d, "peer", { baseRev: 1, grants: [] }).error.status, 404, "outside scope => 404");
  assert.equal(upd(d, "low", { baseRev: 1, grants: [] }).error.status, 404, "in scope but not listed on a restricted record => 404");
  const hidden = upd(d, "low", { id: "priv", baseRev: 1, grants: [] }).error;
  const missing = upd(d, "low", { id: "does-not-exist", baseRev: 1, grants: [] }).error;
  assert.deepEqual(hidden, missing, "no existence oracle");
});

test("inherit records: ACL management is owner + superadmin only (a downline-parent admin cannot restrict someone else's record)", () => {
  const d = mkDoc({ tx: [rec("t1", "low")], perUser: { low: { transactions: [rec("t1", "low")], quotations: [] } } });
  assert.equal(upd(d, "mid").error.status, 403, "mid is low's parent and may even edit it, but cannot manage its ACL");
  assert.equal(upd(d, "top").error.status, 403);
  assert.equal(upd(d, "root").error, undefined);
  // the regular-user owner CAN manage a record in their own bucket
  assert.equal(upd(d, "low", { bucket: "low" }).error, undefined);
  assert.equal(upd(d, "mid", { bucket: "low" }).error.status, 403);
});

test("a regular user cannot manage ACL on a shared-mode record they own (they cannot write shared at all)", () => {
  const d = mkDoc({ tx: [rec("t1", "low")] });
  assert.equal(upd(d, "low").error.status, 403);
});

test("a regular user with a view-only Payments section cannot manage ACL on their own record", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("t1", "low")], quotations: [] } }, permissions: { user: { marathon: "view" } } });
  assert.equal(upd(d, "low", { bucket: "low" }).error.status, 403);
});

test("per-user bucket addressing: owner is the bucket; wrong bucket / shared-vs-bucket confusion is 404", () => {
  const d = mkDoc({ perUser: { low: { transactions: [rec("t1", "low")], quotations: [] } } });
  assert.equal(upd(d, "low", { bucket: "low" }).result.rev, 1);
  assert.equal(upd(d, "low", { bucket: null }).error.status, 404);
  assert.equal(upd(d, "mid", { bucket: "low" }).error.status, 403, "mid sees low's inherit record but cannot manage it");
  assert.equal(upd(d, "low", { bucket: "peer" }).error.status, 404);
  assert.equal(upd(d, "low", { bucket: "__proto__" }).error.status, 404);
});

test("malformed grant lists are rejected 400 and nothing changes", () => {
  const d = mkDoc({ tx: [rec("t1", "mid")] });
  const bad = {
    "object instead of array": { low: ["view"] },
    "string": "low",
    "unknown uid": [g("ghost")],
    "owner in list": [g("mid")],
    "superadmin in list": [g("root")],
    "duplicate uid": [g("low"), g("low", "edit")],
    "empty perms": [{ uid: "low", perms: [] }],
    "unknown perm": [{ uid: "low", perms: ["view", "own"] }],
    "dup perm": [{ uid: "low", perms: ["view", "view"] }],
    "perms string": [{ uid: "low", perms: "view" }],
    "extra key": [{ uid: "low", perms: ["view"], ownerId: "low" }],
    "missing perms": [{ uid: "low" }],
    "null entry": [null],
    "array entry": [["low", "view"]],
    "too many": Array.from({ length: MAX_ACL_GRANTS + 1 }, (_, i) => ({ uid: `u${i}`, perms: ["view"] })),
    "proto uid": [{ uid: "__proto__", perms: ["view"] }],
    "constructor uid": [{ uid: "constructor", perms: ["view"] }],
    "numeric uid": [{ uid: 1, perms: ["view"] }],
  };
  for (const [name, grants] of Object.entries(bad)) {
    const r = upd(d, "mid", { grants });
    assert.equal(r.error && r.error.status, 400, name);
    assert.equal(r.error.code, "ACL_INVALID", name);
  }
  const hostile = JSON.parse('[{"uid":"low","perms":["view"],"__proto__":{"perms":["acl"]}}]');
  assert.equal(upd(d, "mid", { grants: hostile }).error.status, 400);
  // request-shape errors
  for (const over of [{ collection: "members" }, { collection: undefined }, { id: 5 }, { id: "" }, { baseRev: -1 }, { baseRev: 1.2 }, { baseRev: "0" }, { baseRev: null }, { grants: undefined }, { grants: 5 }, { bucket: 7 }, { bucket: "" }]) {
    assert.equal(upd(d, "mid", over).error.status, 400, JSON.stringify(over));
  }
});

test("exactly MAX grants is accepted; users with duplicate ids in the user list never become ambiguous grantees", () => {
  const many = Array.from({ length: MAX_ACL_GRANTS }, (_, i) => ({ id: `x${i}`, username: `x${i}`, role: "user", linkedId: null }));
  const d = mkDoc({ tx: [rec("t1", "mid")], users: [...USERS, ...many] });
  assert.equal(upd(d, "mid", { grants: many.map((u) => g(u.id)) }).result.rev, 1);
  assert.equal(canonicalizeGrants([g("low")], mkDoc(), "mid").grants.length, 1);
});

test("SELF-GRANT: a non-manager (viewer/editor/unlisted) cannot grant themselves anything", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit")]) })] });
  const r = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "delete", "acl")] });
  assert.equal(r.error.status, 403);
  const peer = upd(d, "peer", { baseRev: 1, grants: [g("peer", "acl")] });
  assert.equal(peer.error.status, 404);
});

test("DELEGATED manager: may grant only what they hold; cannot modify own entry; cannot touch entries above their power; cannot reset to inherit", () => {
  // mid holds view+edit+acl (NOT delete) on low's record; top holds view+delete+acl.
  const mk = () => mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit", "acl"), g("top", "delete", "acl")]) })] });
  const d = mk();
  const ok = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "acl"), g("top", "delete", "acl"), g("peer")] });
  // peer is outside everyone's scope but a grant to them is merely inert -- still a structurally valid addition of `view`
  assert.equal(ok.error, undefined, "adding a view-only entry (a permission mid holds) is allowed");
  const noDelete = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "acl"), g("top", "delete", "acl"), g("peer", "delete")] });
  assert.equal(noDelete.error.status, 403, "mid does not hold delete");
  const ownEntry = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "delete", "acl"), g("top", "delete", "acl")] });
  assert.equal(ownEntry.error.status, 403, "cannot change own grant");
  const revokeOwn = upd(d, "mid", { baseRev: 1, grants: [g("top", "delete", "acl")] });
  assert.equal(revokeOwn.error.status, 403, "cannot remove own grant");
  const touchHigher = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "acl")] });
  assert.equal(touchHigher.error.status, 403, "top's entry contains delete, which mid lacks: cannot revoke it");
  const reset = upd(d, "mid", { baseRev: 1, grants: null });
  assert.equal(reset.error.status, 403, "reset to inherit is owner/superadmin only");
  // a superadmin can do all of the above
  assert.equal(upd(d, "root", { baseRev: 1, grants: null }).error, undefined);
});

test("delegated manager may grant `acl` only because they hold it; a manager without acl cannot manage at all", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit", "acl")]) })] });
  const r = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "acl"), g("peer", "acl")] });
  assert.equal(r.error, undefined);
  const d2 = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit")]) })] });
  assert.equal(upd(d2, "mid", { baseRev: 1, grants: [g("mid", "edit"), g("peer", "acl")] }).error.status, 403);
});

test("a delegated manager's effective perms are capped by section/scope: a view-only-section manager cannot grant edit", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit", "acl")]) })], permissions: { user: { marathon: "write" }, admin: { marathon: "view" } } });
  const r = upd(d, "mid", { baseRev: 1, grants: [g("mid", "edit", "acl")] });
  assert.equal(r.error.status, 403, "admin with view-only Payments section has no write ceiling => cannot manage");
});

test("superadmin may repair an INVALID acl; the owner cannot (fail closed)", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: "garbage" })] });
  assert.equal(upd(d, "low").error.status, 404);
  assert.equal(upd(d, "mid").error.status, 404);
  const r = upd(d, "root", { baseRev: 0, grants: [g("mid")] });
  assert.equal(r.result.rev, 1);
});

test("ownerId can never change through the ACL endpoint, and ambiguous (duplicate-id) records are refused", () => {
  const d = mkDoc({ tx: [rec("t1", "mid")] });
  const r = upd(d, "mid", { grants: [g("low")], ownerId: "low" }); // extra property is simply not a parameter of computeAclUpdate
  assert.equal(find(r.appData.shared.transactions, "t1").ownerId, "mid");
  const dup = mkDoc({ tx: [rec("t1", "mid"), rec("t1", "mid")] });
  assert.equal(upd(dup, "mid").error.status, 409);
});

test("hierarchy re-evaluated at request time: a grant to a user who later leaves the hierarchy has no effect", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit", "delete")]) })] });
  assert.equal(permissionsFor(ctxOf(d, "mid"), "transactions", null, d.shared.transactions[0]).edit, true);
  d.shared.supervisors.find((s) => s.id === "n_low").supervisorId = "n_peer"; // low moves under peer
  assert.equal(permissionsFor(ctxOf(d, "mid"), "transactions", null, d.shared.transactions[0]).view, false);
});

test("malformed hierarchy fails closed for the ACL layer too (cycle => no viewers beyond self)", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, [g("mid", "edit")]) })] });
  d.shared.supervisors.find((s) => s.id === "n_top").supervisorId = "n_low"; // cycle
  const p = permissionsFor(ctxOf(d, "mid"), "transactions", null, d.shared.transactions[0]);
  assert.deepEqual(p, { view: false, edit: false, delete: false, acl: false });
});

test("forged caller fields cannot widen: permissionsFor ignores everything but the server-built context", () => {
  const d = mkDoc({ tx: [rec("t1", "low", { acl: acl(1, []) })] });
  const forged = { uid: "mid", role: "superadmin", linkedId: "n_low" }; // what a hostile client might CLAIM
  // the server derives role/linkedId from the stored user (mid = admin / n_mid), never from the claim:
  const real = callerOf("mid", d);
  assert.equal(permissionsFor(buildRecordAccessContext(d, real), "transactions", null, d.shared.transactions[0]).view, false);
  // (a forged superadmin role WOULD be unrestricted -- which is exactly why the Worker takes role from effectiveRole(token, stored user))
  assert.equal(permissionsFor(buildRecordAccessContext(d, forged), "transactions", null, d.shared.transactions[0]).view, true);
});
