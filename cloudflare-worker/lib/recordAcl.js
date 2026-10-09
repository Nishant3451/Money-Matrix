// ============================================================================================
// RECORD-LEVEL ACCESS CONTROL (ACL) for Payments (`transactions`) and Quotations (`quotations`).
//
// This module is the ONE place where per-record authorization is decided. It is deliberately
// pure (no I/O, no imports from authorization.js) so it can be audited and unit-tested alone.
// authorization.js builds an "access context" from the verified caller + the server's own copy of
// appData and hands it to the functions below.
//
// STORED MODEL (server-owned; the browser can never set it through /data/save):
//
//   record.acl absent                      => INHERIT  (every pre-existing record; no migration)
//   record.acl = { rev, grants: null }     => INHERIT  (tombstone: keeps `rev` monotonic after a revert,
//                                                       so an old, captured ACL request can never replay)
//   record.acl = { rev, grants: [ {uid, perms:[...]}, ... ] }
//                                          => RESTRICTED allow-list. [] (empty) == "private".
//   anything else under `acl`              => INVALID  => FAIL CLOSED (only a superadmin can touch it)
//
// `ownerId` is NOT duplicated here: the owner is `record.ownerId` for records in appData.shared, and the
// per-user BUCKET id for records in appData.perUser[bucket] (exactly what Data Scope already uses).
//
// EFFECTIVE PERMISSION = section permission  ∩  Data Scope ceiling  ∩  record ACL.
// The ACL layer can only NARROW (restricted) or confirm what layers 1-2 allow; it can never widen them:
//   * view needs the owner inside mine+upline+downline (viewOwners);
//   * edit / delete / acl-management need the owner inside mine+downline (writeOwners) -- so UPLINE
//     stays read-only even if a grant contains edit/delete/acl -- AND section permission "write" AND a
//     location the caller's role can actually write (non-admin roles only ever write their OWN bucket).
// ============================================================================================

export const ACL_COLLECTIONS = Object.freeze(["transactions", "quotations"]);
export const ACL_PERMS = Object.freeze(["view", "edit", "delete", "acl"]);
export const MAX_ACL_GRANTS = 25;
export const MAX_ACL_REV = 2_000_000_000;
const MAX_UID_LENGTH = 128;
const MAX_AUDIT_ENTRIES = 500;

const hasOwn = (o, k) => !!o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const isPlainObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const sameKeys = (obj, keys) => {
  const k = Object.keys(obj);
  return k.length === keys.length && keys.every((x) => hasOwn(obj, x));
};

const NONE = Object.freeze({ view: false, edit: false, delete: false, acl: false });
const ALL = Object.freeze({ view: true, edit: true, delete: true, acl: true });

// --------------------------------------------------------------------------------------------
// Parsing (strict, fail closed)
// --------------------------------------------------------------------------------------------

/** @returns {{kind:"inherit",rev:number}|{kind:"restricted",rev:number,grants:Map<string,Set<string>>}|{kind:"invalid"}} */
export function parseAcl(rec) {
  if (!isPlainObject(rec)) return { kind: "invalid" };
  if (!hasOwn(rec, "acl")) return { kind: "inherit", rev: 0 };
  const acl = rec.acl;
  if (!isPlainObject(acl) || !sameKeys(acl, ["rev", "grants"])) return { kind: "invalid" };
  if (!Number.isInteger(acl.rev) || acl.rev < 1 || acl.rev > MAX_ACL_REV) return { kind: "invalid" };
  if (acl.grants === null) return { kind: "inherit", rev: acl.rev };
  if (!Array.isArray(acl.grants) || acl.grants.length > MAX_ACL_GRANTS) return { kind: "invalid" };
  const grants = new Map();
  for (const g of acl.grants) {
    if (!isPlainObject(g) || !sameKeys(g, ["uid", "perms"])) return { kind: "invalid" };
    if (typeof g.uid !== "string" || !g.uid || g.uid.length > MAX_UID_LENGTH) return { kind: "invalid" };
    if (grants.has(g.uid)) return { kind: "invalid" }; // duplicate uid => ambiguous
    if (!Array.isArray(g.perms) || g.perms.length < 1 || g.perms.length > ACL_PERMS.length) return { kind: "invalid" };
    const perms = new Set();
    for (const p of g.perms) {
      if (typeof p !== "string" || !ACL_PERMS.includes(p) || perms.has(p)) return { kind: "invalid" };
      perms.add(p);
    }
    grants.set(g.uid, perms);
  }
  return { kind: "restricted", rev: acl.rev, grants };
}

// --------------------------------------------------------------------------------------------
// Evaluation
// --------------------------------------------------------------------------------------------

/** The owner of a record at a location: the bucket id for per-user records, `ownerId` for shared ones. */
export function ownerOfRecord(rec, bucket) {
  if (typeof bucket === "string" && bucket) return bucket;
  return isPlainObject(rec) && typeof rec.ownerId === "string" && rec.ownerId ? rec.ownerId : null;
}

/**
 * @param {object} ctx  { uid, isSuper, isFull, viewOwners:Set, writeOwners:Set, section:{transactions,quotations} }
 * @param {string} collection  "transactions" | "quotations"
 * @param {string|null} bucket per-user bucket id, or null for appData.shared
 * @returns {{view:boolean,edit:boolean,delete:boolean,acl:boolean}}
 */
export function permissionsFor(ctx, collection, bucket, rec) {
  if (!ctx || !ACL_COLLECTIONS.includes(collection) || !isPlainObject(rec)) return NONE;
  if (ctx.isSuper) return ALL; // superadmin is unrestricted and cannot be locked out by any ACL
  const owner = ownerOfRecord(rec, bucket);
  if (owner === null) return NONE; // ownerless (legacy) records stay superadmin-only, as before
  const sec = ctx.section ? ctx.section[collection] : "hidden";
  if (sec !== "view" && sec !== "write") return NONE;
  if (!ctx.viewOwners.has(owner)) return NONE; // outside Data Scope: an ACL can never pull it back in
  const acl = parseAcl(rec);
  if (acl.kind === "invalid") return NONE; // fail closed
  // WRITE CEILING (applies to every non-superadmin, grants included): section "write" AND the owner inside mine+downline.
  // Upline is never in writeOwners, so it is read-only whatever an ACL says.
  const writeCeiling = sec === "write" && ctx.writeOwners.has(owner);
  // ROLE PATH: where the caller's role could ALREADY write without any ACL (admins: anywhere in the ceiling; other roles:
  // only their own bucket). Owner rights and INHERIT records keep requiring it -- an ACL never widens those.
  const canWrite = writeCeiling && rolePathAt(ctx, bucket);
  const isOwner = owner === ctx.uid;
  if (acl.kind === "inherit") {
    return { view: true, edit: canWrite, delete: canWrite, acl: isOwner && canWrite };
  }
  if (isOwner) return { view: true, edit: canWrite, delete: canWrite, acl: canWrite };
  const g = acl.grants.get(ctx.uid);
  if (!g) return NONE; // restricted + not listed => no access at all
  // An EXPLICIT grant is the one thing that extends write access beyond the role path -- but only inside the ceiling above.
  return { view: true, edit: writeCeiling && g.has("edit"), delete: writeCeiling && g.has("delete"), acl: writeCeiling && g.has("acl") };
}

/** True where the caller's ROLE can write without any ACL: full roles anywhere (the Data Scope gate still confines
 *  them), every other role only in its own per-user bucket. */
function rolePathAt(ctx, bucket) {
  return !!ctx.isFull || (typeof bucket === "string" && bucket === ctx.uid);
}

// --------------------------------------------------------------------------------------------
// VIEW gate (/data/get and everything built on buildAuthorizedView, e.g. /privacy/export)
// --------------------------------------------------------------------------------------------

function filterRecords(arr, ctx, collection, bucket) {
  const kept = [];
  for (const rec of arr) {
    const p = permissionsFor(ctx, collection, bucket, rec);
    if (!p.view) continue;
    if (p.acl || !hasOwn(rec, "acl")) { kept.push(rec); continue; }
    const copy = { ...rec };
    delete copy.acl; // non-managers never see who else has access
    kept.push(copy);
  }
  return kept;
}

/** Collections whose activity entries are subject to record visibility. STICKY: a collection stays active once any
 *  record in it is restricted/invalid OR the (server-owned) ACL audit trail shows an ACL was ever set on that collection,
 *  so deleting the last restricted record can never re-expose the names in entries written about it. With no ACL ever
 *  used the activity log is exactly what it always was. */
function aclActiveCollections(fullData) {
  const active = new Set();
  const check = (arr, coll) => {
    if (!Array.isArray(arr)) return;
    for (const r of arr) if (isPlainObject(r) && hasOwn(r, "acl") && parseAcl(r).kind !== "inherit") { active.add(coll); return; }
  };
  const shared = isPlainObject(fullData && fullData.shared) ? fullData.shared : {};
  const perUser = isPlainObject(fullData && fullData.perUser) ? fullData.perUser : {};
  for (const coll of ACL_COLLECTIONS) {
    check(shared[coll], coll);
    for (const b of Object.values(perUser)) if (isPlainObject(b)) check(b[coll], coll);
  }
  if (Array.isArray(fullData && fullData.recordAclAudit)) {
    for (const e of fullData.recordAclAudit) if (isPlainObject(e) && ACL_COLLECTIONS.includes(e.coll)) active.add(e.coll);
  }
  return active;
}

/** Finds THE record an activity entry refers to in the server's data, or null when absent/ambiguous (fail closed). */
function makeRecordLookup(fullData) {
  const shared = isPlainObject(fullData && fullData.shared) ? fullData.shared : {};
  const perUser = isPlainObject(fullData && fullData.perUser) ? fullData.perUser : {};
  return (coll, bucket, id) => {
    let arr;
    if (bucket === null) arr = shared[coll];
    else arr = hasOwn(perUser, bucket) && isPlainObject(perUser[bucket]) ? perUser[bucket][coll] : null;
    if (!Array.isArray(arr)) return null;
    let found = null;
    for (const r of arr) {
      if (isPlainObject(r) && r.id === id) { if (found) return null; found = r; }
    }
    return found;
  };
}

/** A valid stable record reference on an activity entry: { recId: string, recBucket: string|null }. */
function recordRefOf(e) {
  if (typeof e.recId !== "string" || !e.recId || e.recId.length > MAX_UID_LENGTH || !hasOwn(e, "recBucket")) return null;
  const b = e.recBucket;
  if (b !== null && (typeof b !== "string" || !b || b.length > MAX_UID_LENGTH)) return null;
  return { id: e.recId, bucket: b };
}

/**
 * NEW Payment/Quotation activity entries get a SERVER-stamped `actorUid` (the verified caller; any client value is
 * discarded) and keep a client-supplied record reference only if it is well-formed. The reference is used solely to
 * decide who may SEE the entry (never to grant anything), so a wrong or forged reference can at worst hide/show text the
 * forger typed themselves. Entries without a usable reference are "legacy" and fail closed (see applyRecordAclToView).
 */
export function stampScopedActivityEntry(entry, uid) {
  if (!isPlainObject(entry) || !ACL_COLLECTIONS.includes(entry.coll)) return entry;
  const c = { ...entry };
  delete c.actorUid;
  if (typeof uid === "string" && uid) c.actorUid = uid;
  if (!recordRefOf(c)) { delete c.recId; delete c.recBucket; }
  return c;
}

/**
 * Applies record ACLs to an already section- and scope-gated view. Copies only; inputs are never mutated.
 *  - Records the caller cannot VIEW are removed; the access list is stripped for anyone who cannot manage it.
 *  - Activity log: see aclActiveCollections / stampScopedActivityEntry. In an active collection an entry is visible only to a
 *    superadmin, to its server-stamped actor uid, or to someone who can VIEW the record its stable reference points to.
 *    Entries with no reliable reference (legacy) are hidden. Display names and customer names are never consulted.
 */
export function applyRecordAclToView(out, fullData, ctx) {
  if (!ctx || ctx.isSuper) return out;
  const shared = { ...(isPlainObject(out.shared) ? out.shared : {}) };
  for (const coll of ACL_COLLECTIONS) {
    if (Array.isArray(shared[coll])) shared[coll] = filterRecords(shared[coll], ctx, coll, null);
  }
  const perUser = {};
  for (const [id, bucket] of Object.entries(isPlainObject(out.perUser) ? out.perUser : {})) {
    if (!isPlainObject(bucket)) { perUser[id] = bucket; continue; }
    const copy = { ...bucket };
    for (const coll of ACL_COLLECTIONS) if (Array.isArray(copy[coll])) copy[coll] = filterRecords(copy[coll], ctx, coll, id);
    perUser[id] = copy;
  }
  let activityLog = out.activityLog;
  const active = aclActiveCollections(fullData);
  if (active.size && Array.isArray(activityLog)) {
    const lookup = makeRecordLookup(fullData);
    activityLog = activityLog.filter((e) => {
      if (!isPlainObject(e) || !active.has(e.coll)) return true;
      if (typeof e.actorUid === "string" && e.actorUid === ctx.uid) return true; // server-stamped author
      const ref = recordRefOf(e);
      if (!ref) return false; // legacy / unreferenced entry: fail closed
      const rec = lookup(e.coll, ref.bucket, ref.id);
      return !!rec && permissionsFor(ctx, e.coll, ref.bucket, rec).view;
    });
  }
  return { ...out, shared, perUser, activityLog };
}

// --------------------------------------------------------------------------------------------
// WRITE gate (/data/save). Runs AFTER the existing section + Data Scope write gates, and also for
// superadmin (who may edit/delete anything, but can never change `acl`/`ownerId` through a blob).
// --------------------------------------------------------------------------------------------

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => hasOwn(b, k) && deepEqual(a[k], b[k]));
}

/** Record content with the two server-owned control fields removed, for "did the caller change anything?". */
function contentOf(rec) {
  const c = { ...rec };
  delete c.acl;
  delete c.ownerId;
  return c;
}

/** `submitted` record + the SERVER's acl/ownerId (the only trusted values for those two fields). */
function withServerControl(submitted, server) {
  const c = { ...submitted };
  delete c.acl;
  delete c.ownerId;
  if (hasOwn(server, "ownerId")) c.ownerId = server.ownerId;
  if (hasOwn(server, "acl")) c.acl = server.acl;
  return c;
}

function gateRecordArray(serverArr, mergedArr, ctx, collection, bucket) {
  const sArr = Array.isArray(serverArr) ? serverArr : [];
  const mArr = Array.isArray(mergedArr) ? mergedArr : [];
  const serverIndex = new Map();
  sArr.forEach((r, i) => { if (isPlainObject(r) && r.id != null && !serverIndex.has(r.id)) serverIndex.set(r.id, i); });

  const existing = []; // [serverPosition, record]
  const fresh = [];
  const handled = new Set();
  for (const m of mArr) {
    if (!isPlainObject(m) || m.id == null) { fresh.push(m); continue; }
    if (!serverIndex.has(m.id)) {
      const c = { ...m };
      delete c.acl; // a brand-new record is always INHERIT; the browser cannot create one pre-configured
      fresh.push(c);
      continue;
    }
    if (handled.has(m.id)) continue; // duplicate of an existing id: only the first is considered
    handled.add(m.id);
    const pos = serverIndex.get(m.id);
    const s = sArr[pos];
    if (deepEqual(contentOf(m), contentOf(s))) { existing.push([pos, s]); continue; } // nothing changed (ownerId/acl noise is discarded)
    if (permissionsFor(ctx, collection, bucket, s).edit) existing.push([pos, withServerControl(m, s)]);
    else existing.push([pos, s]); // edit not permitted: the server's copy wins
  }
  // Server records the caller's blob no longer contains = deletions. Allowed only with DELETE.
  for (const [id, pos] of serverIndex) {
    if (handled.has(id)) continue;
    const s = sArr[pos];
    if (!permissionsFor(ctx, collection, bucket, s).delete) existing.push([pos, s]); // restore
  }
  existing.sort((a, b) => a[0] - b[0]);
  return [...existing.map((e) => e[1]), ...fresh];
}

export function applyRecordAclToSave(merged, serverData, ctx, submitted) {
  const serverShared = isPlainObject(serverData && serverData.shared) ? serverData.shared : {};
  const serverPerUser = isPlainObject(serverData && serverData.perUser) ? serverData.perUser : {};
  const mShared = isPlainObject(merged.shared) ? merged.shared : {};
  const mPerUser = isPlainObject(merged.perUser) ? merged.perUser : {};

  const shared = { ...mShared };
  for (const coll of ACL_COLLECTIONS) {
    const had = Array.isArray(mShared[coll]);
    const res = gateRecordArray(serverShared[coll], mShared[coll], ctx, coll, null);
    if (had || res.length) shared[coll] = res;
  }

  const perUser = { ...mPerUser };
  const bucketIds = new Set([...Object.keys(serverPerUser), ...Object.keys(mPerUser)]);
  for (const id of bucketIds) {
    const mb = mPerUser[id];
    const sb = serverPerUser[id];
    if (mb !== undefined && !isPlainObject(mb)) continue; // not a bucket we can reason about; leave to existing gates
    const copy = isPlainObject(mb) ? { ...mb } : {};
    let touched = isPlainObject(mb);
    for (const coll of ACL_COLLECTIONS) {
      const had = isPlainObject(mb) && Array.isArray(mb[coll]);
      const res = gateRecordArray(isPlainObject(sb) ? sb[coll] : undefined, isPlainObject(mb) ? mb[coll] : undefined, ctx, coll, id);
      if (had || res.length) { copy[coll] = res; touched = true; }
    }
    if (touched) perUser[id] = copy;
  }
  return applyDelegatedWrites({ ...merged, shared, perUser }, serverData, ctx, submitted);
}

// --------------------------------------------------------------------------------------------
// DELEGATED WRITES. The existing merge only ever accepts, from a non-admin role, the caller's OWN bucket, and takes shared
// Payments/Quotations from the server. So an explicit EDIT/DELETE grant on someone else's record needs this one extra pass,
// which reads the caller's SUBMITTED blob for exactly the records the ACL layer allows them to change:
//   * EDIT   -- a submitted record that differs from the server's replaces it (acl/ownerId still come from the server);
//               only where the role path does not already handle the location, and only if permissionsFor().edit.
//   * DELETE -- only via an EXPLICIT request: blob.recordDeletes = [{coll, bucket, id}]. Absence from the blob is NEVER a
//               delete for these records: a stale client that never received a freshly granted record must not destroy it.
//   * Nothing is created here, and anything not covered by an explicit grant is untouched.
// --------------------------------------------------------------------------------------------
const MAX_RECORD_DELETES = 200;
const delKey = (coll, bucket, id) => JSON.stringify([coll, bucket, id]);

function parseRecordDeletes(submitted) {
  const out = new Set();
  const list = isPlainObject(submitted) && Array.isArray(submitted.recordDeletes) ? submitted.recordDeletes.slice(0, MAX_RECORD_DELETES) : [];
  for (const d of list) {
    if (!isPlainObject(d) || !sameKeys(d, ["coll", "bucket", "id"])) continue; // malformed => ignored (fail closed: nothing deleted)
    if (!ACL_COLLECTIONS.includes(d.coll)) continue;
    if (d.bucket !== null && (typeof d.bucket !== "string" || !d.bucket || d.bucket.length > MAX_UID_LENGTH)) continue;
    if (typeof d.id !== "string" || !d.id || d.id.length > MAX_UID_LENGTH) continue;
    out.add(delKey(d.coll, d.bucket, d.id));
  }
  return out;
}

function delegateArray(arr, serverArr, subArr, ctx, coll, bucket, deletes) {
  const serverById = new Map();
  for (const r of Array.isArray(serverArr) ? serverArr : []) if (isPlainObject(r) && r.id != null && !serverById.has(r.id)) serverById.set(r.id, r);
  const out = [];
  for (const r of arr) {
    const s = isPlainObject(r) && r.id != null ? serverById.get(r.id) : undefined;
    if (!s) { out.push(r); continue; }
    const p = permissionsFor(ctx, coll, bucket, s);
    if (p.delete && deletes.has(delKey(coll, bucket, r.id))) continue;
    if (p.edit && !rolePathAt(ctx, bucket) && Array.isArray(subArr)) {
      const sub = subArr.find((x) => isPlainObject(x) && x.id === r.id);
      if (sub && !deepEqual(contentOf(sub), contentOf(s))) { out.push(withServerControl(sub, s)); continue; }
    }
    out.push(r);
  }
  return out;
}

function applyDelegatedWrites(merged, serverData, ctx, submitted) {
  const sub = isPlainObject(submitted) ? submitted : {};
  const subShared = isPlainObject(sub.shared) ? sub.shared : {};
  const subPer = isPlainObject(sub.perUser) ? sub.perUser : {};
  const serverShared = isPlainObject(serverData && serverData.shared) ? serverData.shared : {};
  const serverPer = isPlainObject(serverData && serverData.perUser) ? serverData.perUser : {};
  const deletes = parseRecordDeletes(sub);

  const shared = { ...merged.shared };
  for (const coll of ACL_COLLECTIONS) {
    if (Array.isArray(shared[coll])) shared[coll] = delegateArray(shared[coll], serverShared[coll], subShared[coll], ctx, coll, null, deletes);
  }
  const perUser = { ...merged.perUser };
  for (const id of Object.keys(perUser)) {
    if (!isPlainObject(perUser[id])) continue;
    const copy = { ...perUser[id] };
    const sb = hasOwn(serverPer, id) && isPlainObject(serverPer[id]) ? serverPer[id] : {};
    const ub = hasOwn(subPer, id) && isPlainObject(subPer[id]) ? subPer[id] : {};
    for (const coll of ACL_COLLECTIONS) {
      if (Array.isArray(copy[coll])) copy[coll] = delegateArray(copy[coll], sb[coll], ub[coll], ctx, coll, id, deletes);
    }
    perUser[id] = copy;
  }
  return { ...merged, shared, perUser };
}

// --------------------------------------------------------------------------------------------
// ACL MUTATION (POST /record/acl). Pure: takes the freshly-read appData, returns the new appData.
// --------------------------------------------------------------------------------------------

const fail = (status, code, message, extra) => ({ error: { status, code, message, ...(extra || {}) } });
const NOT_FOUND = () => fail(404, "RECORD_NOT_FOUND", "Record not found");
const INVALID = () => fail(400, "ACL_INVALID", "The access list is not valid");

/** Validates and canonicalizes a client-supplied grants list. Returns {grants:[{uid,perms}]} (sorted, canonical) or {error}. */
export function canonicalizeGrants(input, serverData, ownerId) {
  if (!Array.isArray(input) || input.length > MAX_ACL_GRANTS) return { error: INVALID().error };
  const users = new Map();
  for (const u of Array.isArray(serverData && serverData.users) ? serverData.users : []) {
    if (isPlainObject(u) && typeof u.id === "string" && u.id && !users.has(u.id)) users.set(u.id, u);
  }
  const seen = new Set();
  const out = [];
  for (const g of input) {
    if (!isPlainObject(g) || !sameKeys(g, ["uid", "perms"])) return { error: INVALID().error };
    const { uid, perms } = g;
    if (typeof uid !== "string" || !uid || uid.length > MAX_UID_LENGTH || seen.has(uid)) return { error: INVALID().error };
    const user = users.get(uid);
    if (!user || uid === ownerId || user.role === "superadmin") return { error: INVALID().error }; // unknown / owner / superadmin (implicit)
    if (!Array.isArray(perms) || perms.length < 1 || perms.length > ACL_PERMS.length) return { error: INVALID().error };
    const set = new Set();
    for (const p of perms) {
      if (typeof p !== "string" || !ACL_PERMS.includes(p) || set.has(p)) return { error: INVALID().error };
      set.add(p);
    }
    set.add("view"); // edit / delete / acl all imply view
    seen.add(uid);
    out.push({ uid, perms: ACL_PERMS.filter((p) => set.has(p)) });
  }
  out.sort((a, b) => (a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0));
  return { grants: out };
}

function locate(appData, collection, bucket, id) {
  let arr;
  if (bucket === null) {
    arr = isPlainObject(appData.shared) && Array.isArray(appData.shared[collection]) ? appData.shared[collection] : null;
  } else {
    const per = isPlainObject(appData.perUser) && hasOwn(appData.perUser, bucket) ? appData.perUser[bucket] : null;
    arr = isPlainObject(per) && Array.isArray(per[collection]) ? per[collection] : null;
  }
  if (!arr) return { notFound: true };
  const hits = [];
  arr.forEach((r, i) => { if (isPlainObject(r) && r.id === id) hits.push(i); });
  if (hits.length === 0) return { notFound: true };
  if (hits.length > 1) return { ambiguous: true };
  return { arr, index: hits[0] };
}

/**
 * @param {object} p { appData, ctx, caller:{uid,role}, collection, bucket, id, baseRev, grants }
 *   `grants` is an array (restricted allow-list; [] = private) or null (revert to inherit).
 * @returns {{error:{status,code,message}}|{appData, result}}
 */
export function computeAclUpdate({ appData, ctx, collection, bucket, id, baseRev, grants }) {
  // ---- 1. request shape (400) ----
  if (!ACL_COLLECTIONS.includes(collection)) return INVALID();
  if (typeof id !== "string" || !id || id.length > MAX_UID_LENGTH) return INVALID();
  if (bucket !== null && (typeof bucket !== "string" || !bucket || bucket.length > MAX_UID_LENGTH)) return INVALID();
  if (!Number.isInteger(baseRev) || baseRev < 0 || baseRev > MAX_ACL_REV) return INVALID();
  if (grants !== null && !Array.isArray(grants)) return INVALID();

  // ---- 2. locate + authorize (404 when the caller cannot even VIEW it: existence is not disclosed) ----
  const loc = locate(appData, collection, bucket, id);
  if (loc.notFound) return NOT_FOUND();
  if (loc.ambiguous) return fail(409, "RECORD_AMBIGUOUS", "Record is ambiguous");
  const rec = loc.arr[loc.index];
  const perms = permissionsFor(ctx, collection, bucket, rec);
  if (!perms.view) return NOT_FOUND();
  if (!perms.acl) return fail(403, "ACL_FORBIDDEN", "You are not allowed to change access for this record");

  const owner = ownerOfRecord(rec, bucket);
  const isOwnerOrSuper = ctx.isSuper || owner === ctx.uid;
  const current = parseAcl(rec);
  if (current.kind === "invalid" && !ctx.isSuper) return NOT_FOUND(); // (unreachable: permissionsFor already denied)
  const curRev = current.kind === "invalid" ? 0 : current.rev;

  // ---- 3. validate the requested list (400) ----
  let canonical = null;
  if (grants !== null) {
    const c = canonicalizeGrants(grants, appData, owner);
    if (c.error) return { error: c.error };
    canonical = c.grants;
  }

  // ---- 4. stale / replayed request (409) ----
  if (baseRev !== curRev) return fail(409, "ACL_STALE", "This record's access changed since you loaded it", { currentRev: curRev });
  if (curRev >= MAX_ACL_REV) return fail(409, "ACL_REV_EXHAUSTED", "Access for this record cannot be changed further");

  // ---- 5. anti-escalation for DELEGATED managers (neither owner nor superadmin) ----
  if (!isOwnerOrSuper) {
    if (canonical === null) return fail(403, "ACL_FORBIDDEN", "Only the owner can reset access to inherited");
    const before = current.kind === "restricted" ? current.grants : new Map();
    const after = new Map(canonical.map((g) => [g.uid, new Set(g.perms)]));
    const mine = { view: perms.view, edit: perms.edit, delete: perms.delete, acl: perms.acl };
    const touched = new Set([...before.keys(), ...after.keys()]);
    for (const uid of touched) {
      const b = before.get(uid);
      const a = after.get(uid);
      const same = b && a && b.size === a.size && [...b].every((p) => a.has(p));
      if (same) continue;
      if (uid === ctx.uid) return fail(403, "ACL_FORBIDDEN", "You cannot change your own access");
      for (const p of [...(b || []), ...(a || [])]) {
        if (!mine[p]) return fail(403, "ACL_FORBIDDEN", "You cannot grant or revoke permissions you do not hold");
      }
    }
    // A state that is restricted must stay restricted (reverting to inherit was refused above).
  }

  // ---- 6. no-op detection (no rev churn) ----
  const sameAsCurrent =
    canonical === null
      ? current.kind === "inherit"
      : current.kind === "restricted" &&
        JSON.stringify(canonical) === JSON.stringify([...current.grants].map(([uid, s]) => ({ uid, perms: ACL_PERMS.filter((p) => s.has(p)) })).sort((x, y) => (x.uid < y.uid ? -1 : 1)));
  if (sameAsCurrent) return { appData, result: { rev: curRev, mode: canonical === null ? "inherit" : "restricted", changed: false } };

  // ---- 7. apply (copy-on-write) ----
  const newAcl = { rev: curRev + 1, grants: canonical };
  const nextRec = { ...rec, acl: newAcl };
  const nextArr = loc.arr.slice();
  nextArr[loc.index] = nextRec;
  const next = { ...appData };
  if (bucket === null) next.shared = { ...appData.shared, [collection]: nextArr };
  else next.perUser = { ...appData.perUser, [bucket]: { ...appData.perUser[bucket], [collection]: nextArr } };
  const audit = Array.isArray(appData.recordAclAudit) ? appData.recordAclAudit : [];
  next.recordAclAudit = [
    { ts: Date.now(), actor: ctx.uid, coll: collection, bucket, recId: id, action: canonical === null ? "reset_inherit" : "set", rev: newAcl.rev, grantCount: canonical === null ? 0 : canonical.length },
    ...audit,
  ].slice(0, MAX_AUDIT_ENTRIES);
  return { appData: next, result: { rev: newAcl.rev, mode: canonical === null ? "inherit" : "restricted", changed: true } };
}
