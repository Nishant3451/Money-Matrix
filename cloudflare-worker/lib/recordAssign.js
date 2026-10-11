// ============================================================================================
// RECORD ASSIGNMENT / OWNERSHIP TRANSFER for Payments (`transactions`) and Quotations (`quotations`).  (pure; no I/O)
//
// Ownership is server-controlled: `ownerId` (shared storage) / the per-user bucket (isolated storage) can NEVER be changed
// through /data/save (see applyRecordAclToSave). The one way to give a record to somebody else is POST /record/assign,
// which calls computeAssignment() below on a freshly-read copy of appData.
//
// WHO may assign WHAT (all derived from the verified caller + the server's own data, never from the request):
//   * the caller must be able to VIEW the record and EDIT it (section "write" + Data Scope write ceiling + record ACL), and
//     must be its owner, a full-access role (admin and above) acting inside their ceiling, or a record-super;
//     a user who merely holds an explicit EDIT grant may edit the content but cannot hand the record to somebody else;
//   * to WHOM:  Developer / record-super -> any ACTIVE user;  everyone else -> only themselves or users in their own
//     mine+downline hierarchy (never upline, never unrelated people). The target must be active (not disabled) and hold at
//     least "view" on the section, otherwise the record would be invisible to them;
//   * stale protection: `expectedOwner` must equal the record's current owner, otherwise 409 and nothing changes.
//
// Moving a record never makes it more widely available: the access list (record ACL) stays as it was (a restricted list stays
// restricted; the new owner is removed from the grants because the owner is implicit) and its revision is bumped, so an old
// captured ACL request cannot replay against the transferred record. A legacy record that has no owner is only ever
// assignable by a record-super, and only by an explicit request (expectedOwner: null) -- the owner is never guessed.
// ============================================================================================
import { assignableTargets, emptyPerUserBucket } from "./authorization.js";
import { ACL_COLLECTIONS, MAX_ACL_REV, locate, ownerOfRecord, parseAcl, permissionsFor } from "./recordAcl.js";

const MAX_UID_LENGTH = 128;
const MAX_AUDIT_ENTRIES = 500;
const PERM_ORDER = ["view", "edit", "delete", "acl"];
const isPlainObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const fail = (status, code, message, extra) => ({ error: { status, code, message, ...(extra || {}) } });

/**
 * @param {object} p { appData, ctx, caller:{uid,role,linkedId}, collection, bucket, id, expectedOwner, targetUid }
 *   `ctx` is buildRecordAccessContext(appData, caller). `bucket` is null for appData.shared records, else the per-user bucket id.
 * @returns {{error:{status,code,message}}|{appData, result:{owner,changed}}}
 */
export function computeAssignment({ appData, ctx, caller, collection, bucket, id, expectedOwner, targetUid }) {
  // ---- 1. request shape (400) ----
  const badId = (v) => typeof v !== "string" || !v || v.length > MAX_UID_LENGTH;
  if (!ACL_COLLECTIONS.includes(collection) || badId(id) || badId(targetUid)) return fail(400, "ASSIGN_INVALID", "The assignment request is not valid");
  if (bucket !== null && badId(bucket)) return fail(400, "ASSIGN_INVALID", "The assignment request is not valid");
  if (expectedOwner !== null && badId(expectedOwner)) return fail(400, "ASSIGN_INVALID", "The assignment request is not valid");

  // ---- 2. locate + authorize (404 when the caller cannot even VIEW it: existence is not disclosed) ----
  const loc = locate(appData, collection, bucket, id);
  if (loc.notFound) return fail(404, "RECORD_NOT_FOUND", "Record not found");
  if (loc.ambiguous) return fail(409, "RECORD_AMBIGUOUS", "Record is ambiguous");
  const rec = loc.arr[loc.index];
  const perms = permissionsFor(ctx, collection, bucket, rec);
  if (!perms.view) return fail(404, "RECORD_NOT_FOUND", "Record not found");
  const owner = ownerOfRecord(rec, bucket); // null only for a legacy unowned record (record-super only: everyone else got 404 above)

  // ---- 3. stale request (409): the caller must have seen the CURRENT owner ----
  if (expectedOwner !== owner) return fail(409, "OWNER_STALE", "This record's owner changed since you loaded it", { currentOwner: owner });

  // ---- 4. may this caller hand this record to somebody else? ----
  const mayTransfer = perms.edit && (ctx.isSuper || ctx.isFull || owner === ctx.uid);
  if (!mayTransfer) return fail(403, "ASSIGN_FORBIDDEN", "You are not allowed to assign this record");

  // ---- 5. no-op ----
  if (targetUid === owner) return { appData, result: { owner, changed: false } };

  // ---- 6. is the target someone this caller may assign to? (nonexistent / inactive / out of hierarchy / cannot see the section: one generic answer) ----
  const eligible = assignableTargets(appData, caller, collection);
  if (!eligible.some((t) => t.uid === targetUid)) return fail(400, "ASSIGN_TARGET_INVALID", "That user cannot be assigned this record");

  // ---- 7. apply (copy-on-write) ----
  const acl = parseAcl(rec);
  const nextRec = { ...rec, ownerId: targetUid };
  if (acl.kind === "restricted") {
    if (acl.rev >= MAX_ACL_REV) return fail(409, "ACL_REV_EXHAUSTED", "This record cannot be reassigned further");
    // Still exactly as restricted as before; the new owner is implicit so it leaves the grant list; the revision moves on.
    const grants = [];
    for (const [uid, perms2] of acl.grants) if (uid !== targetUid) grants.push({ uid, perms: PERM_ORDER.filter((p) => perms2.has(p)) });
    grants.sort((a, b) => (a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0));
    nextRec.acl = { rev: acl.rev + 1, grants };
  }

  const next = { ...appData };
  if (bucket === null) {
    const arr = loc.arr.slice();
    arr[loc.index] = nextRec;
    next.shared = { ...appData.shared, [collection]: arr };
  } else {
    // Isolated storage: ownership IS the bucket, so the record moves to the target's bucket.
    const perUser = { ...appData.perUser };
    const targetBucket = isPlainObject(perUser[targetUid]) ? { ...perUser[targetUid] } : emptyPerUserBucket();
    const targetArr = Array.isArray(targetBucket[collection]) ? targetBucket[collection] : [];
    if (targetArr.some((r) => isPlainObject(r) && r.id === id)) return fail(409, "RECORD_ID_CONFLICT", "The recipient already has a record with this id");
    perUser[bucket] = { ...perUser[bucket], [collection]: loc.arr.filter((_, i) => i !== loc.index) };
    targetBucket[collection] = [...targetArr, nextRec];
    perUser[targetUid] = targetBucket;
    next.perUser = perUser;
  }
  const audit = Array.isArray(appData.accessAudit) ? appData.accessAudit : [];
  next.accessAudit = [
    { ts: Date.now(), actor: ctx.uid, action: "assign", coll: collection, bucket, recId: id, from: owner, to: targetUid },
    ...audit,
  ].slice(0, MAX_AUDIT_ENTRIES);
  return { appData: next, result: { owner: targetUid, changed: true } };
}
