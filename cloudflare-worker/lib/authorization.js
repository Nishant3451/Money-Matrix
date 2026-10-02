// ============================================================================================
// Server-side authorization / data-isolation logic for getAppData & saveAppData.
//
// PROVENANCE: functions/index.js (the original Cloud Function that implemented these rules)
// does not exist anywhere in this repository, and this repo has no git history — so it cannot
// be recovered or diffed against. What follows is NOT a guess at new rules: the read-scoping
// logic below (getDownlineSupervisorIds / scope filters for members, coaches, supervisors,
// activityLog) is a direct, unmodified port of the client-side functions of the same name that
// already exist in index.html (search for "THE DOWNLINE CONSTRAINT ENGINE"). Those functions
// are the app's own real algorithm — the frontend already computes them today for its own UI
// filtering/defense-in-depth — not an invention. Only the WRITE side (mergeAuthorizedSave) is
// genuinely new code, because no write-side equivalent survives anywhere. It is built to mirror
// the read-scope symmetrically (a caller may only change what they're authorized to read),
// which is both the conservative default and literally what the task brief asked for. One
// concrete piece of surviving evidence supports this direction: a comment in index.html (near
// ensure()) states that "saveAppData ... silently drops a non-superadmin's `users` field" rather
// than rejecting the whole save — i.e. out-of-scope sections are dropped/ignored, not treated as
// a hard error. That silent-drop behavior is reproduced here for every section, not just users.
//
// Roles: "superadmin" and "admin" both get full, unfiltered access (this mirrors isAdmin() in
// the client, which is `role === 'admin' || role === 'superadmin'`). A plain "user" who has a
// linkedId (i.e. is tied to a supervisor node) gets a downline-scoped view/write; a "user" with
// no linkedId gets no shared-directory access at all (mirrors getScopedMembers() etc. returning
// the unfiltered list only for admins, and otherwise depending entirely on currentUser.linkedId
// being set — the ": return members" fallback with no linkedId is a client display quirk we do
// NOT mirror server-side, since serving an unscoped list to an unlinked non-admin would be a
// data leak; server-side we scope-to-empty instead. See buildAuthorizedView below.)
// ============================================================================================

/**
 * Walks the supervisor->supervisor chain (verbatim port of getDownlineSupervisorIds in
 * index.html) and returns the root id plus every supervisor beneath it, at any depth. Guards
 * against circular links so it can never loop forever.
 */
export function getDownlineSupervisorIds(rootId, supervisors) {
  const ids = new Set([rootId]);
  let added = true;
  while (added) {
    added = false;
    (supervisors || []).forEach((s) => {
      if (s.supervisorId && ids.has(s.supervisorId) && !ids.has(s.id)) {
        ids.add(s.id);
        added = true;
      }
    });
  }
  return ids;
}

export function isFullAccessRole(role) {
  return role === "superadmin" || role === "admin";
}

// ---------------------------------------------------------------------------------------------
// ROLE FRESHNESS. The Worker takes the caller's role from the verified ID token's `role` claim, and
// an already-issued ID token (and the persisted claim a refresh/re-login re-reads) can be OLDER than
// the user's stored role: the User Management role-only edit changes appData.users[].role through
// /data/save and does NOT touch the credentials doc, the Firebase claim or any session. A demoted
// admin therefore kept admin authority — and could even re-promote themselves — until a PIN reset.
//
// The stored record is already read, in the same snapshot, by every handler that authorizes on role,
// so it is the authoritative current role at zero extra I/O. This is DEMOTE-ONLY by design: when the
// stored role carries LESS privilege than the token claims, the stored role wins immediately; a stored
// role never raises privilege above what the token proves (promotions still take effect through a
// fresh login as before). Privilege order is superadmin > admin > everything else.
// ---------------------------------------------------------------------------------------------
const ROLE_RANK = { superadmin: 2, admin: 1 };
const roleRank = (r) => (hasOwn(ROLE_RANK, r) ? ROLE_RANK[r] : 0);
export function effectiveRole(tokenRole, storedUser) {
  const stored = storedUser && typeof storedUser.role === "string" && storedUser.role ? storedUser.role : null;
  if (!stored) return tokenRole; // no authoritative record to compare against: unchanged behaviour
  return roleRank(stored) < roleRank(tokenRole) ? stored : tokenRole;
}

// ============================================================================================
// SECTION-LEVEL AUTHORIZATION (server-enforced)
//
// Until now the Worker only did downline scoping; the per-section permissions (Access Control /
// Individual Access / Product & Quotation "Manage Access") were enforced ONLY by the browser, so a
// user with a section set to "hidden" still received that section's data from /data/get and could
// still write it via /data/save. This block makes the Worker authoritative for the three sensitive
// datasets, using the app's EXISTING permission data — not a new permission system.
//
//   permission key  ->  data collection (both in `shared` and in every `perUser` bucket)
//   products        ->  products
//   quotations      ->  quotations   (also covers invoices: an invoice is a quotation that has an
//                                     invoiceNumber; there is no separate invoices collection)
//   marathon        ->  transactions ("Payments" in the UI)
//
// Resolution order is a line-for-line mirror of getPerm() in index.html so client and server can
// never disagree:  superadmin -> per-user override -> role matrix -> role fallback.
// Everything is computed from the SERVER's stored data and the verified caller identity; nothing
// the client submits (role, permissions, overrides) is ever consulted.
// ============================================================================================
export const GATED_SECTIONS = Object.freeze([
  Object.freeze({ permKey: "products", collection: "products" }),
  Object.freeze({ permKey: "quotations", collection: "quotations" }),
  Object.freeze({ permKey: "marathon", collection: "transactions" }),
]);

const hasOwn = (o, k) => !!o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
// Anything that is not exactly "view" or "write" is treated as "hidden" (fail closed) — the client
// does the same, since canView()/canWrite() only accept those two values.
const normalizePerm = (v) => (v === "view" || v === "write" ? v : "hidden");

/**
 * @returns {"hidden"|"view"|"write"} the caller's effective permission for `section`.
 * @param {object} data    the server's authoritative appData (permissions / userPermissions)
 * @param {object} caller  { uid, role } — resolved server-side from the verified token
 */
export function resolveSectionPerm(data, caller, section) {
  const { uid, role } = caller || {};
  // Superadmin is unrestricted and cannot be locked out by any override or matrix entry.
  if (role === "superadmin") return "write";
  const overrides = data && data.userPermissions;
  if (hasOwn(overrides, uid) && hasOwn(overrides[uid], section) && overrides[uid][section]) {
    return normalizePerm(overrides[uid][section]);
  }
  const matrix = data && data.permissions;
  if (hasOwn(matrix, role) && hasOwn(matrix[role], section) && matrix[role][section]) {
    return normalizePerm(matrix[role][section]);
  }
  return role === "admin" ? "write" : "hidden";
}
export const canViewSection = (data, caller, section) => resolveSectionPerm(data, caller, section) !== "hidden";
export const canWriteSection = (data, caller, section) => resolveSectionPerm(data, caller, section) === "write";

// ============================================================================================
// DATA SCOPE for Payments (transactions) and Quotations — WHOSE records a caller may see.
//
// Section permission (above) decides IF a caller may see a section at all; this decides WHICH PEOPLE'S
// records within it. It reuses the existing hierarchy, it does not add one:
//   * the tree is shared.supervisors[].supervisorId (a node's upline),
//   * a user attaches to it through users[].linkedId, and
//   * "downline" is exactly getDownlineSupervisorIds() / scopeUsers() — the same rule that already scopes
//     members, coaches, supervisors and the users list.
// Every record carries ownerId (saveTx / saveQuotation stamp it); in per-user mode the owner is the bucket.
//
// MAXIMUM scope, computed here from the SERVER's data and the verified caller — never from the request:
//   superadmin            -> everything ("all"), including legacy records that carry no ownerId
//   admin / user / other  -> themselves + their downline ("mine_downline"). Admin gets NO "all": the old
//                            "full-access roles see every record" behaviour is intentionally not applied
//                            to these two collections.
// "Upline" is deliberately NOT a scope: no existing rule lets any role see an upline's records, and
// exposing a superior's payments/quotations would be a new privilege, not a view of existing ones.
// A client may REQUEST a narrower scope; anything outside `allowed` is rejected, never widened.
// ============================================================================================
export const DATA_SCOPES = Object.freeze(["all", "mine_downline", "mine", "downline"]);
export const SCOPED_COLLECTIONS = Object.freeze(["transactions", "quotations"]);

/** @returns {{allowed:string[], defaultScope:string, owners:{mine:string[],downline:string[],mine_downline:string[]}, isSuper:boolean}} */
export function resolveDataScope(fullData, caller) {
  const { uid, role, linkedId } = caller || {};
  const users = Array.isArray(fullData && fullData.users) ? fullData.users : [];
  const supervisors = (fullData && fullData.shared && fullData.shared.supervisors) || [];
  const downlineNodes = linkedId ? getDownlineSupervisorIds(linkedId, supervisors) : new Set();
  const downline = [];
  for (const u of users) {
    if (u && typeof u.id === "string" && u.id !== uid && u.linkedId && downlineNodes.has(u.linkedId)) downline.push(u.id);
  }
  const mine = typeof uid === "string" && uid ? [uid] : [];
  const isSuper = role === "superadmin";
  const hasDownline = downline.length > 0;
  const allowed = [];
  if (isSuper) allowed.push("all");
  if (hasDownline) allowed.push("mine_downline");
  allowed.push("mine");
  if (hasDownline) allowed.push("downline");
  return {
    allowed,
    defaultScope: isSuper ? "all" : hasDownline ? "mine_downline" : "mine",
    owners: { mine, downline, mine_downline: [...new Set([...mine, ...downline])] },
    isSuper,
  };
}

/** Validates a CLIENT-REQUESTED scope against what the server computed. undefined/null => the default. */
export function resolveRequestedScope(ds, requested) {
  if (requested === undefined || requested === null) return { ok: true, key: ds.defaultScope };
  if (typeof requested !== "string" || !ds.allowed.includes(requested)) return { ok: false };
  return { ok: true, key: requested };
}
/** Owner-id Set for a scope key, or null meaning "no owner restriction" (superadmin's "all"). */
const ownerSetForScope = (ds, key) => (key === "all" ? null : new Set(ds.owners[key] || []));
const ownedBy = (rec, owners) => owners === null || (!!rec && typeof rec.ownerId === "string" && owners.has(rec.ownerId));

function scopeError() {
  return Object.assign(new Error("Requested data scope is not allowed"), { code: "SCOPE_NOT_ALLOWED" });
}

/** Applies the data scope to an already section-gated view (copies only; inputs are never mutated). */
function gateScopeForView(out, fullData, caller, ds, activeKey) {
  const owners = ownerSetForScope(ds, activeKey);
  const shared = { ...(out.shared || {}) };
  for (const coll of SCOPED_COLLECTIONS) {
    if (Array.isArray(shared[coll])) shared[coll] = shared[coll].filter((r) => ownedBy(r, owners));
  }
  const perUser = {};
  for (const [id, bucket] of Object.entries(out.perUser || {})) {
    if (!isPlainObject(bucket) || owners === null || owners.has(id)) { perUser[id] = bucket; continue; }
    const copy = { ...bucket };
    for (const coll of SCOPED_COLLECTIONS) if (Array.isArray(copy[coll])) copy[coll] = [];
    perUser[id] = copy;
  }
  // Non-full callers are only ever sent their OWN bucket. For the scopes that include other people, add the
  // scoped collections (only) of those people's buckets — and only for sections the caller may view.
  if (owners !== null && !isFullAccessRole(caller.role)) {
    const fullPerUser = fullData.perUser || {};
    for (const id of owners) {
      if (hasOwn(perUser, id) || !isPlainObject(fullPerUser[id])) continue;
      const partial = {};
      for (const { permKey, collection } of GATED_SECTIONS) {
        if (!SCOPED_COLLECTIONS.includes(collection)) continue;
        partial[collection] = canViewSection(fullData, caller, permKey) && Array.isArray(fullPerUser[id][collection]) ? fullPerUser[id][collection] : [];
      }
      perUser[id] = partial;
    }
  }
  // The activity log names customers of payments/quotations. Entries record an actor DISPLAY NAME (client-written,
  // not an id), so attribution is best-effort and fails closed: keep a payments/quotations entry only when its actor
  // matches the username or display name of someone whose records are in scope; superadmin "all" keeps everything.
  let activityLog = out.activityLog;
  if (owners !== null) {
    const actors = new Set();
    for (const u of fullData.users || []) {
      if (u && owners.has(u.id)) {
        if (u.username) actors.add(u.username);
        const dn = fullData.profiles && fullData.profiles[u.id] && fullData.profiles[u.id].displayName;
        if (dn) actors.add(dn);
      }
    }
    activityLog = (out.activityLog || []).filter((a) => !a || !SCOPED_COLLECTIONS.includes(a.coll) || actors.has(a.user));
  }
  return {
    ...out,
    shared,
    perUser,
    activityLog,
    dataScope: { allowed: ds.allowed, default: ds.defaultScope, active: activeKey, owners: ds.owners },
  };
}

/** mergeScopedArray with identical accept/reject/delete semantics, but records that already exist server-side keep the
 *  server's relative order (new records follow, in submission order). A no-op save therefore leaves the stored list
 *  byte-for-byte unchanged instead of re-sorting it into "out-of-scope first" on every save. */
function mergeScopedArrayStable(serverArr, submittedArr, inScope) {
  const merged = mergeScopedArray(serverArr, submittedArr, inScope);
  const pos = new Map((Array.isArray(serverArr) ? serverArr : []).map((r, i) => [r && r.id, i]));
  const existing = merged.filter((r) => r && pos.has(r.id)).sort((a, b) => pos.get(a.id) - pos.get(b.id));
  const fresh = merged.filter((r) => !(r && pos.has(r.id)));
  return [...existing, ...fresh];
}

/** After a save has been merged, confines a NON-superadmin's changes to Payments/Quotations to records inside their
 *  maximum scope: records of people outside it are restored from the server, cannot be edited, re-attributed, deleted
 *  or injected, and an id that collides with an out-of-scope record cannot be taken over. Decided from `serverData`.
 *  This is what makes it safe that an admin's client only ever HOLDS its in-scope records but a full-access save
 *  otherwise replaces `shared`/`perUser` wholesale. */
function applyOwnerScopeWriteGate(merged, serverData, caller) {
  if (caller.role === "superadmin") return merged;
  const maxOwners = new Set(resolveDataScope(serverData, caller).owners.mine_downline);
  const serverShared = serverData.shared || {};
  const serverPerUser = serverData.perUser || {};
  const shared = { ...(isPlainObject(merged.shared) ? merged.shared : {}) };
  for (const coll of SCOPED_COLLECTIONS) {
    if (!hasOwn(shared, coll)) continue;
    shared[coll] = mergeScopedArrayStable(serverShared[coll], shared[coll], (r) => ownedBy(r, maxOwners));
  }
  const perUser = {};
  for (const [id, bucket] of Object.entries(isPlainObject(merged.perUser) ? merged.perUser : {})) {
    if (!isPlainObject(bucket) || maxOwners.has(id)) { perUser[id] = bucket; continue; }
    const copy = { ...bucket };
    const serverBucket = serverPerUser[id];
    for (const coll of SCOPED_COLLECTIONS) {
      if (!isPlainObject(serverBucket)) copy[coll] = [];
      else if (hasOwn(serverBucket, coll)) copy[coll] = serverBucket[coll];
      else delete copy[coll];
    }
    perUser[id] = copy;
  }
  return { ...merged, shared, perUser };
}

/** Returns a copy of `out` with every collection the caller may not VIEW emptied — in the shared
 *  directory, in every per-user bucket they were about to receive, and in the activity log (which
 *  carries customer/product names). Copies only; `out` and the source data are never mutated. */
function gateViewForCaller(out, fullData, caller) {
  const hidden = GATED_SECTIONS.filter((s) => !canViewSection(fullData, caller, s.permKey));
  if (!hidden.length) return out;
  const hiddenColls = new Set(hidden.map((s) => s.collection));
  const shared = { ...(out.shared || {}) };
  const perUser = {};
  for (const [id, bucket] of Object.entries(out.perUser || {})) perUser[id] = isPlainObject(bucket) ? { ...bucket } : bucket;
  for (const { collection } of hidden) {
    shared[collection] = [];
    for (const bucket of Object.values(perUser)) if (isPlainObject(bucket)) bucket[collection] = [];
  }
  return {
    ...out,
    shared,
    perUser,
    activityLog: (out.activityLog || []).filter((a) => !(a && hiddenColls.has(a.coll))),
  };
}

/** After a save has been merged, restores the SERVER's copy of every gated collection the caller
 *  may not WRITE (hidden or view-only). Decided from `serverData`, so a caller cannot widen their own
 *  write access inside the same request. Also what makes it safe that a hidden-section user's client
 *  holds `[]` for that collection and echoes it back: it can never overwrite the real records. */
function applySectionWriteGate(merged, serverData, caller) {
  const locked = GATED_SECTIONS.filter((s) => !canWriteSection(serverData, caller, s.permKey));
  if (!locked.length) return merged;
  const serverShared = serverData.shared || {};
  const serverPerUser = serverData.perUser || {};
  const shared = { ...(isPlainObject(merged.shared) ? merged.shared : {}) };
  const perUser = {};
  for (const [id, bucket] of Object.entries(isPlainObject(merged.perUser) ? merged.perUser : {})) {
    perUser[id] = isPlainObject(bucket) ? { ...bucket } : bucket;
  }
  for (const { collection } of locked) {
    if (hasOwn(serverShared, collection)) shared[collection] = serverShared[collection];
    else delete shared[collection];
    for (const [id, bucket] of Object.entries(perUser)) {
      if (!isPlainObject(bucket)) continue;
      const serverBucket = serverPerUser[id];
      if (!isPlainObject(serverBucket)) bucket[collection] = []; // brand-new bucket: nothing to preserve
      else if (hasOwn(serverBucket, collection)) bucket[collection] = serverBucket[collection];
      else delete bucket[collection];
    }
  }
  return { ...merged, shared, perUser };
}

/** Ports getScopedMembers/Coaches/Supervisors/Activity from index.html. */
function scopeShared(shared, role, linkedId) {
  const members = shared.members || [];
  const coaches = shared.coaches || [];
  const supervisors = shared.supervisors || [];

  if (isFullAccessRole(role)) {
    return { members, coaches, supervisors };
  }
  if (!linkedId) {
    // No downline root to scope from — a non-admin, unlinked user gets none of the shared
    // directory. (The client's own fallback of "just return everything" is a UI quirk we do
    // not reproduce server-side; that would defeat the point of scoping.)
    return { members: [], coaches: [], supervisors: [] };
  }
  const downline = getDownlineSupervisorIds(linkedId, supervisors);
  const scopedSupervisors = supervisors.filter((s) => downline.has(s.id));
  const scopedCoaches = coaches.filter((c) => downline.has(c.supervisorId));
  const scopedMembers = members.filter(
    (m) =>
      downline.has(m.supervisorId) ||
      (m.coachId && downline.has((coaches.find((c) => c.id === m.coachId) || {}).supervisorId))
  );
  return { members: scopedMembers, coaches: scopedCoaches, supervisors: scopedSupervisors };
}

function scopeActivityLog(activityLog, shared, role, linkedId) {
  if (isFullAccessRole(role)) return activityLog || [];
  if (!linkedId) return [];
  const downline = getDownlineSupervisorIds(linkedId, shared.supervisors || []);
  return (activityLog || []).filter((a) => a.scopeId && downline.has(a.scopeId));
}

/** Filters the users control-plane list the same way the shared directory is scoped. */
function scopeUsers(users, role, linkedId, downlineIds) {
  if (isFullAccessRole(role)) return users || [];
  return (users || []).filter((u) => u.linkedId && downlineIds.has(u.linkedId));
}

/**
 * Builds the exact JSON payload a given caller is authorized to receive — mirrors what the
 * frontend's data() + getScoped*() helpers already assume the server hands back.
 *
 * @param {object} fullData   the full, authoritative appData.json contents
 * @param {object} caller     { uid, role, linkedId }  — role/linkedId resolved server-side from
 *                            the caller's own record in fullData.users, NEVER from client input
 */
export function buildAuthorizedView(fullData, caller, opts = {}) {
  const { uid, role, linkedId } = caller;
  const full = isFullAccessRole(role);
  const downlineIds = linkedId ? getDownlineSupervisorIds(linkedId, (fullData.shared || {}).supervisors || []) : new Set();

  const shared = fullData.shared || {};
  const scopedShared = scopeShared(shared, role, linkedId);

  const out = {
    settings: fullData.settings || {},
    permissions: fullData.permissions || {},
    customSections: fullData.customSections || [],
    profiles: fullData.profiles || {},
    users: scopeUsers(fullData.users, role, linkedId, downlineIds),
    activityLog: scopeActivityLog(fullData.activityLog, shared, role, linkedId),
    shared: {
      ...shared,
      members: scopedShared.members,
      coaches: scopedShared.coaches,
      supervisors: scopedShared.supervisors,
      // transactions/gifts/custom/etc are NOT downline-scoped anywhere in the existing client
      // (data() returns them unfiltered even for scoped users) — preserved as-is.
    },
    // perUser: only the caller's own bucket for a non-privileged caller (matches
    // data()/isAdmin() gating setView() in the client); admins/superadmin get every bucket so
    // the existing "view as" feature keeps working.
    perUser: full ? fullData.perUser || {} : { [uid]: (fullData.perUser || {})[uid] || emptyPerUserBucket() },
    // userPermissions: a non-privileged caller only ever reads their OWN override (see
    // DB.userPermissions?.[currentUser?.id]?.[section] in index.html) — no reason to ship
    // every other user's override map to them.
    userPermissions: full
      ? fullData.userPermissions || {}
      : { [uid]: (fullData.userPermissions || {})[uid] || {} },
    // ---- Privacy system (Part B) ----
    // policyVersions: published versions are visible to everyone (a user must be able to read
    // the policy they're asked to accept); admins additionally see drafts so they can review
    // before publishing. Never exposes anything else.
    policyVersions: full
      ? fullData.policyVersions || []
      : (fullData.policyVersions || []).filter((p) => p.status === "published"),
    // consent/preferences/policyAcceptances: same self-only-unless-admin shape as perUser.
    privacyConsents: full
      ? fullData.privacyConsents || {}
      : { [uid]: (fullData.privacyConsents || {})[uid] || [] },
    privacyPreferences: full
      ? fullData.privacyPreferences || {}
      : { [uid]: (fullData.privacyPreferences || {})[uid] || { essential: true } },
    policyAcceptances: full
      ? fullData.policyAcceptances || {}
      : { [uid]: (fullData.policyAcceptances || {})[uid] || {} },
    // privacyRequests: a non-admin only ever sees their own requests, never another user's.
    privacyRequests: full
      ? fullData.privacyRequests || []
      : (fullData.privacyRequests || []).filter((r) => r.uid === uid),
    // privacyAuditLog: admin-only. Exposing every user's privacy actions to every other user
    // would itself be a privacy leak, so non-admins get nothing here (not even their own
    // entries) rather than a filtered view — the audit trail is an oversight tool, not a
    // per-user activity feed (that's what activityLog is for).
    privacyAuditLog: full ? fullData.privacyAuditLog || [] : [],
  };
  // Section-level gate LAST, so it applies on top of (never instead of) the scope rules above:
  // "Products: view" widens nothing beyond what the shared/per-user scoping already allowed.
  const sectionGated = gateViewForCaller(out, fullData, caller);
  // Then the data scope (WHOSE records), computed from server data. A requested scope is validated, never widened.
  const ds = resolveDataScope(fullData, caller);
  const requested = resolveRequestedScope(ds, opts && opts.scope);
  if (!requested.ok) throw scopeError();
  return gateScopeForView(sectionGated, fullData, caller, ds, requested.key);
}

export function emptyPerUserBucket() {
  return { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], quotations: [], clients: [] };
}

/**
 * Applies a caller's submitted full-DB save onto the server's authoritative copy, keeping only
 * the sections/records that caller is authorized to change. Everything outside their scope is
 * taken from the server's existing state, unchanged — this is what makes it safe to accept a
 * "whole DB blob" payload from a client that may only ever have seen a filtered subset of it.
 *
 * @param {object} serverData    current authoritative appData.json contents
 * @param {object} submitted     the caller's submitted full DB JSON
 * @param {object} caller        { uid, role, linkedId }
 * @returns {object} the new authoritative appData.json contents to persist
 */
export function mergeAuthorizedSave(serverData, submitted, caller) {
  const sectionGated = applySectionWriteGate(mergeAuthorizedSaveScoped(serverData, submitted, caller), serverData, caller);
  return applyOwnerScopeWriteGate(sectionGated, serverData, caller);
}

function mergeAuthorizedSaveScoped(serverData, submitted, caller) {
  const { uid, role, linkedId } = caller;
  const full = isFullAccessRole(role);
  submitted = submitted && typeof submitted === "object" ? submitted : {};

  if (full) {
    // Superadmin/admin are the server-verified control plane — apply their save as-is, but
    // still never trust anything about the caller's OWN identity/role from the body, and never
    // let even an admin overwrite the credentials doc (that's a separate document entirely and
    // is never part of appData in the first place).
    return {
      users: sanitizeUsersForFullAccessSave(serverData.users, submitted.users, role),
      profiles: isPlainObject(submitted.profiles) ? submitted.profiles : serverData.profiles || {},
      settings: isPlainObject(submitted.settings) ? submitted.settings : serverData.settings || {},
      // Access settings are the security policy itself: ONLY a superadmin may change them (the UI
      // already restricts Access Control / Individual Access / Manage Access to superadmin). An
      // admin's submitted copy is ignored, so an admin cannot grant themselves or anyone else access.
      permissions: role === "superadmin" && isPlainObject(submitted.permissions) ? submitted.permissions : serverData.permissions || {},
      customSections: Array.isArray(submitted.customSections) ? submitted.customSections : serverData.customSections || [],
      userPermissions: role === "superadmin" && isPlainObject(submitted.userPermissions) ? submitted.userPermissions : serverData.userPermissions || {},
      shared: isPlainObject(submitted.shared) ? submitted.shared : serverData.shared || {},
      perUser: isPlainObject(submitted.perUser) ? submitted.perUser : serverData.perUser || {},
      activityLog: mergeActivityLog(serverData.activityLog, submitted.activityLog, () => true),
      // Privacy fields (Part B): ALWAYS carried forward from the server's existing state,
      // for every caller including admin/superadmin. These are only ever mutated by the
      // dedicated /privacy/* endpoints, which apply one narrow, validated, audited change at a
      // time — never by a generic "whole DB blob" save, even an admin's. This is what makes it
      // safe that a consent/request record can never be silently dropped, forged, or
      // overwritten by replaying/editing a saveAppData payload.
      ...privacyPassthrough(serverData),
    };
  }

  // Non-privileged (scoped) caller. Every control-plane / other-people's-data section is
  // silently dropped and the server's existing value wins instead — never a hard error, so a
  // scoped user's legitimate in-scope edits still get saved even though the rest of their
  // payload is ignored.
  const serverShared = serverData.shared || {};
  const submittedShared = isPlainObject(submitted.shared) ? submitted.shared : {};
  const downlineIds = linkedId ? getDownlineSupervisorIds(linkedId, serverShared.supervisors || []) : new Set();

  const mergedShared = {
    ...serverShared,
    supervisors: mergeScopedArray(serverShared.supervisors, submittedShared.supervisors, (s) => downlineIds.has(s.id)),
    coaches: mergeScopedArray(serverShared.coaches, submittedShared.coaches, (c) => downlineIds.has(c.supervisorId)),
    members: mergeScopedArray(
      serverShared.members,
      submittedShared.members,
      (m) =>
        downlineIds.has(m.supervisorId) ||
        (m.coachId && downlineIds.has((serverShared.coaches || []).find((c) => c.id === m.coachId)?.supervisorId))
    ),
    // transactions/gifts/custom/etc: not scoped anywhere client-side, so a scoped caller in
    // *shared* mode has never had an authorized-narrower view of them to safely diff against —
    // leave the server's copy untouched for these rather than risk a scoped caller clobbering
    // org-wide records they never actually saw filtered.
  };

  const serverPerUser = serverData.perUser || {};
  const submittedOwnBucket = isPlainObject(submitted.perUser) ? submitted.perUser[uid] : null;
  const mergedPerUser = {
    ...serverPerUser,
    [uid]: submittedOwnBucket && isPlainObject(submittedOwnBucket) ? submittedOwnBucket : serverPerUser[uid] || emptyPerUserBucket(),
  };

  // A non-privileged caller may NOT change any userPermissions entry, including their own. This used to
  // be allowed because the server never consulted userPermissions; now that resolveSectionPerm()
  // does, accepting a self-written override would be a self-service privilege escalation.
  const mergedUserPermissions = { ...(serverData.userPermissions || {}) };

  return {
    // Control-plane sections: server's copy always wins for a non-privileged caller.
    users: serverData.users || [],
    profiles: serverData.profiles || {},
    settings: serverData.settings || {},
    permissions: serverData.permissions || {},
    customSections: serverData.customSections || [],
    userPermissions: mergedUserPermissions,
    shared: mergedShared,
    perUser: mergedPerUser,
    // Append-only: a scoped caller may add new entries scoped to their own downline, but can
    // never remove or rewrite existing entries (matches "activityLog append-only behavior").
    activityLog: mergeActivityLog(serverData.activityLog, submitted.activityLog, (a) => a.scopeId && downlineIds.has(a.scopeId)),
    // See the full-access branch above for why these are always passed through untouched.
    ...privacyPassthrough(serverData),
  };
}

/** The six Part-B privacy fields, always taken verbatim from the server's existing state and
 * never from `submitted` — see the callers above for why. Centralized here so both branches of
 * mergeAuthorizedSave stay symmetric and a future field can't be added to one and forgotten in
 * the other. */
function privacyPassthrough(serverData) {
  return {
    privacyConsents: serverData.privacyConsents || {},
    policyVersions: serverData.policyVersions || [],
    policyAcceptances: serverData.policyAcceptances || {},
    privacyPreferences: serverData.privacyPreferences || {},
    privacyRequests: serverData.privacyRequests || [],
    privacyAuditLog: serverData.privacyAuditLog || [],
  };
}

/**
 * Merges a submitted array back onto the server array, but only for records the caller is
 * authorized for (per `inScope`). Existing out-of-scope records are always kept untouched, and
 * a submitted record can only be added/updated if the resulting (post-edit) record is itself
 * in-scope — this also blocks a scoped caller from "reassigning" a record out of their own
 * downline to escape future authorization.
 */
function mergeScopedArray(serverArr, submittedArr, inScope) {
  serverArr = Array.isArray(serverArr) ? serverArr : [];
  submittedArr = Array.isArray(submittedArr) ? submittedArr : [];
  const byId = new Map(serverArr.map((r) => [r.id, r]));
  const submittedById = new Map(submittedArr.filter((r) => r && r.id != null).map((r) => [r.id, r]));

  // Keep every out-of-scope server record exactly as-is, regardless of what the client sent
  // (or omitted — a scoped client's local copy never had these records to begin with).
  const result = serverArr.filter((r) => !inScope(r));

  // For in-scope ids: apply the submitted version if present and still in-scope after the
  // edit; otherwise (submitted omitted it => deleted, or edited-out-of-scope => rejected)
  // fall back to keeping the server version, EXCEPT a real client-side delete (submitted array
  // no longer contains an id that used to be in-scope) is honored, since that's indistinguishable
  // from an intentional delete within scope.
  const inScopeServerIds = new Set(serverArr.filter(inScope).map((r) => r.id));
  inScopeServerIds.forEach((id) => {
    const submittedRec = submittedById.get(id);
    if (submittedRec === undefined) return; // deleted by caller — do not carry it forward
    if (inScope(submittedRec)) result.push(submittedRec);
    else result.push(byId.get(id)); // attempted reassignment out of scope — reject the edit
  });

  // Brand-new records the caller added (id not present server-side at all): allowed only if
  // the new record itself is in-scope.
  submittedArr.forEach((rec) => {
    if (!rec || rec.id == null) return;
    if (byId.has(rec.id)) return; // already handled above
    if (inScope(rec)) result.push(rec);
  });

  return result;
}

/** Append-only merge: keep every existing entry, add only new, authorized entries. */
function mergeActivityLog(serverLog, submittedLog, canAppend) {
  serverLog = Array.isArray(serverLog) ? serverLog : [];
  submittedLog = Array.isArray(submittedLog) ? submittedLog : [];
  const known = new Set(serverLog.map((e) => activityKey(e)));
  const additions = submittedLog.filter((e) => e && !known.has(activityKey(e)) && canAppend(e));
  // New entries are unshifted client-side (most-recent-first) — keep that convention.
  return [...additions, ...serverLog];
}
function activityKey(e) {
  return `${e.ts}|${e.user}|${e.action}|${e.coll}|${e.name}|${e.scopeId || ""}`;
}

function isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

// ----------------------------------------------------------------------------------------------
// PHASE 6 FIX (privilege-escalation guard on the generic /data/save path):
//
// userPin.js's authorizeSetUserPin() enforces two invariants for the dedicated /user/setPin
// endpoint: (1) only a superadmin caller may grant the "superadmin" role to anyone, and (2) a
// non-superadmin (plain "admin") caller may never modify an existing superadmin's record at all.
// Before this fix, mergeAuthorizedSave's full-access branch above accepted `submitted.users`
// completely as-is for ANY full-access caller (admin OR superadmin), with no equivalent check —
// so a caller with only "admin" claims could bypass both invariants simply by calling
// POST /data/save with a hand-edited `users` array (e.g. setting their own record's `role` to
// "superadmin", or rewriting an existing superadmin's row) instead of going through
// /user/setPin. This does not by itself forge a Firebase ID token or its `role` custom claim
// (which is what authenticateRequest actually trusts for the CURRENT request's authorization),
// but it corrupts the authoritative `users` control-plane list that (a) the login endpoint falls
// back to for role assignment whenever a credentials-doc entry's `role` is ever missing
// (`entry.role || user.role` in handleLogin), (b) downline/scope computations and the admin UI
// read as ground truth, and (c) is the exact invariant /user/setPin exists to protect — so
// leaving one write path enforcing it and the other not is a real, exploitable inconsistency for
// any account with mere "admin" claims (a lower-trust role than "superadmin" by design).
//
// Fix: apply the SAME two invariants here, mirroring authorizeSetUserPin's rules exactly, so a
// non-superadmin full-access caller can freely edit ordinary users' non-role-sensitive fields
// (matching existing admin capabilities) but can never (a) introduce or keep a "superadmin"-role
// record, or (b) modify any existing superadmin's record in any way — both silently revert to
// the server's existing value rather than hard-failing the whole save, consistent with this
// function's existing "silently drop what you're not authorized to change" convention.
function sanitizeUsersForFullAccessSave(serverUsers, submittedUsers, callerRole) {
  serverUsers = Array.isArray(serverUsers) ? serverUsers : [];
  if (callerRole === "superadmin") {
    // Superadmin is the top of the hierarchy — no additional restriction beyond "must be an array".
    return Array.isArray(submittedUsers) ? submittedUsers : serverUsers;
  }
  if (!Array.isArray(submittedUsers)) return serverUsers;

  const serverById = new Map(serverUsers.map((u) => [u && u.id, u]));
  const result = [];
  const seen = new Set();

  submittedUsers.forEach((u) => {
    if (!u || u.id == null) return;
    seen.add(u.id);
    const existing = serverById.get(u.id);
    if (existing && existing.role === "superadmin") {
      // Existing superadmin record: a plain admin caller may not change it at all — keep the
      // server's version untouched (mirrors "insufficient clearance to edit a superadmin
      // account").
      result.push(existing);
      return;
    }
    if (u.role === "superadmin") {
      // Attempt to grant/keep superadmin on a non-superadmin (or brand-new) record — reject just
      // this role change, falling back to the server's existing role for that record (mirrors
      // "only superadmin may grant the superadmin role"). For a brand-new record this means it
      // is dropped to role "user" rather than superadmin, never silently discarded entirely.
      result.push(existing ? { ...u, role: existing.role } : { ...u, role: "user" });
      return;
    }
    result.push(u);
  });

  // Any existing user the caller's payload omitted entirely (e.g. a stale/partial client-side
  // copy) is preserved as-is — the non-privileged branch below already treats omission as
  // intentional deletion for scoped callers, but the full-access branch has always trusted the
  // submitted array as the complete list; a superadmin-protected record must never disappear
  // just because an admin's payload didn't include it.
  serverUsers.forEach((u) => {
    if (u && u.role === "superadmin" && !seen.has(u.id)) result.push(u);
  });

  return result;
}
