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
export function buildAuthorizedView(fullData, caller) {
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
  };
  return out;
}

export function emptyPerUserBucket() {
  return { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], custom: {}, products: [], quotations: [] };
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
  const { uid, role, linkedId } = caller;
  const full = isFullAccessRole(role);
  submitted = submitted && typeof submitted === "object" ? submitted : {};

  if (full) {
    // Superadmin/admin are the server-verified control plane — apply their save as-is, but
    // still never trust anything about the caller's OWN identity/role from the body, and never
    // let even an admin overwrite the credentials doc (that's a separate document entirely and
    // is never part of appData in the first place).
    return {
      users: Array.isArray(submitted.users) ? submitted.users : serverData.users || [],
      profiles: isPlainObject(submitted.profiles) ? submitted.profiles : serverData.profiles || {},
      settings: isPlainObject(submitted.settings) ? submitted.settings : serverData.settings || {},
      permissions: isPlainObject(submitted.permissions) ? submitted.permissions : serverData.permissions || {},
      customSections: Array.isArray(submitted.customSections) ? submitted.customSections : serverData.customSections || [],
      userPermissions: isPlainObject(submitted.userPermissions) ? submitted.userPermissions : serverData.userPermissions || {},
      shared: isPlainObject(submitted.shared) ? submitted.shared : serverData.shared || {},
      perUser: isPlainObject(submitted.perUser) ? submitted.perUser : serverData.perUser || {},
      activityLog: mergeActivityLog(serverData.activityLog, submitted.activityLog, () => true),
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

  const submittedOwnOverride = isPlainObject(submitted.userPermissions) ? submitted.userPermissions[uid] : null;
  const mergedUserPermissions = { ...(serverData.userPermissions || {}) };
  if (isPlainObject(submittedOwnOverride)) mergedUserPermissions[uid] = submittedOwnOverride;

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
