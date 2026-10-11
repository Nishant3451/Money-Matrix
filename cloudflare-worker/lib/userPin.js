// ============================================================================================
// Authorization decision for the setUserPin endpoint. This is a straight, faithful translation
// of gates that already exist in index.html's UI code (delUser, saveUser, userModal,
// confirmSupervisorPromotion — search for isSuperAdmin()/isAdmin() in those functions) into a
// real server-side enforcement. Those client checks were previously only cosmetic (hiding
// buttons); nothing stopped a modified client from calling the callable directly with different
// arguments. This function is what makes them load-bearing.
//
// ROLE HIERARCHY (roles.js):  developer > superadmin > admin > everything else.
//   * Nobody can create, promote-to or delete the "developer" role here; the Developer is created ONLY by /developer/bootstrap and
//     no other account can change or remove it (the Developer can still change its own PIN through the "self" operation).
//   * Only the Developer may create, promote, demote, reset or delete a SUPERADMIN account.
//   * Admins can still only be deleted by a superadmin or above.
//
// Operations:
//   - "self":   caller changes their own PIN. Requires currentPin to verify against the
//               existing hash (mirrors the Settings > Change PIN currentPin field).
//   - "create": caller (must be admin/superadmin) provisions a brand-new account.
//   - "update": caller (must be admin/superadmin) changes an existing OTHER user's PIN/role/
//               username, or a superadmin renaming their own username.
//   - "delete": caller (must be admin/superadmin) removes an existing OTHER user's account.
// ============================================================================================

import { isFullAccessRole, roleRank, isSuperRole, ROLE_DEVELOPER, ROLE_SUPERADMIN } from "./roles.js";
export { isFullAccessRole };

/**
 * @param {{uid:string, role:string}} caller        resolved server-side from the verified ID
 *                                                    token's claims — never from the request body
 * @param {object|null} targetUser                   the existing DB.users entry for
 *                                                    payload.targetUserId, or null if it doesn't
 *                                                    exist yet (a create)
 * @param {object} payload                            the request body
 *                                                    { targetUserId, newPin, currentPin, role,
 *                                                      renameFrom, delete }
 * @returns {{ok:true, op:string}|{ok:false, error:string}}
 */
export function authorizeSetUserPin(caller, targetUser, payload) {
  const targetUserId = String(payload?.targetUserId || "").trim();
  if (!targetUserId) return { ok: false, error: "targetUserId is required" };

  const isSelf = targetUserId === caller.uid;
  const callerFullAccess = isFullAccessRole(caller.role);

  // --- Self-service PIN change ---------------------------------------------------------------
  if (isSelf && !payload?.delete) {
    if (!targetUser) return { ok: false, error: "account not found" };
    if (!payload?.newPin) return { ok: false, error: "newPin is required" };
    if (!payload?.currentPin) return { ok: false, error: "currentPin is required to change your own PIN" };
    // A caller can never grant themselves a new role or rename themselves through the
    // self-service path (mirrors "!isSuperAdmin() && u.id===currentUser.id => role stays put"
    // and username being disabled for a non-superadmin editing their own row).
    return { ok: true, op: "self" };
  }

  // Every remaining operation targets SOMEONE ELSE (or a self-delete attempt, which is always
  // rejected below) and therefore requires admin/superadmin, full stop — mirrors every
  // management screen (Users, rank promotion) being gated behind isAdmin()/isSuperAdmin().
  if (!callerFullAccess) {
    return { ok: false, error: "insufficient privileges" };
  }

  // --- Delete ---------------------------------------------------------------------------------
  if (payload?.delete) {
    if (isSelf) return { ok: false, error: "cannot delete your own active session" }; // mirrors delUser's id===currentUser.id guard
    if (!targetUser) return { ok: false, error: "account not found" };
    if (targetUser.role === ROLE_DEVELOPER) return { ok: false, error: "developer is protected" };
    if (targetUser.role === ROLE_SUPERADMIN) {
      if (caller.role !== ROLE_DEVELOPER) return { ok: false, error: "only the developer may remove a superadmin" };
      return { ok: true, op: "delete" };
    }
    if (targetUser.role === "admin" && !isSuperRole(caller.role)) {
      return { ok: false, error: "insufficient clearance to delete admin" };
    }
    return { ok: true, op: "delete" };
  }

  // --- Create (target doesn't exist yet) -------------------------------------------------------
  if (!targetUser) {
    const newRole = payload?.role || "user";
    if (newRole === ROLE_DEVELOPER) return { ok: false, error: "the developer role cannot be granted" };
    if (newRole === ROLE_SUPERADMIN && caller.role !== ROLE_DEVELOPER) {
      return { ok: false, error: "only the developer may grant the superadmin role" };
    }
    if (roleRank(newRole) >= roleRank(caller.role) && roleRank(newRole) >= 2 && caller.role !== ROLE_DEVELOPER) {
      return { ok: false, error: "insufficient clearance to grant that role" };
    }
    if (!payload?.newPin) return { ok: false, error: "newPin is required to create an account" };
    return { ok: true, op: "create" };
  }

  // --- Update an existing OTHER user -----------------------------------------------------------
  if (targetUser.role === ROLE_DEVELOPER) return { ok: false, error: "developer is protected" };
  if (targetUser.role === ROLE_SUPERADMIN && caller.role !== ROLE_DEVELOPER) {
    return { ok: false, error: "only the developer may change a superadmin account" };
  }
  const newRole = payload?.role;
  if (newRole && newRole === ROLE_DEVELOPER) return { ok: false, error: "the developer role cannot be granted" };
  if (newRole && newRole === ROLE_SUPERADMIN && caller.role !== ROLE_DEVELOPER) {
    return { ok: false, error: "only the developer may grant the superadmin role" };
  }
  if (payload?.renameFrom && !isSuperRole(caller.role)) {
    return { ok: false, error: "only superadmin may rename a login username" };
  }
  return { ok: true, op: "update" };
}
