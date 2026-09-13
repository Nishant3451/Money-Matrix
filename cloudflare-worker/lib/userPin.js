// ============================================================================================
// Authorization decision for the setUserPin endpoint. This is a straight, faithful translation
// of gates that already exist in index.html's UI code (delUser, saveUser, userModal,
// confirmSupervisorPromotion — search for isSuperAdmin()/isAdmin() in those functions) into a
// real server-side enforcement. Those client checks were previously only cosmetic (hiding
// buttons); nothing stopped a modified client from calling the callable directly with different
// arguments. This function is what makes them load-bearing.
//
// Operations:
//   - "self":   caller changes their own PIN. Requires currentPin to verify against the
//               existing hash (mirrors the Settings > Change PIN currentPin field).
//   - "create": caller (must be admin/superadmin) provisions a brand-new account.
//   - "update": caller (must be admin/superadmin) changes an existing OTHER user's PIN/role/
//               username, or a superadmin renaming their own username.
//   - "delete": caller (must be admin/superadmin) removes an existing OTHER user's account.
// ============================================================================================

export function isFullAccessRole(role) {
  return role === "superadmin" || role === "admin";
}

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
    if (targetUser.role === "superadmin") return { ok: false, error: "superadmin is protected" };
    if (targetUser.role === "admin" && caller.role !== "superadmin") {
      return { ok: false, error: "insufficient clearance to delete admin" };
    }
    return { ok: true, op: "delete" };
  }

  // --- Create (target doesn't exist yet) -------------------------------------------------------
  if (!targetUser) {
    const newRole = payload?.role || "user";
    if (newRole === "superadmin" && caller.role !== "superadmin") {
      return { ok: false, error: "only superadmin may grant the superadmin role" };
    }
    if (!payload?.newPin) return { ok: false, error: "newPin is required to create an account" };
    return { ok: true, op: "create" };
  }

  // --- Update an existing OTHER user -----------------------------------------------------------
  if (targetUser.role === "superadmin" && caller.role !== "superadmin") {
    return { ok: false, error: "insufficient clearance to edit a superadmin account" };
  }
  const newRole = payload?.role;
  if (newRole && newRole === "superadmin" && caller.role !== "superadmin") {
    return { ok: false, error: "only superadmin may grant the superadmin role" };
  }
  if (payload?.renameFrom && caller.role !== "superadmin") {
    return { ok: false, error: "only superadmin may rename a login username" };
  }
  return { ok: true, op: "update" };
}
