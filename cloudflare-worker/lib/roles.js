// ============================================================================================
// Role hierarchy helpers (pure; no I/O).
//
//     developer  >  superadmin  >  admin  >  everything else (supervisors / ordinary users)
//
// The role of a caller is NEVER read from a request body. It comes from the verified ID token's `role`
// claim, demoted (never raised) to the stored users[] record's role by effectiveRole() in authorization.js.
// The "developer" role in particular can only be created by the one-time /developer/bootstrap operation (see
// login-worker.js); no /data/save, /user/setPin or import path can grant it.
// ============================================================================================

export const ROLE_DEVELOPER = "developer";
export const ROLE_SUPERADMIN = "superadmin";
export const ROLE_ADMIN = "admin";

const ROLE_RANK = Object.freeze({ developer: 3, superadmin: 2, admin: 1 });

export const hasOwn = (o, k) => !!o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);

/** 3 developer, 2 superadmin, 1 admin, 0 anything else (including unknown / non-string values). */
export function roleRank(role) {
  return typeof role === "string" && hasOwn(ROLE_RANK, role) ? ROLE_RANK[role] : 0;
}

export const isDeveloperRole = (role) => role === ROLE_DEVELOPER;
/** Superadmin OR above: the "control plane" roles (permissions matrix, individual access, full account management). */
export const isSuperRole = (role) => role === ROLE_SUPERADMIN || role === ROLE_DEVELOPER;
/** Roles that receive the unfiltered control-plane view (users list, every perUser bucket ...). */
export const isFullAccessRole = (role) => role === ROLE_DEVELOPER || role === ROLE_SUPERADMIN || role === ROLE_ADMIN;

/** A user record that is switched off. Fail closed: only an explicit `disabled === true` counts as active-off, but a
 *  record must also be a plain object to count as an active user at all. */
export const isDisabledUser = (u) => !!u && typeof u === "object" && u.disabled === true;
export const isActiveUser = (u) => !!u && typeof u === "object" && !Array.isArray(u) && typeof u.id === "string" && !!u.id && u.disabled !== true;
