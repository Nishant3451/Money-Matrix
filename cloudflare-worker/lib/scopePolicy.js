// ============================================================================================
// DEVELOPER-CONTROLLED DATA SCOPE POLICY (pure; no I/O).
//
// Stored (server-owned; /data/save can never carry it -- see privacyPassthrough in authorization.js) as
//
//   appData.scopePolicy = {
//     rev: <integer>,                                   // bumped on every change; stale requests are refused
//     global: { superadminAll: <boolean> },             // false => NO superadmin may use "All Data"
//     users:  { [uid]: { upline?: boolean, downline?: boolean, all?: boolean } },
//   }
//
// A policy can ONLY NARROW what the role + the verified hierarchy already allow. It can never add a scope option, never
// grant "All Data" to anyone below superadmin, and it never applies to the Developer (the Developer cannot be locked out).
//   * "mine" is always available (it is the caller's own data).
//   * upline:false / downline:false removes that hierarchy direction from the caller's scope options AND from the
//     ceilings the record layer enforces (viewOwners / writeOwners), so it narrows real authority, not just a dropdown.
//   * all:false (or global.superadminAll:false) takes "All Data" away from a superadmin; that account then behaves like
//     any other hierarchy-scoped account for Payments and Quotations.
// Absent policy / absent keys = the default behaviour, unchanged. A policy that is present but malformed FAILS CLOSED
// (no upline, no downline, no superadmin "All Data") rather than silently granting anything.
// ============================================================================================
import { hasOwn } from "./roles.js";

export const MAX_POLICY_USERS = 500;
export const MAX_POLICY_REV = 2_000_000_000;
const MAX_UID_LENGTH = 128;
const POLICY_KEYS = Object.freeze(["upline", "downline", "all"]);
const isPlainObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const sameKeySet = (obj, keys) => { const k = Object.keys(obj); return k.length === keys.length && keys.every((x) => hasOwn(obj, x)); };

/** @returns {{kind:"default"}|{kind:"invalid"}|{kind:"ok", rev:number, global:{superadminAll:boolean}, users:Map<string,object>}} */
export function parseScopePolicy(raw) {
  if (raw === undefined || raw === null) return { kind: "default", rev: 0, global: { superadminAll: true }, users: new Map() };
  if (!isPlainObject(raw) || !sameKeySet(raw, ["rev", "global", "users"])) return { kind: "invalid" };
  if (!Number.isInteger(raw.rev) || raw.rev < 0 || raw.rev > MAX_POLICY_REV) return { kind: "invalid" };
  if (!isPlainObject(raw.global) || !sameKeySet(raw.global, ["superadminAll"]) || typeof raw.global.superadminAll !== "boolean") return { kind: "invalid" };
  if (!isPlainObject(raw.users)) return { kind: "invalid" };
  const entries = Object.entries(raw.users);
  if (entries.length > MAX_POLICY_USERS) return { kind: "invalid" };
  const users = new Map();
  for (const [uid, p] of entries) {
    if (!uid || uid.length > MAX_UID_LENGTH || !isPlainObject(p)) return { kind: "invalid" };
    const keys = Object.keys(p);
    if (keys.length < 1 || keys.some((k) => !POLICY_KEYS.includes(k) || typeof p[k] !== "boolean")) return { kind: "invalid" };
    users.set(uid, { ...p });
  }
  return { kind: "ok", rev: raw.rev, global: { superadminAll: raw.global.superadminAll }, users };
}

/** Plain-JSON form of a parsed policy (what is stored). */
export function serializeScopePolicy(parsed) {
  const users = {};
  for (const uid of [...parsed.users.keys()].sort()) users[uid] = { ...parsed.users.get(uid) };
  return { rev: parsed.rev, global: { superadminAll: parsed.global.superadminAll }, users };
}

/**
 * What the policy lets THIS caller keep. Developer: everything (policy never applies). Everyone else: narrowing only.
 * @returns {{upline:boolean, downline:boolean, allAllowed:boolean}}  (allAllowed is only ever true for a superadmin/developer)
 */
export function effectivePolicyFor(rawPolicy, uid, role) {
  if (role === "developer") return { upline: true, downline: true, allAllowed: true };
  const p = parseScopePolicy(rawPolicy);
  const isSuperadmin = role === "superadmin";
  if (p.kind === "invalid") return { upline: false, downline: false, allAllowed: false }; // fail closed
  const mine = typeof uid === "string" && p.users.has(uid) ? p.users.get(uid) : {};
  return {
    upline: mine.upline !== false,
    downline: mine.downline !== false,
    allAllowed: isSuperadmin && p.global.superadminAll !== false && mine.all !== false,
  };
}

/**
 * Validates a Developer's request to set one user's policy. `policy` is an object with any of upline/downline/all
 * (booleans), or null to reset that user to the default. Returns {ok:true, entry|null} or {ok:false}.
 * `all` may only be CONFIGURED for a superadmin account, and only to narrow (false) -- true is accepted as "default".
 */
export function validateUserPolicyInput(policy, targetRole) {
  if (policy === null) return { ok: true, entry: null };
  if (!isPlainObject(policy)) return { ok: false };
  const keys = Object.keys(policy);
  if (keys.length < 1 || keys.some((k) => !POLICY_KEYS.includes(k) || typeof policy[k] !== "boolean")) return { ok: false };
  if (hasOwn(policy, "all") && targetRole !== "superadmin") return { ok: false }; // All Data is never configurable for admin/user, and not applicable to the developer
  const entry = {};
  for (const k of POLICY_KEYS) if (hasOwn(policy, k)) entry[k] = policy[k];
  // `true` is the default for every key, so drop it: the stored policy only ever lists RESTRICTIONS.
  for (const k of Object.keys(entry)) if (entry[k] === true) delete entry[k];
  return { ok: true, entry: Object.keys(entry).length ? entry : null };
}

/** The policy as the Developer's console sees it: the stored policy in plain-JSON form, the default when absent, and
 *  `invalid: true` (with a default-shaped body, rev 0) when what is stored is malformed -- the Developer can overwrite it. */
export function scopePolicyForDeveloper(raw) {
  const p = parseScopePolicy(raw);
  if (p.kind === "invalid") return { rev: 0, global: { superadminAll: true }, users: {}, invalid: true };
  return serializeScopePolicy(p);
}

/**
 * Applies a Developer's change to the stored policy. `change` = { baseRev, global?: {superadminAll:boolean},
 * user?: { uid, policy: object|null } } -- at least one of `global` / `user`.
 * `targetRoleOf(uid)` returns the stored role of an existing account or null (unknown accounts are refused).
 * A stale baseRev is refused (409) so an old console cannot overwrite a newer policy; a malformed STORED policy counts as rev 0
 * so the Developer can always repair it.
 * @returns {{error:{status,code,message,extra?}}|{policy:object, changed:boolean}}
 */
export function computePolicyUpdate(rawPolicy, change, targetRoleOf) {
  const bad = (status, code, message, extra) => ({ error: { status, code, message, ...(extra || {}) } });
  if (!isPlainObject(change)) return bad(400, "POLICY_INVALID", "The policy change is not valid");
  const keys = Object.keys(change);
  if (keys.some((k) => !["baseRev", "global", "user"].includes(k)) || !hasOwn(change, "baseRev")) return bad(400, "POLICY_INVALID", "The policy change is not valid");
  if (!hasOwn(change, "global") && !hasOwn(change, "user")) return bad(400, "POLICY_INVALID", "The policy change is not valid");
  if (!Number.isInteger(change.baseRev) || change.baseRev < 0 || change.baseRev > MAX_POLICY_REV) return bad(400, "POLICY_INVALID", "The policy change is not valid");
  const parsed = parseScopePolicy(rawPolicy);
  const cur = parsed.kind === "ok" ? parsed : { rev: 0, global: { superadminAll: true }, users: new Map() };
  if (change.baseRev !== cur.rev) return bad(409, "POLICY_STALE", "The scope policy changed since you loaded it", { currentRev: cur.rev });
  if (cur.rev >= MAX_POLICY_REV) return bad(409, "POLICY_REV_EXHAUSTED", "The scope policy cannot be changed further");
  const next = { rev: cur.rev + 1, global: { ...cur.global }, users: new Map(cur.users) };
  if (hasOwn(change, "global")) {
    const g = change.global;
    if (!isPlainObject(g) || !sameKeySet(g, ["superadminAll"]) || typeof g.superadminAll !== "boolean") return bad(400, "POLICY_INVALID", "The policy change is not valid");
    next.global.superadminAll = g.superadminAll;
  }
  if (hasOwn(change, "user")) {
    const u = change.user;
    if (!isPlainObject(u) || !sameKeySet(u, ["uid", "policy"]) || typeof u.uid !== "string" || !u.uid || u.uid.length > MAX_UID_LENGTH) return bad(400, "POLICY_INVALID", "The policy change is not valid");
    const role = targetRoleOf(u.uid);
    if (role === null) return bad(404, "POLICY_TARGET_NOT_FOUND", "That account does not exist");
    if (role === "developer") return bad(403, "POLICY_TARGET_DEVELOPER", "The Developer's access cannot be restricted");
    const v = validateUserPolicyInput(u.policy, role);
    if (!v.ok) return bad(400, "POLICY_INVALID", "That policy is not valid for this account");
    if (v.entry === null) next.users.delete(u.uid); else next.users.set(u.uid, v.entry);
    if (next.users.size > MAX_POLICY_USERS) return bad(400, "POLICY_INVALID", "Too many per-account policies");
  }
  const serialized = serializeScopePolicy(next);
  const before = serializeScopePolicy(cur);
  const sameAsBefore = JSON.stringify({ g: before.global, u: before.users }) === JSON.stringify({ g: serialized.global, u: serialized.users }) && parsed.kind !== "invalid";
  if (sameAsBefore) return { policy: before, changed: false };
  return { policy: serialized, changed: true };
}
