// ============================================================================================
// DPDP-ready privacy system — shared schema, validation, and helpers.
//
// SCOPE / HONESTY NOTE: this app does not currently run any analytics, marketing, or tracking
// SDK (verified by source audit of index.html — no gtag/Analytics/Pixel/Sentry/Mixpanel/Hotjar
// and no such script tags). So the only real "processing category" today is the essential
// account/business data the app needs to function. The consent/preferences model below is
// still built generically (arbitrary category keys, versioned, withdrawable) so a REAL future
// optional processor can be added without redesigning this file — but PRIVACY_PREFERENCE_KEYS
// intentionally ships with only "essential" until something optional actually exists. Do not
// add fake categories here to make the UI look more complete.
//
// STORAGE MODEL: this app has exactly one Firestore document that holds all app data
// (moneymatrix/appData, a single JSON string field — see googleFirestore.js). There is no
// separate "privacy" collection to create. The fields below are simply new top-level keys
// inside that same JSON blob:
//
//   privacyConsents:     { [uid]: ConsentRecord[] }
//   policyVersions:      PolicyVersion[]                 (all versions ever published; draft or
//                                                          published — draft is admin-only)
//   policyAcceptances:   { [uid]: { [policyType]: { version, timestamp } } }
//   privacyPreferences:  { [uid]: { essential: true, ... } }
//   privacyRequests:     PrivacyRequest[]
//   privacyAuditLog:     AuditEntry[]                     (append-only, admin-only to read)
//
// CRITICAL: none of these fields are ever written via the generic /data/save endpoint —
// authorization.js's mergeAuthorizedSave explicitly carries them forward unchanged for every
// caller, admin included. They are only ever mutated by the dedicated /privacy/* handlers in
// login-worker.js, each of which re-reads the authoritative document, applies one narrowly
// scoped change, and writes the whole document back — matching the exact pattern already used
// by handleSetUserPin. This keeps the "never trust client-supplied identity/authorization" rule
// intact: every mutation below derives `uid`/`role` from the verified ID token, never from the
// request body.
// ============================================================================================

export const PRIVACY_REQUEST_CATEGORIES = [
  "access",
  "correction",
  "deletion",
  "consent_question",
  "complaint",
  "security_concern",
  "other",
];

export const PRIVACY_REQUEST_STATUSES = [
  "requested",
  "under_review",
  "approved",
  "rejected",
  "completed",
  "partially_completed",
];

const TERMINAL_STATUSES = new Set(["completed", "rejected", "partially_completed"]);

export const POLICY_TYPES = ["privacy_policy", "terms_of_service", "cookie_policy", "refund_policy"];

// Only "essential" is real today (see module comment). Any other key submitted by a client is
// rejected rather than silently accepted, so the server never records consent for a category
// that doesn't correspond to real processing.
export const PRIVACY_PREFERENCE_KEYS = ["essential"];

// CONSENT CATEGORY ALLOW-LIST (Hardening Correction — Consent API integrity): the server is the
// sole authority on which {type, purpose} pairs correspond to real, optional processing in this
// application. Without this list, a direct API caller (bypassing the UI entirely) could POST
// /privacy/consent with any arbitrary type/purpose string and the server would happily record a
// "consent" for a processing category that doesn't exist -- which is itself a privacy-integrity
// problem (a fabricated consent record is misleading in either direction: it could later be
// pointed to as "proof" a user consented to something that was never actually processed, or
// used to claim ordinary/essential processing was somehow optional).
//
// This application currently performs NO optional processing that consent could meaningfully
// apply to -- only essential/account-functionality processing, which is mandatory and is
// deliberately NOT represented as a consent record (see index.html's privacyConsentHtml(), which
// shows essential as an always-on, non-togglable item, never a consent entry). So per the
// hardening brief -- "if there is no optional consent category today, the safest implementation
// is to reject arbitrary consent creation rather than inventing one" -- this allow-list is
// intentionally EMPTY. Every /privacy/consent grant attempt is rejected until a genuine optional
// processing category is added here (and, at the same time, a real UI control for it is wired up
// in index.html -- never the other way around: never add a category here before the processing
// it names actually exists).
export const KNOWN_CONSENT_CATEGORIES = [
  // { type: "...", purpose: "..." }
];

export function isKnownConsentCategory(type, purpose, categories = KNOWN_CONSENT_CATEGORIES) {
  return categories.some((c) => c.type === type && c.purpose === purpose);
}

export const MAX_DESCRIPTION_LENGTH = 4000;
export const MAX_NOTE_LENGTH = 4000;
export const MAX_REQUESTS_PER_WINDOW = 8;
export const REQUEST_WINDOW_MS = 60 * 60 * 1000; // 1 hour
export const MAX_EXPORTS_PER_WINDOW = 5;
export const EXPORT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
// Phase 5 audit item #12: /privacy/consent, /privacy/policy/accept, and /privacy/preferences
// previously had no rate limiting at all (see PART-B-HARDENING-REPORT.md §14, "Remaining
// limitations" -- an authenticated user spamming their own consent/preference endpoint was
// disclosed as low-severity but real). These are ordinary authenticated user actions (not
// abuse-prone in the way exports/requests are), so the limit is generous -- it exists to cap
// the theoretical spam case, not to interfere with normal use.
export const MAX_PRIVACY_WRITES_PER_WINDOW = 60;
export const PRIVACY_WRITE_WINDOW_MS = 60 * 60 * 1000; // 1 hour

export function genId(prefix) {
  // crypto.randomUUID() is available in the Workers runtime.
  return `${prefix}_${crypto.randomUUID()}`;
}

export function nowTs() {
  return Date.now();
}

/** Trims, coerces to string, and hard-caps length. Never throws — returns "" for anything that
 * isn't a usable string, so callers can validate emptiness explicitly. */
export function sanitizeText(value, maxLen) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed.slice(0, maxLen);
}

export function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

/** Simple per-key sliding-window rate limiter reusing the same RATE_LIMIT_KV binding the login
 * endpoint already uses. Kept independent of login-worker.js's login-specific lockout logic
 * (different shape: a hard cap per window, not progressive lockout) since privacy-endpoint abuse
 * (e.g. spamming export/request creation) is a different threat than credential stuffing. */
async function rateLimitKey(kind, uid) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${kind}:${uid}`));
  const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `rl:privacy:${hex}`;
}

/** Returns { allowed, misconfigured? }. HARDENING ISSUE #3: this used to fail OPEN (return
 * `{ allowed: true }`) whenever the RATE_LIMIT_KV binding was missing, which meant a
 * misconfigured deployment would silently accept an unlimited number of privacy
 * requests/exports -- a real abuse vector, not just a cosmetic gap. It now fails CLOSED instead:
 * a missing binding is reported back as `{ allowed: false, misconfigured: true }` so the caller
 * can return a controlled 503 ("temporarily unavailable") rather than either (a) crashing the
 * Worker, (b) leaking why to the client, or (c) silently behaving as if rate limiting existed.
 * See login-worker.js's createPrivacyRequest / handlePrivacyExport for how this is surfaced. */
export async function checkAndReserveRateLimit(env, kind, uid, maxPerWindow, windowMs) {
  if (!env.RATE_LIMIT_KV) return { allowed: false, misconfigured: true };
  const key = await rateLimitKey(kind, uid);
  const now = Date.now();
  const state = (await env.RATE_LIMIT_KV.get(key, "json")) || { count: 0, windowStart: now };
  const windowState = now - state.windowStart > windowMs ? { count: 0, windowStart: now } : state;
  if (windowState.count >= maxPerWindow) return { allowed: false };
  windowState.count += 1;
  await env.RATE_LIMIT_KV.put(key, JSON.stringify(windowState), {
    expirationTtl: Math.ceil(windowMs / 1000) + 60,
  });
  return { allowed: true };
}

/** Appends one entry to the append-only privacy audit log. Identity comes from the verified
 * caller (`uid`/`role`), never the request body — callers of this helper must have already
 * authenticated the request. Display-name-style fields are NOT the identity source; `uid` is. */
export function appendAudit(appData, { uid, role, action, detail }) {
  const log = Array.isArray(appData.privacyAuditLog) ? appData.privacyAuditLog : [];
  const entry = { id: genId("aud"), ts: nowTs(), uid, actorRole: role, action, detail: detail || null };
  // Most-recent-first, matching the existing activityLog convention.
  appData.privacyAuditLog = [entry, ...log].slice(0, 5000); // hard cap so this can never grow unbounded
  return appData;
}

export function getUserRequests(privacyRequests, uid) {
  return (Array.isArray(privacyRequests) ? privacyRequests : []).filter((r) => r.uid === uid);
}

export function findPublishedPolicy(policyVersions, policyType, version) {
  return (Array.isArray(policyVersions) ? policyVersions : []).find(
    (p) => p.type === policyType && p.version === version && p.status === "published"
  );
}

export function latestPublishedPolicy(policyVersions, policyType) {
  const matches = (Array.isArray(policyVersions) ? policyVersions : [])
    .filter((p) => p.type === policyType && p.status === "published")
    .sort((a, b) => (b.effectiveDate || "").localeCompare(a.effectiveDate || ""));
  return matches[0] || null;
}

export function isValidStatusTransition(from, to) {
  if (!PRIVACY_REQUEST_STATUSES.includes(to)) return false;
  if (TERMINAL_STATUSES.has(from)) return false; // terminal states are final
  return true;
}

// -------------------------------------------------------------------------------------------
// CSV export safety (spreadsheet formula injection). Any field beginning with =, +, -, @, TAB,
// or CR is prefixed with a leading apostrophe so spreadsheet software treats it as literal text
// instead of a formula. This mirrors the OWASP-recommended mitigation.
// -------------------------------------------------------------------------------------------
const CSV_DANGEROUS_LEAD = /^[=+\-@\t\r]/;

export function csvSafeField(value) {
  let s = value === null || value === undefined ? "" : String(value);
  if (CSV_DANGEROUS_LEAD.test(s)) s = "'" + s;
  // Standard CSV quoting: wrap in quotes if it contains a comma, quote, or newline; double any
  // embedded quotes.
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

export function toCsv(rows, columns) {
  const header = columns.map((c) => csvSafeField(c)).join(",");
  const body = rows
    .map((row) => columns.map((c) => csvSafeField(row[c])).join(","))
    .join("\r\n");
  return header + "\r\n" + body;
}
