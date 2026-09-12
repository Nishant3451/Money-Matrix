const functions = require("firebase-functions");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
admin.initializeApp();

const db = admin.firestore();
const CRED_DOC = db.doc("moneymatrix/credentials");
const APP_DOC = db.doc("moneymatrix/appData");
// A tiny, non-sensitive document every approved client can read directly and listen to live —
// just a timestamp, bumped on every successful write. It's what keeps the app feeling
// real-time without ever letting the client read the actual (unfiltered) data directly. See
// getAppData()/saveAppData() below and the "real-time sync" note in firestore.rules.
const META_DOC = db.doc("moneymatrix/meta");

const BCRYPT_ROUNDS = 10;

// ============================================================================================
// PHASE 5 FINDING 1 — bcrypt/bcryptjs 72-byte input truncation.
//
// bcrypt (and bcryptjs, used here) silently truncates its input to 72 bytes before hashing —
// anything beyond byte 72 is simply ignored, both when hashing and when comparing. Today this
// is harmless in practice: every real PIN in this app is 4-6 numeric digits (see the login
// screen's maxlength=6), nowhere near 72 bytes. But nothing server-side enforced an upper
// bound — only a lower one (`length < 4`) — and several admin-facing inputs (`u_pin`, `s_new`,
// `promo_pin`) had no client-side maxlength either. If a caller (a careless paste, a script
// calling setUserPin directly, or a future UI change) ever set a PIN longer than 72 bytes, two
// different PINs that merely share the same first 72 bytes would hash identically and both
// would authenticate — an ambiguity, not a break of the current system, since no such PIN
// exists today, but worth closing off at the source rather than leaving it possible.
//
// FIX: reject any PIN over MAX_PIN_LENGTH characters outright, well before it ever reaches
// bcrypt. 16 characters is chosen so that even in the worst case (every character a 4-byte
// UTF-8 code point) the byte length (64) stays safely under bcrypt's 72-byte limit — so no
// accepted PIN can ever be silently truncated, not just no accepted *numeric* PIN. This is a
// pure upper bound alongside the existing lower bound; it cannot invalidate any PIN that could
// ever have been legitimately set, since every real credential in this system is far shorter.
const MAX_PIN_LENGTH = 16;
function assertPinLength(pin) {
  if (pin.length > MAX_PIN_LENGTH) {
    throw new functions.https.HttpsError("invalid-argument", `PIN must be at most ${MAX_PIN_LENGTH} characters`);
  }
}

// crypto.randomInt is a CSPRNG (uses the OS's secure random source), unlike Math.random()
// which is not cryptographically secure and whose internal state can, in principle, be
// reconstructed from observed outputs. Used here since this generates a real credential
// (an admin-issued PIN), not just UI randomness.
function randomPin() {
  return String(crypto.randomInt(1000, 10000));
}

// ============================================================================================
// App Check — a BOT/ABUSE mitigation, not an identity or authorization boundary.
//
// App Check proves "this request came from a genuine instance of our app" (attested by
// reCAPTCHA/Play Integrity/DeviceCheck depending on platform) — it says nothing about WHO is
// using the app. It never replaces the role/token-based authorization already enforced
// throughout this file (the caller's verified role/approved claim remains the only thing any
// privileged decision is based on — see verifyCallerToken() below). Its only job here is to
// make it harder to script mass requests directly against these endpoints, bypassing the UI.
//
// IMPORTANT — NOT YET SAFE TO HARD-ENFORCE: hard-rejecting requests without a valid App Check
// token (context.app) requires the CLIENT to also initialize the App Check SDK with a real
// reCAPTCHA v3/Enterprise site key from this Firebase project's console — that key does not
// exist in this codebase and I cannot fabricate one. Turning on hard enforcement before that
// client-side setup exists would lock every legitimate user out, including the app's own
// normal traffic. So this currently only WARNS (via Cloud Logging) when a request arrives
// without an App Check token, so you can see how much traffic would be affected. Once App
// Check is configured in the Firebase console AND the client is updated to initialize it
// (see the note left in merged.html), flip ENFORCE_APP_CHECK to true below.
const ENFORCE_APP_CHECK = false;
function checkAppCheck(context, fnName) {
  if (!context.app) {
    if (ENFORCE_APP_CHECK) {
      throw new functions.https.HttpsError("failed-precondition", "App attestation required");
    }
    console.warn(`[app-check] ${fnName} called without a valid App Check token (enforcement is currently OFF)`);
  }
}

// ============================================================================================
// Revocation-checked identity verification.
//
// context.auth, as automatically populated by the Callable Functions framework, verifies the
// caller's ID token's SIGNATURE and standard claims (expiry, issuer, audience) — but does NOT
// check whether the token has since been revoked (via revokeRefreshTokens(), which setUserPin
// calls after a role change or account deletion). A token that was valid when issued keeps
// passing that default check for the rest of its ~1 hour lifetime even after revocation,
// unless revocation status is checked explicitly. Every security-sensitive function below
// re-verifies the SAME raw ID token the request actually carried, this time with
// checkRevoked=true, and trusts ONLY the result of that fresh check — never context.auth
// directly, and never anything from the request body.
//
// This still relies on the token's own cryptographic signature (verified by
// admin.auth().verifyIdToken against Firebase's public keys for this project) — the same
// guarantee context.auth already provides. Nothing here can be influenced by a client-supplied
// header value alone: without a validly-signed token behind it, verification fails outright,
// the same as it always has. An attacker cannot inject a fake uid/role/approved this way —
// they would need a genuine token Firebase itself signed, which only login/setUserPin ever
// produce, and only for the identity they were actually authenticated as.
//
// NOT TESTED against live Firebase from this environment — extracting the raw token from
// context.rawRequest.headers.authorization is well-documented, stable behavior for 1st-gen
// callable functions, but I have no way to execute this against real Firebase infrastructure
// to confirm it empirically. Treat this as implemented-with-high-confidence, not verified.
async function verifyCallerToken(context) {
  const authHeader = (context.rawRequest && context.rawRequest.headers && context.rawRequest.headers.authorization) || "";
  const match = /^Bearer (.+)$/.exec(authHeader);
  if (!match) {
    throw new functions.https.HttpsError("unauthenticated", "Sign in required");
  }
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(match[1], /* checkRevoked */ true);
  } catch (e) {
    // Expired, revoked, malformed, or otherwise invalid — all rejected the same way, so a
    // caller can't distinguish "expired" from "revoked" and use that to probe account status.
    throw new functions.https.HttpsError("unauthenticated", "Session is no longer valid — please log in again.");
  }
  return { uid: decoded.uid, role: decoded.role || "user", approved: decoded.approved === true };
}

// ============================================================================================
// Login rate limiting / brute-force protection.
//
// Enforced entirely server-side, keyed by data the ATTACKER cannot reset by changing their own
// state: the username being attempted (so switching usernames doesn't reset a shared budget for
// one target — instead each username has its own budget) AND, as defense-in-depth, the caller's
// IP address (so spraying many different usernames from one source is also capped). Neither key
// depends on anything the caller can freely mint more of by "creating a new account" — there is
// no account-creation step before login exists, and calling this function directly changes
// nothing, since the checks happen here, not in the UI.
//
// KNOWN LIMITATION, disclosed rather than hidden: this is a two-phase check-then-record design
// (check lock status, do the slow bcrypt work, then record the outcome), not a single atomic
// operation, because whether an attempt succeeded isn't known until after the bcrypt compare
// runs. Under a very tight burst of purely parallel requests arriving faster than Firestore can
// record the previous ones, a few extra attempts beyond the nominal threshold could land before
// the lockout catches up. It is NOT bypassable by changing IP/username/calling the function
// directly in the way a client-side or single-key limiter would be — it just isn't a perfectly
// atomic hard cap under extreme parallelism. Also NOT TESTED against a live environment.
const crypto = require("crypto");
const MAX_ATTEMPTS_BEFORE_LOCK = 5;
const BASE_LOCK_SECONDS = 30;
const MAX_LOCK_SECONDS = 15 * 60;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

function rateLimitDocRef(kind, key) {
  const hashed = crypto.createHash("sha256").update(String(key)).digest("hex");
  return db.collection(kind === "username" ? "loginAttempts" : "loginAttemptsByIp").doc(hashed);
}

// Computes the next failed-attempt state from the current stored state, applying the same
// window-expiry + exponential-backoff rules the old recordLoginAttempt() used. Pure function,
// no I/O, so it's usable both inside a transaction and in isolated unit tests.
function nextFailedAttemptState(data, now) {
  let state = data ? { ...data } : { count: 0, windowStart: now, lockedUntil: 0 };
  if (now - state.windowStart > ATTEMPT_WINDOW_MS) {
    state = { count: 0, windowStart: now, lockedUntil: 0 };
  }
  state.count += 1;
  if (state.count >= MAX_ATTEMPTS_BEFORE_LOCK) {
    const lockSeconds = Math.min(
      BASE_LOCK_SECONDS * Math.pow(2, state.count - MAX_ATTEMPTS_BEFORE_LOCK),
      MAX_LOCK_SECONDS
    );
    state.lockedUntil = now + lockSeconds * 1000;
  }
  return state;
}

// ============================================================================================
// PHASE 4 FINDING 1 FIX — Atomic rate-limit reservation.
//
// Replaces the old separate "check (plain read) -> do slow bcrypt work -> record (transactional
// write)" sequence. That split had a TOCTOU race: every concurrent request in a burst could
// complete its un-transacted read of "not locked" before any of them committed a write,
// letting more attempts through in a single wave than MAX_ATTEMPTS_BEFORE_LOCK should allow,
// because the accounting only ever happened AFTER the slow bcrypt step, once it was already too
// late to stop the burst.
//
// Here, checking lock state AND speculatively reserving the attempt slot (as if this attempt
// will fail) happen inside ONE Firestore transaction, executed BEFORE bcrypt runs. Firestore
// transactions serialize/retry against the same document(s) on contention, so concurrent
// requests against the same username/IP genuinely queue through this reservation instead of all
// observing stale "unlocked" state. If the attempt turns out to succeed, finalizeLoginAttempt()
// below resets the counter afterward. If it fails, no further write is needed — the reservation
// already recorded it as a failed attempt, which is exactly the state a failed attempt should
// leave behind.
//
// Both keys (username, IP) are reserved together in a single transaction, preserving the
// original behavior of only counting a fresh attempt against either key when NEITHER is already
// locked — a request rejected outright because one key is already locked is never counted as a
// new attempt against the other.
async function reserveLoginAttempt(usernameKey, ip) {
  const userRef = rateLimitDocRef("username", usernameKey);
  const ipRef = rateLimitDocRef("ip", ip);
  return db.runTransaction(async (tx) => {
    const [userSnap, ipSnap] = await Promise.all([tx.get(userRef), tx.get(ipRef)]);
    const now = Date.now();
    const userLocked = !!(userSnap.exists && userSnap.data().lockedUntil > now);
    const ipLocked = !!(ipSnap.exists && ipSnap.data().lockedUntil > now);
    if (userLocked || ipLocked) {
      // Already locked — reject fast, same as before, without counting this as a new attempt
      // against either key.
      return { locked: true };
    }
    const userState = nextFailedAttemptState(userSnap.exists ? userSnap.data() : null, now);
    const ipState = nextFailedAttemptState(ipSnap.exists ? ipSnap.data() : null, now);
    tx.set(userRef, userState);
    tx.set(ipRef, ipState);
    return { locked: false };
  });
}

// Called after the bcrypt compare resolves. On success, resets both counters (undoing the
// reservation's speculative "failed attempt" increment). On failure, this is a no-op — the
// reservation transaction above already recorded the failed attempt.
async function finalizeLoginAttempt(usernameKey, ip, success) {
  if (!success) return;
  const now = Date.now();
  const resetState = { count: 0, windowStart: now, lockedUntil: 0 };
  await Promise.all([
    rateLimitDocRef("username", usernameKey).set(resetState),
    rateLimitDocRef("ip", ip).set(resetState)
  ]);
}

// A fixed, precomputed hash checked (via a real bcrypt.compare, not skipped) whenever the
// submitted username doesn't exist or has no credential — so that path takes the same time as
// a real "wrong PIN" check, closing the timing side-channel that would otherwise let an
// attacker distinguish "no such account" from "account exists, wrong PIN" by response time
// alone, without weakening the actual PIN check for real accounts in any way.
const DUMMY_HASH = bcrypt.hashSync("mm-timing-safety-fixed-dummy-value", BCRYPT_ROUNDS);

// createCustomToken() never provisions a Firebase Auth user record for the uid it mints a
// token for — that record is only lazily created when the CLIENT actually exchanges the token
// via signInWithCustomToken. setCustomUserClaims(), unlike createCustomToken(), requires that
// record to already exist, and throws auth/user-not-found if it doesn't — which it won't yet,
// server-side, on anyone's very first login. This wraps the call so a brand-new account's
// first login provisions the user record first rather than failing outright.
async function setClaimsEnsuringUserExists(uid, claims) {
  try {
    await admin.auth().setCustomUserClaims(uid, claims);
  } catch (e) {
    if (e && e.code === "auth/user-not-found") {
      try { await admin.auth().createUser({ uid }); } catch (e2) {
        if (!e2 || e2.code !== "auth/uid-already-exists") throw e2;
      }
      await admin.auth().setCustomUserClaims(uid, claims);
    } else {
      throw e;
    }
  }
}

// The Firestore document stores the entire app state as ONE string field, `json` — not as
// top-level document fields. Every function that needs to read or write the app's data goes
// through these two helpers so that fact only has to be handled correctly in one place.
async function readAppData() {
  const snap = await APP_DOC.get();
  if (!snap.exists) return {};
  try { return JSON.parse(snap.data().json || "{}"); }
  catch (e) { return {}; }
}
async function writeAppData(obj) {
  await APP_DOC.set({ json: JSON.stringify(obj) });
}

// ============================================================================================
// saveAppData — server-side authorization for every write to the shared business document.
//
// WHY THIS EXISTS: moneymatrix/appData is one shared document (not per-user documents), and
// the app's real authorization model is hierarchical downline scoping (a supervisor may write
// records belonging to their own downline chain, walked via supervisorId links) plus a
// role/section permission matrix (e.g. "user" role has club:write but marathon:hidden) — not
// simple per-uid ownership. Firestore Security Rules cannot express an unbounded
// hierarchy walk or reliably diff individual elements of an array field, so that logic cannot
// live in firestore.rules. It lives here instead: firestore.rules now denies ALL direct client
// writes to this document (see firestore.rules), and this function is the only path a write
// can take. It re-implements the same section-permission and downline-scope logic the client
// already trusts for its own UI (getPerm/getScopedMembers/etc in the app), so that logic
// can't be bypassed by calling Firestore directly — it runs here, server-side, using only the
// caller's verified role claim and the CURRENT document state, never anything the client
// merely asserts about itself.
// ============================================================================================

const CONTROL_PLANE_KEYS = ["users", "permissions", "customSections", "settings", "userPermissions"];

// Fields ensure() fills in locally the first time they're missing, with the same fixed
// defaults every client would compute — allowing these specific transitions through for any
// approved user (not just superadmin) avoids a legitimate non-admin save being rejected just
// because it incidentally carried a first-time default alongside an unrelated business-data
// change. This does not weaken control-plane protection: it only ever permits moving from
// "missing" to one specific, hardcoded, non-sensitive default value — never an arbitrary
// caller-supplied value, and never a change to a field that already had a value.
function isBenignDefaultInit(key, before, after) {
  const j = (v) => JSON.stringify(v === undefined ? null : v);
  if (key === "userPermissions") return (before === undefined || before === null) && j(after) === j({});
  if (key === "customSections") return (before === undefined || before === null) && j(after) === j([]);
  if (key === "settings") {
    if (before === undefined || before === null) return false; // settings itself must already exist
    const beforeKeys = Object.keys(before || {});
    const afterKeys = Object.keys(after || {});
    // Only newly-added keys allowed, each matching a known safe default, and every
    // previously-existing key must be byte-identical (no sneaking in an unrelated change).
    const added = afterKeys.filter(k => !beforeKeys.includes(k));
    const knownDefaults = { formula1Flavors: ["Vanilla", "Orange"], afreshFlavors: ["Lemon", "Wild Berry"] };
    for (const k of beforeKeys) { if (j(before[k]) !== j(after[k])) return false; }
    for (const k of added) { if (!(k in knownDefaults) || j(after[k]) !== j(knownDefaults[k])) return false; }
    return true;
  }
  return false;
}

// customSections is superadmin-controlled (see CONTROL_PLANE_KEYS), but the UI's icon picker
// (a fixed <select>) is only a client-side constraint — a direct API call could send anything.
// icon/label render unescaped into an HTML class attribute in a few places in merged.html
// (now fixed to esc() them too, but this is validated here as well, in depth): an icon value
// containing '"', '<', or similar could break out of that attribute and store persistent XSS
// that runs in the browser of every other user who views the sidebar/permissions/section-
// manager pages. Restricting the stored shape to what a legitimate icon class ever needs to be
// closes this off at the source, not just at render time.
const ICON_RE = /^fa-[a-z0-9-]+$/;
function validateCustomSections(arr) {
  if (!Array.isArray(arr)) {
    throw new functions.https.HttpsError("invalid-argument", "customSections must be an array");
  }
  for (const cs of arr) {
    if (!cs || typeof cs !== "object" || typeof cs.id !== "string" || typeof cs.label !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "Invalid custom section entry");
    }
    if (cs.icon !== undefined && (typeof cs.icon !== "string" || !ICON_RE.test(cs.icon))) {
      throw new functions.https.HttpsError("invalid-argument", "Invalid custom section icon");
    }
  }
}

function getPermFor(section, role, uid, permissions, userPermissions) {
  if (role === "superadmin") return "write";
  const override = userPermissions?.[uid]?.[section];
  if (override) return override;
  if (permissions && permissions[role] && permissions[role][section]) return permissions[role][section];
  return role === "admin" ? "write" : (section === "dashboard" ? "view" : "hidden");
}

function downlineIds(rootId, supervisors) {
  const ids = new Set([rootId]);
  let added = true;
  while (added) {
    added = false;
    for (const s of (supervisors || [])) {
      if (s && s.supervisorId && ids.has(s.supervisorId) && !ids.has(s.id)) { ids.add(s.id); added = true; }
    }
  }
  return ids;
}

function byId(arr) {
  const m = new Map();
  (arr || []).forEach(x => { if (x && x.id != null) m.set(x.id, x); });
  return m;
}

// A record with no `id` (or a null id) is invisible to byId()/diffRecords() below — it would
// never be matched against the old array, so it would never be diffed, authorized, or even
// noticed at all, and would be merged into the document untouched. Rejecting any such element
// outright, for the arrays that are diffed record-by-record, closes that off entirely rather
// than relying on the diff to catch something it structurally cannot see.
//
// This also rejects ids containing characters that have no legitimate reason to appear in a
// generated id (see nid(): "id_"+Date.now()+"_"+base36 random) but that are exactly what's
// needed to break out of an HTML attribute or a JS string literal built from that id on the
// client (', ", \, <, >, backtick), plus control characters and unreasonably long strings.
// This is a character blacklist, not a strict format allowlist, specifically so it does not
// reject any legitimately existing id already in the database (including hand-entered or
// imported ids) that merely doesn't match nid()'s exact shape — it only rejects ids that could
// not possibly be a normal identifier in the first place. Client-side output encoding (esc()/
// sj()) is still the primary defense; this is a second, independent layer.
const UNSAFE_ID_CHARS = /['"<>\\`\x00-\x1f]/;
function requireValidIds(arr, label) {
  for (const x of (arr || [])) {
    if (!x || x.id == null || x.id === "") {
      throw new functions.https.HttpsError("invalid-argument", `Every ${label} record must have an id`);
    }
    if (typeof x.id !== "string" || x.id.length > 200 || UNSAFE_ID_CHARS.test(x.id)) {
      throw new functions.https.HttpsError("invalid-argument", `Invalid ${label} id`);
    }
  }
}

// Returns [{id, before, after}] for every element that was added, removed, or changed between
// two id-keyed arrays. Comparison is by value (JSON-equal), not reference.
function diffRecords(oldArr, newArr) {
  const oldMap = byId(oldArr), newMap = byId(newArr);
  const ids = new Set([...oldMap.keys(), ...newMap.keys()]);
  const out = [];
  for (const id of ids) {
    const a = oldMap.get(id), b = newMap.get(id);
    if (JSON.stringify(a) !== JSON.stringify(b)) out.push({ id, before: a, after: b });
  }
  return out;
}

// Authorizes a change to one record in a downline-scoped collection (members/coaches/
// supervisors). `resolveSupervisorId` maps a record (before or after state) to the
// supervisorId that owns it. Checked against BOTH before and after state, so reassigning a
// record's ownership into or out of a caller's scope is authorized on both ends, not just one.
function authorizeScopedRecord(change, role, downline, resolveSupervisorId) {
  if (role === "superadmin" || role === "admin") return true;
  const ownerBefore = change.before ? resolveSupervisorId(change.before) : null;
  const ownerAfter = change.after ? resolveSupervisorId(change.after) : null;
  if (change.before && !(ownerBefore && downline.has(ownerBefore))) return false;
  if (change.after && !(ownerAfter && downline.has(ownerAfter))) return false;
  return true;
}

// Read-side counterpart to authorizeScopedRecord: returns only the records the caller is
// authorized to see, instead of validating a proposed change. Same ownership rule, applied
// as a filter rather than a check.
function filterToDownline(arr, role, downline, resolveSupervisorId) {
  if (role === "superadmin" || role === "admin") return arr || [];
  return (arr || []).filter(r => {
    const owner = resolveSupervisorId(r);
    return owner && downline.has(owner);
  });
}

// ============================================================================================
// PHASE 7 — round-trip reconciliation for downline-scoped arrays (members/coaches/supervisors).
//
// getAppData hands a non-privileged caller a downline-FILTERED subset of these arrays (via
// filterToDownline above). A real client only ever holds that subset locally, edits within it,
// and round-trips the whole (still-filtered) array back through saveAppData — it never had the
// out-of-scope records to begin with, so it can't send them back even unmodified. Comparing
// that filtered array directly against the full server-side array (as saveAppData did through
// Phase 6) makes every out-of-scope record look like an attempted deletion, which
// authorizeScopedRecord correctly refuses — but "correctly refuses" here means the ENTIRE save
// is rejected for a record the caller never touched and couldn't have. See AUDIT_STATUS.md
// Phase 6, "Discovered but explicitly deferred", for the original report.
//
// Fix, in two parts (both required together — doing only one reintroduces a bug):
//
// 1. visibleBaseline() gives the diff/permission-check logic below the SAME filtered view of
//    `old` that the caller's own getAppData response would have contained, instead of the full
//    server-side array. A caller who round-trips their view unmodified now diffs as "no
//    change" instead of "mass deletion". A caller who edits/adds/removes a record WITHIN their
//    own downline still diffs normally and is still authorized per-record exactly as before
//    (authorizeScopedRecord is unchanged and still runs on every real diff).
//
// 2. reconcileScopedArray() fixes the actual PERSISTED value, not just the check. The final
//    `merged` object is built via `{ ...current, ...incoming }` (see below) — a naive fix that
//    only relaxed the check above would still write the caller's (necessarily filtered)
//    `incoming.shared.X` wholesale, silently DELETING every out-of-scope record from the real
//    database on a successful save. reconcileScopedArray prevents that by reconstructing the
//    stored array itself: every record outside the caller's downline is preserved verbatim from
//    the server's current authoritative value (the caller never had authority over it and never
//    even saw it), and only the caller's own in-scope records are taken from what they submitted.
//
// Privileged callers (superadmin/admin) are untouched by either function — they still see and
// write the full, unfiltered array, exactly as before this phase.
function visibleBaseline(arr, role, downline, resolveSupervisorId) {
  if (role === "superadmin" || role === "admin") return arr || [];
  return filterToDownline(arr, role, downline, resolveSupervisorId);
}

// Diff-against-baseline for a downline-scoped array, guarding against one specific bypass: an
// id that already exists in the FULL authoritative `fullOldArr` but was filtered out of the
// caller's own `baselineArr` (outside their downline) must NOT be treated as a fresh "add"
// just because it's new to the caller's baseline — that would let a non-privileged caller claim
///overwrite an existing out-of-scope record by re-submitting its id with a different owner and
// content, since authorizeScopedRecord would see `before: undefined` and only check the (now
// caller-controlled) `after` ownership. Surfacing the REAL prior record as `before` here makes
// authorizeScopedRecord correctly reject it via the existing ownerBefore-not-in-downline check.
function diffScopedRecords(fullOldArr, baselineArr, newArr) {
  const fullOldMap = byId(fullOldArr);
  const baselineMap = byId(baselineArr);
  const newMap = byId(newArr);
  const ids = new Set([...baselineMap.keys(), ...newMap.keys()]);
  const out = [];
  for (const id of ids) {
    const baseVal = baselineMap.get(id);
    const newVal = newMap.get(id);
    if (JSON.stringify(baseVal) === JSON.stringify(newVal)) continue;
    const before = baseVal === undefined && fullOldMap.has(id) ? fullOldMap.get(id) : baseVal;
    out.push({ id, before, after: newVal });
  }
  return out;
}

function reconcileScopedArray(oldArr, newArr, role, downline, resolveSupervisorId) {
  if (role === "superadmin" || role === "admin") return newArr || []; // full trust, unchanged
  const outOfScope = (oldArr || []).filter(r => {
    const owner = resolveSupervisorId(r);
    return !(owner && downline.has(owner));
  });
  const inScopeNew = (newArr || []).filter(r => {
    const owner = resolveSupervisorId(r);
    return owner && downline.has(owner);
  });
  return [...outOfScope, ...inScopeNew];
}

// Mirrors the client's getScopedActivity() exactly (same scopeId/downline rule) — added here
// because getAppData previously returned the FULL activityLog to every approved caller and
// relied on the client to filter it for display. That's exactly the class of assumption this
// audit flags as unsafe: an attacker who calls getAppData directly (bypassing the UI) would
// have seen activity entries — names/actions — from outside their own downline. Filtering now
// happens here, server-side, using the same verified downline Set getAppData already computes.
function filterActivityToDownline(log, role, downline) {
  if (role === "superadmin" || role === "admin") return log || [];
  return (log || []).filter(a => a && a.scopeId && downline.has(a.scopeId));
}

// Shared by getAppData: the caller's verified identity (role from the freshly revocation-
// checked token, never the request) plus their downline scope (computed from the CURRENT
// server-side document, never the client's claims about itself).
async function callerContext(context, current) {
  const { uid: callerUid, role: callerRole, approved } = await verifyCallerToken(context);
  if (!approved) {
    throw new functions.https.HttpsError("permission-denied", "Not approved");
  }
  const callerUser = (current.users || []).find(u => u.id === callerUid);
  const callerLinkedId = callerUser ? callerUser.linkedId : null;
  const supervisors = (current.shared && current.shared.supervisors) || [];
  const downline = callerLinkedId ? downlineIds(callerLinkedId, supervisors) : new Set();
  return { callerUid, callerRole, callerLinkedId, downline };
}

/**
 * getAppData()
 * The ONLY way a client ever obtains business data now — direct Firestore reads of
 * moneymatrix/appData are denied entirely (see firestore.rules). This computes and returns
 * exactly the subset of the document the caller is authorized to see, using the same
 * downline-scope and section-permission logic saveAppData already enforces on writes. Nothing
 * beyond what's explicitly included below ever leaves this function.
 */
exports.getAppData = functions.https.onCall(async (data, context) => {
  checkAppCheck(context, "getAppData");
  const current = await readAppData();
  const { callerUid, callerRole, callerLinkedId, downline } = await callerContext(context, current);

  const shared = current.shared || {};
  const coachesAll = shared.coaches || [];
  function coachSupervisorId(coachId) {
    const c = coachesAll.find(x => x.id === coachId);
    return c ? c.supervisorId : null;
  }

  const isPrivileged = callerRole === "superadmin" || callerRole === "admin";

  const outShared = {
    members: filterToDownline(shared.members, callerRole, downline,
      (m) => m.supervisorId || (m.coachId ? coachSupervisorId(m.coachId) : null)),
    coaches: filterToDownline(shared.coaches, callerRole, downline, (c) => c.supervisorId),
    supervisors: filterToDownline(shared.supervisors, callerRole, downline, (s) => s.id),
  };
  // Transactions/gifts/products/quotations: section-permission based, matching the app's
  // existing model exactly (no per-record ownership for these — see the note in
  // firestore.rules/saveAppData). "view" or "write" both grant read visibility; "hidden"
  // means the section is omitted from the response entirely, not just hidden in the UI.
  const sectionFor = { transactions: "marathon", gifts: "gifts", products: "products", quotations: "quotations" };
  for (const [field, section] of Object.entries(sectionFor)) {
    const perm = getPermFor(section, callerRole, callerUid, current.permissions, current.userPermissions);
    outShared[field] = (perm === "view" || perm === "write") ? (shared[field] || []) : [];
  }

  // perUser (isolated-mode data): only the caller's own bucket, unless privileged.
  let outPerUser = {};
  if (isPrivileged) {
    outPerUser = current.perUser || {};
  } else if (current.perUser && current.perUser[callerUid] !== undefined) {
    outPerUser = { [callerUid]: current.perUser[callerUid] };
  }

  // profiles: caller's own, anyone privileged sees all, a supervisor sees profiles of logins
  // within their own downline (mirrors the visibility they already have into those accounts'
  // member/coach/supervisor records — restricting the profile object separately while the
  // same phone/email is already visible on those records would just be inconsistent, not safer).
  const allProfiles = current.profiles || {};
  let outProfiles;
  if (isPrivileged) {
    outProfiles = allProfiles;
  } else {
    outProfiles = {};
    for (const key of Object.keys(allProfiles)) {
      if (key === callerUid) { outProfiles[key] = allProfiles[key]; continue; }
      const owner = (current.users || []).find(u => u.id === key);
      if (owner && owner.linkedId && downline.has(owner.linkedId)) outProfiles[key] = allProfiles[key];
    }
  }

  // PHASE 6 — `users` (the login-account directory: username/role/linkedId, never PINs) is now
  // downline-filtered for non-privileged callers, the same visibility rule already applied to
  // `profiles` a few lines above: the caller's own entry, plus any login account whose
  // `linkedId` falls within the caller's own downline. This is safe to do now (it was
  // explicitly deferred in Phase 5, see AUDIT_STATUS.md Finding 3) because saveAppData no
  // longer diffs a non-superadmin's `users` field against the full server-side list — it's
  // simply dropped and ignored (see the "PHASE 6" comment in saveAppData above), so a
  // filtered client can never again get its saves rejected for a field it isn't authoritative
  // over in the first place.
  const outUsers = isPrivileged
    ? (current.users || [])
    : (current.users || []).filter(u => {
        if (u.id === callerUid) return true;
        return !!(u.linkedId && downline.has(u.linkedId));
      });

  // Control-plane fields (permissions matrix, custom sections, settings, the login/role list
  // minus PINs — already never present here at all): non-sensitive, needed broadly for the UI
  // to function, same as before. `users` never carried PINs to begin with. activityLog is NOT
  // in this bucket — unlike the others it names people and actions across the whole org, so
  // it's downline-filtered below rather than returned broadly (Phase 3 fix: previously
  // returned unfiltered and relied on the client to hide out-of-scope entries).
  return {
    json: JSON.stringify({
      users: outUsers,
      permissions: current.permissions || {},
      customSections: current.customSections || [],
      settings: current.settings || {},
      userPermissions: current.userPermissions || {},
      activityLog: filterActivityToDownline(current.activityLog, callerRole, downline),
      shared: outShared,
      perUser: outPerUser,
      profiles: outProfiles
    })
  };
});

exports.saveAppData = functions.https.onCall(async (data, context) => {
  checkAppCheck(context, "saveAppData");
  const { uid: callerUid, role: callerRole, approved } = await verifyCallerToken(context);
  if (!approved) {
    throw new functions.https.HttpsError("permission-denied", "Not approved");
  }

  const current = await readAppData();
  // The client sends the same {json: "<stringified DB>"} shape it always has (see cloudSave()
  // in the app) — parsed here into the actual object so the section-by-section checks below
  // can compare real values, not a raw string.
  let incoming;
  try { incoming = JSON.parse(String(data?.json ?? "{}")); }
  catch (e) { throw new functions.https.HttpsError("invalid-argument", "Malformed payload"); }
  if (!incoming || typeof incoming !== "object") incoming = {};

  // Reject anything outside the known document shape outright, rather than only checking the
  // fields we already know are sensitive — a genuinely new, unrecognized top-level key (not
  // just one of the five control-plane fields) is refused even though nothing reads it today,
  // so this can't quietly become a gap the next time the schema grows.
  const KNOWN_TOP_LEVEL_KEYS = new Set([...CONTROL_PLANE_KEYS, "shared", "perUser", "profiles", "activityLog"]);
  for (const key of Object.keys(incoming)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) {
      throw new functions.https.HttpsError("invalid-argument", `Unrecognized field '${key}'`);
    }
  }

  // Caller's own linkedId (for downline scoping) comes from the CURRENT server-side document,
  // never from the request — a client could claim any linkedId it wants, so it's never trusted.
  const callerUser = (current.users || []).find(u => u.id === callerUid);
  const callerLinkedId = callerUser ? callerUser.linkedId : null;

  // --- 1. Control-plane fields: superadmin only, with the narrow benign-default carve-out. ---
  //
  // PHASE 6 — `users` is handled differently from the other control-plane keys, deliberately.
  //
  // Every other control-plane key round-trips unfiltered to every approved caller via
  // getAppData, so a non-superadmin's `incoming` value for those keys is always either
  // identical to `current` (nothing to do) or a genuine unauthorized tampering attempt (reject
  // the whole save, as before). `users` is no longer like that as of this phase: getAppData
  // now hands non-privileged callers a downline-filtered SUBSET of `users` (see below), so
  // their local copy differing from the full server-side list is the EXPECTED, permanent
  // state, not tampering — it's a smaller view, not a different value for the same view. Were
  // this treated like the other keys, every save by every non-privileged caller would fail
  // forever once they touched anything (see AUDIT_STATUS.md Phase 5 Finding 3 for why a
  // read-side-only filter was rejected previously).
  //
  // The fix: for `users` specifically, a non-superadmin's incoming value is never trusted and
  // never merged — not rejected outright, just silently dropped, exactly like a client-supplied
  // PIN is never trusted (see setUserPin). `delete incoming.users` here removes it from the
  // object that gets spread into `merged` below, so `current.users` (the real, full, authoritative
  // list) survives untouched no matter what a non-privileged client's payload happened to
  // contain. This is strictly narrower than before: it can never cause a `users` write that
  // wasn't already possible (only superadmin ever reaches the `continue` path that keeps an
  // incoming value), it just stops an irrelevant field from blocking the REST of a legitimate
  // save.
  if ("users" in incoming) {
    if (callerRole === "superadmin") {
      // Unchanged from before this phase: full trust, full replace, exactly as already
      // exercised by the account-management page and the rank-promotion flow.
    } else {
      delete incoming.users;
    }
  }
  for (const key of CONTROL_PLANE_KEYS) {
    if (key === "users") continue; // handled separately above — never falls through to the generic reject-on-diff path
    if (!(key in incoming)) continue; // caller isn't touching this section at all — fine
    const before = current[key];
    const after = incoming[key];
    if (JSON.stringify(before === undefined ? null : before) === JSON.stringify(after === undefined ? null : after)) continue; // no actual change
    if (key === "customSections") validateCustomSections(after); // shape/format check regardless of who's changing it
    if (callerRole === "superadmin") continue; // superadmin may change anything here
    if (isBenignDefaultInit(key, before, after)) continue; // one-time default fill-in, always allowed
    throw new functions.https.HttpsError("permission-denied", `Not authorized to change '${key}'`);
  }

  // --- 2. Business-data sections. ---
  const newShared = incoming.shared || current.shared || {};
  const oldShared = current.shared || {};
  // Validate ids on the arrays used for downline-scope computation itself, not just the ones
  // being diffed below — a malformed/id-less entry here would otherwise corrupt the caller's
  // own downline Set (and every authorization decision derived from it) before the per-record
  // diff even runs.
  requireValidIds(newShared.supervisors, "supervisor");
  requireValidIds(newShared.coaches, "coach");
  requireValidIds(newShared.members, "member");
  // PHASE 7 — scope computation now ALWAYS uses the server's authoritative current data
  // (oldShared), never the client-submitted newShared, for both the downline Set and the
  // coach->supervisor resolver used to authorize this save.
  //
  // Previously this preferred `newShared.supervisors`/`newShared.coaches` (the client's
  // submitted arrays) when present. That was always a latent risk for non-privileged callers
  // (their own claimed topology could shape their own authorized scope within the very same
  // request) but was masked before this phase: any mismatch between the full server-side
  // `oldShared.supervisors` and a client's submitted array already triggered the coarser
  // "no write access to supervisors" rejection for any role without write permission on that
  // section (the overwhelmingly common case), so the self-referential downline was computed
  // but never actually reached in a way that mattered.
  //
  // Phase 7's baseline-based comparison (visibleBaseline, below) removes that accidental
  // masking — a non-privileged caller's round-tripped, downline-FILTERED supervisors array is
  // now expected to differ from the full old array, so the coarse mismatch check alone can no
  // longer be relied on to catch this. Concretely: omitting a downline supervisor record from
  // the submitted array would shrink `downline` itself (computed from that same submitted
  // array), which in turn shrinks the caller's own `visibleBaseline`, which could make the
  // omission compare as "no change" — silently bypassing the write-permission gate entirely.
  // Anchoring `downline` to the server's authoritative topology instead closes this off: a
  // non-privileged caller's scope for this request is now always exactly what the server
  // itself would compute from current data, never something the caller's own payload can
  // shape. Superadmin/admin are unaffected either way (authorizeScopedRecord short-circuits
  // to true for them regardless of downline content).
  const supervisorsForScope = oldShared.supervisors || [];
  const coachesForScope = oldShared.coaches || [];
  const downline = callerLinkedId ? downlineIds(callerLinkedId, supervisorsForScope) : new Set();

  function coachSupervisorId(coachId) {
    const c = (coachesForScope || []).find(x => x.id === coachId);
    return c ? c.supervisorId : null;
  }

  if ("shared" in incoming) {
    // FINDING A FIX — `newShared` was previously spread wholesale into the persisted value
    // (`incoming.shared = { ...newShared, members: ..., coaches: ..., supervisors: ... }`
    // below), with only members/coaches/supervisors reconciled against server authority and
    // only transactions/gifts/products/quotations permission-checked. Any OTHER key a caller
    // added to `shared` was neither diffed, nor permission-checked, nor stripped — it just
    // rode the spread straight into the shared, org-wide `moneymatrix/appData` document.
    // Confirmed exploitable by a `role: "user"` account with `permissions: {}` (i.e. zero
    // write access to any section, anywhere): `shared.injectedByPlainUser` was accepted and
    // persisted with no authorization check of any kind. This mirrors the SAME allow-list
    // pattern already applied one level up (KNOWN_TOP_LEVEL_KEYS) — it was just never applied
    // inside `shared` too. Reject any key that isn't part of the known, already-authorized
    // shape, for every caller (not just non-privileged ones) — a superadmin has no legitimate
    // reason to introduce an unrecognized key either, and rejecting it here is strictly safer
    // than silently allowing the shape of this document to drift.
    const KNOWN_SHARED_KEYS = new Set(["members", "coaches", "supervisors", "transactions", "gifts", "products", "quotations"]);
    for (const key of Object.keys(newShared)) {
      if (!KNOWN_SHARED_KEYS.has(key)) {
        throw new functions.https.HttpsError("invalid-argument", `Unrecognized field 'shared.${key}'`);
      }
    }
    // PHASE 7 — see the "round-trip reconciliation" comment above authorizeScopedRecord/
    // filterToDownline for the full explanation. For each downline-scoped array, `baseline`
    // is what THIS caller's own getAppData response would have contained (full array for
    // privileged callers, downline-filtered for everyone else) — comparisons and diffs are
    // computed against that, not the raw full server-side array, so a non-privileged caller
    // round-tripping their own filtered view no longer looks like a mass-deletion attempt.
    const resolveMember = (m) => m.supervisorId || (m.coachId ? coachSupervisorId(m.coachId) : null);

    // members — club permission + downline scope (own supervisorId, or via coachId -> coach's supervisorId)
    const membersBaseline = visibleBaseline(oldShared.members, callerRole, downline, resolveMember);
    if (JSON.stringify(membersBaseline) !== JSON.stringify(newShared.members || [])) {
      if (getPermFor("club", callerRole, callerUid, current.permissions, current.userPermissions) !== "write") {
        throw new functions.https.HttpsError("permission-denied", "No write access to club members");
      }
      for (const change of diffScopedRecords(oldShared.members, membersBaseline, newShared.members)) {
        if (!authorizeScopedRecord(change, callerRole, downline, resolveMember)) {
          throw new functions.https.HttpsError("permission-denied", "Member is outside your downline scope");
        }
      }
    }
    // coaches — coaches permission + downline scope
    const coachesBaseline = visibleBaseline(oldShared.coaches, callerRole, downline, (c) => c.supervisorId);
    if (JSON.stringify(coachesBaseline) !== JSON.stringify(newShared.coaches || [])) {
      if (getPermFor("coaches", callerRole, callerUid, current.permissions, current.userPermissions) !== "write") {
        throw new functions.https.HttpsError("permission-denied", "No write access to coaches");
      }
      for (const change of diffScopedRecords(oldShared.coaches, coachesBaseline, newShared.coaches)) {
        if (!authorizeScopedRecord(change, callerRole, downline, (c) => c.supervisorId)) {
          throw new functions.https.HttpsError("permission-denied", "Coach is outside your downline scope");
        }
      }
    }
    // supervisors — supervisors permission + downline scope (the record IS the supervisor)
    const supervisorsBaseline = visibleBaseline(oldShared.supervisors, callerRole, downline, (s) => s.id);
    if (JSON.stringify(supervisorsBaseline) !== JSON.stringify(newShared.supervisors || [])) {
      if (getPermFor("supervisors", callerRole, callerUid, current.permissions, current.userPermissions) !== "write") {
        throw new functions.https.HttpsError("permission-denied", "No write access to supervisors");
      }
      for (const change of diffScopedRecords(oldShared.supervisors, supervisorsBaseline, newShared.supervisors)) {
        if (!authorizeScopedRecord(change, callerRole, downline, (s) => s.id)) {
          throw new functions.https.HttpsError("permission-denied", "Supervisor is outside your downline scope");
        }
      }
    }
    // transactions/gifts/products/quotations — the app's OWN model treats these as
    // organization-wide shared data gated purely by section permission, not per-record
    // ownership (there is no per-record scoping for these client-side either) — mirrored
    // here as-is rather than inventing a stricter model the app doesn't actually have. These
    // are NOT downline-filtered on read (getAppData returns them in full whenever the caller
    // has view-or-write permission on the section), so no round-trip mismatch is possible
    // here — unchanged from before this phase.
    const sectionFor = { transactions: "marathon", gifts: "gifts", products: "products", quotations: "quotations" };
    for (const [field, section] of Object.entries(sectionFor)) {
      if (JSON.stringify(oldShared[field] || []) !== JSON.stringify(newShared[field] || [])) {
        if (getPermFor(section, callerRole, callerUid, current.permissions, current.userPermissions) !== "write") {
          throw new functions.https.HttpsError("permission-denied", `No write access to ${field}`);
        }
      }
    }

    // PHASE 7 — reconcile the value that actually gets PERSISTED (not just the check above).
    // For a non-privileged caller, `incoming.shared.X` is necessarily a filtered view and must
    // never be written wholesale — that would silently delete every out-of-scope record from
    // the real database (see the comment above reconcileScopedArray for why). Superadmin/admin
    // are untouched: reconcileScopedArray returns their `newShared.X` unchanged, exactly as
    // `merged = {...current, ...incoming}` already did before this phase.
    incoming.shared = {
      ...newShared,
      members: reconcileScopedArray(oldShared.members, newShared.members, callerRole, downline, resolveMember),
      coaches: reconcileScopedArray(oldShared.coaches, newShared.coaches, callerRole, downline, (c) => c.supervisorId),
      supervisors: reconcileScopedArray(oldShared.supervisors, newShared.supervisors, callerRole, downline, (s) => s.id),
    };
  }

  // perUser (isolated / dataSharing:false mode) — strictly own bucket only, or superadmin.
  //
  // FINDING B FIX — same round-trip class as shared.members/coaches/supervisors and profiles
  // above (see the Phase 7 comments there). getAppData() gives a non-privileged caller (not
  // superadmin, not admin) only their OWN perUser bucket — but the real client always
  // round-trips its ENTIRE local DB on every save (see cloudSave() in merged.html), so every
  // other uid's bucket is structurally absent from a non-privileged caller's submission, not an
  // attempted deletion. The old check compared straight against the full server-side
  // `oldPerUser`, so any uid other than the caller's own showing up "missing" was treated as an
  // unauthorized-edit attempt and the WHOLE save was rejected — confirmed reproducible: even a
  // completely unmodified round-trip of a supervisor's own authorized view was rejected with
  // "Cannot modify another user's isolated data". In practice this broke every save by every
  // non-admin/non-superadmin account the moment a second user had isolated data at all.
  //
  // Fix: compare against the caller's own VISIBLE baseline instead of the raw full server
  // value — the full object for privileged callers (superadmin/admin, who both receive the
  // full perUser object from getAppData, so a genuine mismatch for them IS a real edit
  // attempt), or just the caller's own bucket for everyone else. The actual persisted value is
  // reconciled the same way as profiles above: only superadmin gets full trust/full replace;
  // every other caller (including admin, which sees everything but is still write-restricted to
  // its own bucket, unchanged from before this fix) can only ever have their own bucket
  // persisted from what they submitted — every other uid's bucket is preserved verbatim from
  // the server's current authoritative value, never trusted from a non-superadmin's payload.
  if ("perUser" in incoming) {
    const oldPerUser = current.perUser || {};
    const newPerUser = incoming.perUser || {};
    const perUserIsPrivileged = callerRole === "superadmin" || callerRole === "admin";
    const baselinePerUser = perUserIsPrivileged ? oldPerUser : { [callerUid]: oldPerUser[callerUid] };
    const uids = new Set([...Object.keys(baselinePerUser), ...Object.keys(newPerUser)]);
    for (const uid of uids) {
      if (JSON.stringify(baselinePerUser[uid] || null) !== JSON.stringify(newPerUser[uid] || null)) {
        if (callerRole !== "superadmin" && uid !== callerUid) {
          throw new functions.https.HttpsError("permission-denied", "Cannot modify another user's isolated data");
        }
      }
    }
    if (callerRole === "superadmin") {
      // Unchanged from before this fix: full trust, full replace — incoming.perUser flows
      // straight into `merged` below exactly as submitted.
    } else {
      incoming.perUser = { ...oldPerUser, [callerUid]: newPerUser[callerUid] };
      if (newPerUser[callerUid] === undefined) delete incoming.perUser[callerUid];
    }
  }

  // profiles — a user may edit their own profile; editing anyone else's requires superadmin.
  // (Narrower than the previous client-only model, which also let a supervisor edit a
  // downline supervisor's profile — that specific action now requires superadmin. Disclosed
  // as an intentional tightening, not an oversight.)
  //
  // PHASE 7 — same round-trip class as shared.members/coaches/supervisors above: getAppData
  // gives a non-privileged caller a downline-filtered SUBSET of `profiles` (their own entry
  // plus anyone in their downline — see outProfiles in getAppData). Since a non-superadmin can
  // only ever legitimately WRITE their own key anyway (this block already enforced that), the
  // fix is simpler here than for the arrays: only the caller's own key is compared/trusted at
  // all for a non-privileged caller. Every other key's presence, absence, or content in
  // `incoming.profiles` is a byproduct of the caller's necessarily-filtered view, not a change
  // request, and is ignored rather than treated as an unauthorized-edit or deletion attempt.
  // Superadmin is untouched: full trust, full replace, exactly as before this phase.
  if ("profiles" in incoming) {
    const oldProfiles = current.profiles || {};
    const newProfiles = incoming.profiles || {};
    if (callerRole === "superadmin") {
      // Unchanged from before this phase: full trust, full replace — `incoming.profiles` is
      // left as-is and flows straight into `merged` below.
    } else {
      // Reconcile the PERSISTED value: preserve every other user's profile verbatim from the
      // server's authoritative current value (never trust a non-privileged caller's filtered
      // copy of someone else's profile — see the Phase 7 comment above), and take only the
      // caller's own key from what they submitted. Mirrors reconcileScopedArray's reasoning
      // for the array fields above. Own-profile edits (including deleting their own entry) are
      // always allowed, exactly as before this phase.
      incoming.profiles = { ...oldProfiles, [callerUid]: newProfiles[callerUid] };
      if (newProfiles[callerUid] === undefined) delete incoming.profiles[callerUid];
    }
  }

  // activityLog — was previously accepted as-is with no validation at all ("append/trim-only"
  // was a description of intended client behavior, not something the server enforced). That
  // let any approved user rewrite the audit trail arbitrarily: delete entries covering their
  // own actions, or insert fabricated entries attributing actions to other people. Now enforced
  // as genuinely append-only, and a caller can never attribute a new entry to anyone but
  // themselves.
  if ("activityLog" in incoming) {
    const oldLog = current.activityLog || [];
    const newLog = incoming.activityLog || [];
    if (JSON.stringify(oldLog) !== JSON.stringify(newLog)) {
      if (!Array.isArray(newLog) || newLog.length > 100) {
        throw new functions.https.HttpsError("invalid-argument", "activityLog must be an array of at most 100 entries");
      }
      // Find how many entries were newly prepended (k). Two cases, matching exactly what the
      // client's unshift-then-cap-at-100 logic produces:
      //  - total (k + oldLog.length) <= 100: no trimming occurs, so newLog must be exactly
      //    [added..., ...oldLog] with the FULL old log preserved as the tail — not merely a
      //    same-length prefix of it (a naive "does the tail match a same-length slice of
      //    oldLog" check would wrongly accept deleting oldLog's newest entry and relabeling an
      //    older one as freshly "added", as long as the attacker sets its user field to their
      //    own name).
      //  - total > 100: trimming occurs, so newLog.length must be exactly 100, and the tail
      //    must equal the surviving prefix of oldLog (the oldest entries fall off the cap).
      let addedCount = -1;
      for (let k = 1; k <= newLog.length; k++) {
        const totalIfUncapped = k + oldLog.length;
        const remainder = newLog.slice(k);
        if (totalIfUncapped <= 100) {
          if (newLog.length === totalIfUncapped && JSON.stringify(remainder) === JSON.stringify(oldLog)) {
            addedCount = k;
            break;
          }
        } else {
          if (newLog.length === 100 && JSON.stringify(remainder) === JSON.stringify(oldLog.slice(0, 100 - k))) {
            addedCount = k;
            break;
          }
        }
      }
      if (addedCount === -1) {
        throw new functions.https.HttpsError("permission-denied", "activityLog entries cannot be edited, reordered, or removed — only new entries may be prepended");
      }
      // Mirrors the client's getEditor(): the caller's own display name, falling back to their
      // username. A new entry's "user" field must match this — never someone else's.
      const callerUserRecord = (current.users || []).find(u => u.id === callerUid);
      const expectedEditor =
        (current.profiles && current.profiles[callerUid] && current.profiles[callerUid].displayName) ||
        (callerUserRecord && callerUserRecord.username) ||
        callerUid;
      for (let i = 0; i < addedCount; i++) {
        const entry = newLog[i];
        if (!entry || typeof entry !== "object") {
          throw new functions.https.HttpsError("invalid-argument", "Invalid activityLog entry");
        }
        if (entry.user !== expectedEditor) {
          throw new functions.https.HttpsError("permission-denied", "Cannot attribute an activity log entry to another user");
        }
      }
    }
  }

  const merged = { ...current, ...incoming };
  await writeAppData(merged);
  // Bumps the small public marker doc so every other connected client's onSnapshot listener
  // fires and re-fetches its own authorized view via getAppData() — this is the entire
  // real-time sync mechanism now that direct reads of the real document are denied. Best-
  // effort: if this write fails, the change is already saved and correct, it just won't
  // reliably prompt other tabs to refresh immediately (falls back to normal periodic reload).
  META_DOC.set({ updatedAt: admin.firestore.FieldValue.serverTimestamp() }).catch(() => {});
  return { ok: true };
});

/**
 * login({ username, pin })
 * Public — no auth required (this IS the auth step). Verifies the PIN against the hashed
 * credential store and, on success, mints a custom Firebase Auth token carrying the role
 * as a claim. The client never sees or compares a real PIN itself.
 */
exports.login = functions.https.onCall(async (data, context) => {
  checkAppCheck(context, "login");

  const username = String(data?.username || "").trim();
  const pin = String(data?.pin || "").trim();
  if (!username || !pin) {
    throw new functions.https.HttpsError("invalid-argument", "Username and PIN are required");
  }
  const usernameKey = username.toLowerCase();
  // Best-effort — Cloud Functions' rawRequest.ip reflects Google's own edge infrastructure and
  // can be influenced by proxies; it is NOT treated as a robust identity, only as a coarse,
  // defense-in-depth cap on top of the per-username lockout below, which is the real guarantee.
  const ip = (context.rawRequest && context.rawRequest.ip) || "unknown";

  // Checked BEFORE any real work — this single atomic transaction both checks lock state and
  // reserves the attempt slot, so a locked-out request is rejected fast and identically whether
  // or not the username exists, AND a burst of concurrent requests can't all slip past the
  // check before any of them is recorded (see reserveLoginAttempt() above — PHASE 4 FINDING 1).
  const { locked } = await reserveLoginAttempt(usernameKey, ip);
  if (locked) {
    throw new functions.https.HttpsError("resource-exhausted", "Too many attempts — please wait and try again.");
  }

  const current = await readAppData();
  const users = current.users || [];
  const user = users.find(u => (u.username || "").toLowerCase() === usernameKey);

  let entry = null;
  if (user) {
    const credSnap = await CRED_DOC.get();
    entry = credSnap.data()?.[user.id] || null;
  }
  // Always run a real bcrypt compare, even when there's no such user or no credential entry —
  // against a fixed dummy hash in that case — so response time is the same across "no such
  // account", "account has no PIN set", and "wrong PIN". This never weakens the real check for
  // an actual account: a genuine match still requires the real stored hash to match.
  const hashToCheck = (entry && entry.pinHash) ? entry.pinHash : DUMMY_HASH;
  const compareOk = await bcrypt.compare(pin, hashToCheck);
  const ok = compareOk && !!user && !!(entry && entry.pinHash);

  // The failed-attempt case was already recorded by reserveLoginAttempt() above; this only
  // needs to undo that speculative record on a genuine success.
  await finalizeLoginAttempt(usernameKey, ip, ok);

  if (!ok) {
    throw new functions.https.HttpsError("unauthenticated", "Invalid username or PIN");
  }

  const role = entry.role || user.role || "user";
  const claims = { approved: true, role };
  const token = await admin.auth().createCustomToken(user.id, claims);
  // createCustomToken's claims only ever land in the FIRST ID token obtained from it — Firebase's
  // automatic silent token refresh (roughly hourly) re-mints the ID token from whatever custom
  // claims are persisted on the Auth user record via setCustomUserClaims, not from a one-time
  // custom-token payload. Without this call, approved/role would silently vanish from the
  // caller's token about an hour into every session, and every Firestore/Cloud Function call
  // would start failing with permission-denied for no visible reason.
  await setClaimsEnsuringUserExists(user.id, claims);

  return {
    token,
    user: { id: user.id, username: user.username, role, linkedId: user.linkedId || null }
  };
});

/**
 * setUserPin({ targetUserId, newPin?, currentPin?, role?, renameFrom?, delete? })
 * Requires an authenticated caller. Covers every PIN-related write the app makes:
 *   - Self-service change:      targetUserId === caller's own uid, currentPin required.
 *   - Admin reset/create/edit:  caller must have the 'superadmin' role claim.
 *   - Admin reset w/ no newPin: server generates a PIN and returns it once, in plaintext,
 *                               for the admin to relay — it is never stored in plaintext.
 *   - renameFrom:               moves the credential entry from an old key to targetUserId
 *                               (login-ID rename), optionally also changing the PIN.
 *   - delete: true:             removes the credential entry entirely (account purge).
 */
exports.setUserPin = functions.https.onCall(async (data, context) => {
  checkAppCheck(context, "setUserPin");
  const { uid: callerUid, role: callerRole } = await verifyCallerToken(context);
  const targetUserId = String(data?.targetUserId || "").trim();
  if (!targetUserId) {
    throw new functions.https.HttpsError("invalid-argument", "targetUserId is required");
  }

  // The ONLY trusted source of the caller's privilege level is the role embedded in their
  // Firebase Auth token (freshly re-verified above, including revocation status) — never
  // anything in the request body. `data` is attacker-controlled input and is never read for
  // role/approved/isAdmin decisions.
  const isDelete = data?.delete === true;
  const renameFrom = data?.renameFrom ? String(data.renameFrom).trim() : null;
  const isSelfChange = targetUserId === callerUid && !isDelete && !renameFrom;

  if (isSelfChange) {
    // Self-service PIN change. This branch is structurally isolated from the admin logic
    // below it — it never reads data.role, data.approved, or anything else from the client
    // besides currentPin/newPin, and it always re-reads and re-writes the EXISTING role from
    // Firestore rather than trusting anything the caller sent. A normal user changing their
    // own PIN can never, under any input, change their own role through this path.
    const currentPin = String(data?.currentPin || "");
    const newPinRaw = data?.newPin ? String(data.newPin).trim() : "";
    if (newPinRaw.length < 4) {
      throw new functions.https.HttpsError("invalid-argument", "PIN must be at least 4 digits");
    }
    assertPinLength(newPinRaw);
    const credSnap = await CRED_DOC.get();
    const existing = credSnap.data()?.[targetUserId];
    if (!existing || !existing.pinHash) {
      throw new functions.https.HttpsError("failed-precondition", "No existing credential to verify against");
    }
    const ok = await bcrypt.compare(currentPin, existing.pinHash);
    if (!ok) {
      throw new functions.https.HttpsError("permission-denied", "Current PIN is incorrect");
    }
    const pinHash = await bcrypt.hash(newPinRaw, BCRYPT_ROUNDS);
    await CRED_DOC.set({ [targetUserId]: { pinHash, role: existing.role } }, { merge: true });
    // The PIN just changed, so any session issued before this moment — including the caller's
    // own current token, and including a stolen/still-valid one an attacker might hold — was
    // authenticated against a credential that no longer exists. Revoke all of it immediately,
    // the same way the delete/rename/admin-reset branches below already do, rather than letting
    // an old token keep working for up to its ~1 hour natural lifetime. This only runs after the
    // Firestore write above has already succeeded, so a failed PIN change (wrong currentPin, bad
    // length, no existing credential) never revokes anything.
    await admin.auth().revokeRefreshTokens(targetUserId).catch(() => {});
    return { ok: true };
  }

  // Every path below this line acts on an account OTHER than the caller's own (or is a
  // delete/rename), so it always requires the superadmin role — sourced only from the
  // caller's own token claim, never from the request body.
  if (callerRole !== "superadmin") {
    throw new functions.https.HttpsError("permission-denied", "Only a superadmin can do this");
  }

  if (isDelete) {
    // A superadmin targeting their own account for deletion is never a legitimate action this
    // function should perform — it would revoke their own credential and kill their own active
    // session in the same call, with no recovery path short of another superadmin existing (or
    // re-running the migration script). Reject it outright rather than letting it succeed.
    if (targetUserId === callerUid) {
      throw new functions.https.HttpsError("failed-precondition", "You cannot delete your own account.");
    }
    await CRED_DOC.set({ [targetUserId]: admin.firestore.FieldValue.delete() }, { merge: true });
    // Force out any currently-active session for this account immediately, rather than
    // letting it silently continue on a still-valid token for up to an hour after the
    // credential backing it was just removed.
    await admin.auth().revokeRefreshTokens(targetUserId).catch(() => {});
    return { ok: true };
  }

  if (renameFrom) {
    // renameFrom === targetUserId is a no-op rename (same key twice). Left unhandled, the
    // object literal below would silently collide — {[targetUserId]: {...}, [renameFrom]:
    // delete()} — with the delete() sentinel overwriting the update since they're the same
    // key, deleting the credential instead of updating it. There's no legitimate reason a
    // client would ever send an identical old/new id (a plain role/PIN update without a
    // rename already exists as its own path, below, and doesn't need renameFrom at all), so
    // this is rejected outright rather than given invented "helpful" no-op semantics.
    if (renameFrom === targetUserId) {
      throw new functions.https.HttpsError("invalid-argument", "renameFrom and targetUserId must be different.");
    }
    const credSnap = await CRED_DOC.get();
    const existing = credSnap.data()?.[renameFrom];
    if (!existing) {
      throw new functions.https.HttpsError("not-found", "Original login not found");
    }
    const newPinRaw = data?.newPin ? String(data.newPin).trim() : null;
    if (newPinRaw) assertPinLength(newPinRaw);
    const pinHash = newPinRaw ? await bcrypt.hash(newPinRaw, BCRYPT_ROUNDS) : existing.pinHash;
    const newRole = data?.role || existing.role || "user";
    await CRED_DOC.set({
      [targetUserId]: { pinHash, role: newRole },
      [renameFrom]: admin.firestore.FieldValue.delete()
    }, { merge: true });
    // The account's identity (its Firebase Auth uid) is changing from renameFrom to
    // targetUserId — persist claims under the new uid so a session started there is correct
    // immediately, and revoke the old uid's sessions since its credential no longer exists.
    await Promise.all([
      setClaimsEnsuringUserExists(targetUserId, { approved: true, role: newRole }).catch(() => {}),
      admin.auth().revokeRefreshTokens(renameFrom).catch(() => {})
    ]);
    return { ok: true };
  }

  // Plain create/update/reset — only reachable by a verified superadmin caller, acting on
  // someone else's account. data.role is trusted here ONLY because callerRole has already
  // been verified above; it is never read before that check.
  const newPinRaw = data?.newPin ? String(data.newPin).trim() : null;
  const wasGenerated = !newPinRaw;
  const newPin = newPinRaw || randomPin();
  if (newPin.length < 4) {
    throw new functions.https.HttpsError("invalid-argument", "PIN must be at least 4 digits");
  }
  assertPinLength(newPin);
  const credSnap = await CRED_DOC.get();
  const existing = credSnap.data()?.[targetUserId];
  const pinHash = await bcrypt.hash(newPin, BCRYPT_ROUNDS);
  const role = data?.role || existing?.role || "user";
  await CRED_DOC.set({ [targetUserId]: { pinHash, role } }, { merge: true });
  if (!existing || existing.role !== role) {
    // A real role change (or a brand-new account) — persist the claim now and force any
    // currently-active session for this account to re-authenticate, so a promotion or
    // demotion takes effect right away instead of silently waiting for the next natural
    // token refresh (up to ~an hour) or next login.
    await Promise.all([
      setClaimsEnsuringUserExists(targetUserId, { approved: true, role }).catch(() => {}),
      admin.auth().revokeRefreshTokens(targetUserId).catch(() => {})
    ]);
  }

  return wasGenerated ? { ok: true, newPin } : { ok: true };
});
