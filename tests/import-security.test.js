// ============================================================================================
// Import security / adversarial tests (Part A3, A7, A5).
//
// performApplyImport() and safeImportId() are extracted straight from index.html (same
// technique as the other frontend logic tests) so these exercise the real shipped code.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

function extractFunction(source, name) {
  const startMatch = source.match(new RegExp(`function\\s+${name}\\s*\\(`));
  if (!startMatch) throw new Error(`function ${name} not found in index.html`);
  const start = startMatch.index;
  const openBrace = source.indexOf("{", start);
  let depth = 0, i = openBrace;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(start, i + 1);
}

function buildSandbox({ ownBucket, snapshotCalls = [] } = {}) {
  const state = {
    d: ownBucket || { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [], custom: {} },
    closedModal: false,
    rendered: false,
    toasts: [],
    saved: false,
  };
  const nidSrc = 'function nid(){ return "id_" + Date.now() + "_" + Math.random().toString(36).slice(2,8); }';
  const src = [nidSrc, extractFunction(html, "safeImportId"), extractFunction(html, "performApplyImport")].join("\n\n");
  const sandbox = {
    data: () => state.d,
    pendingImportData: null,
    takeSnapshot: (label) => snapshotCalls.push(label),
    save: () => { state.saved = true; },
    closeModal: () => { state.closedModal = true; },
    render: () => { state.rendered = true; },
    toast: (m) => state.toasts.push(m),
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return { sandbox, state };
}

test("safeImportId: accepts a normal previously-exported nid()-shaped id", () => {
  const { sandbox } = buildSandbox();
  const id = "id_1699999999999_ab12cd";
  assert.equal(sandbox.safeImportId(id), id);
});

test("safeImportId: rejects and regenerates an id containing quote/JS-breakout characters", () => {
  const { sandbox } = buildSandbox();
  const malicious = "x');alert(1);//";
  const result = sandbox.safeImportId(malicious);
  assert.notEqual(result, malicious);
  assert.match(result, /^id_/);
});

test("safeImportId: rejects an oversized id string", () => {
  const { sandbox } = buildSandbox();
  const oversized = "a".repeat(500);
  const result = sandbox.safeImportId(oversized);
  assert.notEqual(result, oversized);
});

test("safeImportId: rejects a non-string id (object/array injection attempt)", () => {
  const { sandbox } = buildSandbox();
  assert.match(sandbox.safeImportId({ $ne: null }), /^id_/);
  assert.match(sandbox.safeImportId(["a", "b"]), /^id_/);
  assert.match(sandbox.safeImportId(null), /^id_/);
  assert.match(sandbox.safeImportId(undefined), /^id_/);
});

test("performApplyImport: clients are now imported (fixes the Phase 3 backup-restore gap)", () => {
  const { sandbox, state } = buildSandbox();
  sandbox.pendingImportData = {
    clients: [{ id: "id_client_1", name: "Rahul Patel", phone: "9876543210" }],
    transactions: [{ id: "id_tx_1", customer: "Rahul Patel", clientId: "id_client_1", amount: 500 }],
  };
  sandbox.performApplyImport("merge");
  assert.equal(state.d.clients.length, 1);
  assert.equal(state.d.clients[0].name, "Rahul Patel");
  assert.equal(state.d.transactions[0].clientId, "id_client_1", "the clientId link survives the round trip");
});

test("performApplyImport: legacy transactions with no clientId import cleanly", () => {
  const { sandbox, state } = buildSandbox();
  sandbox.pendingImportData = {
    transactions: [{ id: "id_tx_legacy", customer: "Old Customer", amount: 200 }],
  };
  sandbox.performApplyImport("merge");
  assert.equal(state.d.transactions[0].clientId, undefined);
  assert.equal(state.d.transactions[0].customer, "Old Customer");
});

test("performApplyImport: a malicious client id is sanitized on import, not trusted verbatim", () => {
  const { sandbox, state } = buildSandbox();
  sandbox.pendingImportData = {
    clients: [{ id: "x');window.__xss=true;//", name: "Attacker" }],
  };
  sandbox.performApplyImport("merge");
  assert.equal(state.d.clients.length, 1);
  assert.notEqual(state.d.clients[0].id, "x');window.__xss=true;//");
  assert.match(state.d.clients[0].id, /^id_/);
});

test("performApplyImport: import only ever writes into the caller's own already-scoped data() bucket", () => {
  // data() here stands in for whatever bucket the Worker has already authorized for this
  // caller — performApplyImport has no code path that reaches any other bucket, there is no
  // uid/ownerId parameter it could use to target one even if it wanted to.
  const ownBucket = { transactions: [], members: [], gifts: [], coaches: [], supervisors: [], clients: [], custom: {} };
  const { sandbox, state } = buildSandbox({ ownBucket });
  sandbox.pendingImportData = { clients: [{ id: "id_c1", name: "Someone", ownerId: "someone_elses_uid" }] };
  sandbox.performApplyImport("merge");
  // the record lands in the (single, already-scoped) bucket regardless of a forged ownerId field
  assert.equal(state.d.clients.length, 1);
  assert.equal(state.d, ownBucket);
});

test("performApplyImport: imported client name flows through esc() safely at render (no executable HTML)", () => {
  const { sandbox, state } = buildSandbox();
  const escSrcMatch = html.match(/^const esc=.*$/m);
  const esc = new Function(`${escSrcMatch[0]}\nreturn esc;`)();
  sandbox.pendingImportData = { clients: [{ id: "id_c1", name: '"><img src=x onerror=alert(1)>' }] };
  sandbox.performApplyImport("merge");
  const rendered = `<b>${esc(state.d.clients[0].name)}</b>`;
  assert.ok(!rendered.includes("<img"), "imported malicious name must not survive as live HTML");
});

// ---- PHASE 6.1, CASE I/J: a malicious/forged backup file cannot inject a superadmin record ----
// performApplyImport() only ever reads the six record collections + `custom` (see its source) —
// it has no code path that reads sd.users, sd.role, sd.permissions, sd.userPermissions, or
// sd.linkedId at all, so a hand-crafted backup file's forged "users" array (with a fake
// superadmin entry) is never even copied into the in-memory data() object here, let alone sent
// onward to /data/save. This is a defense-in-depth confirmation on top of the server-side
// guarantee (authorization.js's mergeAuthorizedSave / sanitizeUsersForFullAccessSave — see
// PHASE-6.1-PRIVILEGE-ESCALATION-REPORT.md) that would ALSO reject it if it somehow were sent.
test("PHASE 6.1 CASE I/J: a backup file's forged users[] (incl. a fake superadmin) is never read by performApplyImport", () => {
  const { sandbox, state } = buildSandbox();
  sandbox.pendingImportData = {
    transactions: [{ id: "id_tx1", amount: 50 }],
    // A malicious/forged top-level users array, exactly as a hand-edited backup file could ship:
    users: [{ id: "attacker", username: "attacker", role: "superadmin", linkedId: null }],
    role: "superadmin",
    permissions: { user: { dashboard: "write" } },
    userPermissions: { attacker: { everything: "write" } },
  };
  sandbox.performApplyImport("merge");
  // The legitimate collection import still works...
  assert.equal(state.d.transactions.length, 1);
  // ...but nothing resembling users/role/permissions ever lands anywhere in the resulting state.
  assert.equal(state.d.users, undefined, "performApplyImport must never create/populate a users[] field");
  assert.equal(state.d.role, undefined);
  assert.equal(state.d.permissions, undefined);
  assert.equal(state.d.userPermissions, undefined);
});
