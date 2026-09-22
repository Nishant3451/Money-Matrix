// ============================================================================================
// Post-login Policy Gate + policy-acceptance publication-gating (Part 4/5/6 of the fix).
//
// These extract the ACTUAL functions from index.html (same technique as
// tests/client-logic.test.js and the computePaymentTotals tests) into a jsdom sandbox with the
// real $, esc, sj, toast, mmBtnBusy helpers (also pulled from index.html) plus a fake
// callWorkerApi so the exact request/response contract can be pinned without a real Worker.
// A full click-path boot (real <script>, real onclick) for My Data / Submit Request / Deletion
// already lives in tests/privacy-center-actions.test.js; this file focuses on the gate and the
// publish-then-accept dependency the live bug report turned up.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const mod = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Pulls a real function out of the module source and returns it as a properly named function
// declaration, whether it was written as `function name(...)`, `window.name = (...) => {...}`,
// or `window.name = async (...) => {...}`.
function extractFunction(source, name) {
  let m = source.match(new RegExp(`function\\s+${name}\\s*\\(`));
  if (m) {
    const open = source.indexOf("{", m.index);
    let depth = 0, i = open;
    for (; i < source.length; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") { depth--; if (depth === 0) break; } }
    return source.slice(m.index, i + 1);
  }
  m = source.match(new RegExp(`window\\.${name}\\s*=\\s*(async\\s*)?\\(([^)]*)\\)\\s*=>\\s*\\{`));
  if (m) {
    const open = m.index + m[0].length - 1;
    let depth = 0, i = open;
    for (; i < source.length; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") { depth--; if (depth === 0) break; } }
    return `${m[1] || ""}function ${name}(${m[2]}) ` + source.slice(open, i + 1);
  }
  throw new Error(`${name} not found`);
}
function between(source, a, b) { const i = source.indexOf(a); const j = source.indexOf(b, i); return source.slice(i, j); }

const POLICY_VERSION_CONSTS = mod.match(/^const PRIVACY_POLICY_VERSION = .*\n(?:const \w+_VERSION = .*\n){3}/m)[0];
const POLICY_CONTENT_SRC = POLICY_VERSION_CONSTS + between(mod, "const POLICY_CONTENT = {", "\nlet privacyTab");
const HELPERS_SRC = [
  mod.match(/^const sj=.*$/m)[0],
  mod.match(/^const \$=.*$/m)[0],
  mod.match(/^const esc=.*$/m)[0],
  mod.match(/^const mmReducedMotion = .*$/m)[0],
  extractFunction(mod, "mmBtnBusy"),
  mod.match(/^function toast\(m\).*$/m)[0],
  extractFunction(mod, "mmDismissToast"),
].join("\n");
const CORE_SRC = [
  extractFunction(mod, "privacyFailureText"),
  extractFunction(mod, "policyStatus"),
  extractFunction(mod, "isPolicyPublished"),
  extractFunction(mod, "policiesNeedingAcceptance"),
  extractFunction(mod, "showPolicyGateError"),
].join("\n\n");

function buildSandbox({ dbExtra = {}, firebaseAvailable = true, hasCurrentUser = true, apiImpl }) {
  const dom = new JSDOM(`<!DOCTYPE html><body></body>`, { runScripts: "outside-only" });
  const w = dom.window;
  const calls = [];
  const ctx = vm.createContext(w);
  const __script = `
    ${POLICY_CONTENT_SRC.replace("\nlet privacyTab", "")}
    ${HELPERS_SRC}
    var DB = ${JSON.stringify({ policyAcceptances: {}, ...dbExtra })};
    var currentUser = ${hasCurrentUser ? '{id:"u1",username:"bob",role:"user"}' : "null"};
    var firebaseAvailable = ${firebaseAvailable};
    var serverViewReceived = true;
    var __calls = [];
    async function callWorkerApi(path, body){ __calls.push({path, body}); const r = (${(apiImpl || (() => ({ data: { ok: true } }))).toString()})(path, body); return r instanceof Promise ? await r : r; }
    ${CORE_SRC}
    // Minimal viewPolicy so acceptPolicy's callers work without pulling in the modal system
    var viewedPolicies = [];
    function viewPolicy(type){ viewedPolicies.push(type); }
    function closeModal(){}
    function renderPrivacyCenter(){}
    function afterPolicyAccepted(){ if(typeof enforcePolicyGate === "function") enforcePolicyGate(); }
    ${extractFunction(mod, "acceptPolicy")}
    ${extractFunction(mod, "enforcePolicyGate")}
    ${extractFunction(mod, "acceptAllPolicies")}
    window.__t = { policyStatus, isPolicyPublished, policiesNeedingAcceptance, acceptPolicy, enforcePolicyGate, acceptAllPolicies, get calls(){ return __calls; }, get DB(){ return DB; } };
  `;
  w.eval(__script);
  return { w, doc: w.document, t: w.__t };
}

const PUBLISHED_ALL = [
  { type: "privacy_policy", version: "1.3", effectiveDate: "2026-09-18", status: "published" },
  { type: "terms_of_service", version: "1.1", effectiveDate: "2026-09-18", status: "published" },
  { type: "cookie_policy", version: "1.2", effectiveDate: "2026-09-18", status: "published" },
  { type: "data_rights", version: "1.2", effectiveDate: "2026-09-18", status: "published" },
];

test("policiesNeedingAcceptance: only PUBLISHED + not-yet-accepted (by this user, for the CURRENT app version) shows up", () => {
  const { t } = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL.slice(0, 2) } }); // only 2 of 4 published
  assert.deepEqual(JSON.parse(JSON.stringify(t.policiesNeedingAcceptance())), ["privacy_policy", "terms_of_service"]);
  const { t: t2 } = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL, policyAcceptances: { u1: { privacy_policy: { version: "1.3", timestamp: 1 }, terms_of_service: { version: "1.1", timestamp: 1 }, cookie_policy: { version: "1.2", timestamp: 1 }, data_rights: { version: "1.2", timestamp: 1 } } } } });
  assert.deepEqual(JSON.parse(JSON.stringify(t2.policiesNeedingAcceptance())), [], "all four accepted -> nothing needed");
  const { t: t3 } = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL, policyAcceptances: { u1: { privacy_policy: { version: "1.2", timestamp: 1 } } } } });
  assert.ok(t3.policiesNeedingAcceptance().includes("privacy_policy"), "accepted an OLD version -> still needed");
});

test("Login policy gate: authenticated user with missing acceptance gets the gate; with current acceptance does not", async () => {
  const noAccept = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, apiImpl: () => ({ data: { ok: true } }) });
  noAccept.w.eval(`enforcePolicyGate()`);
  assert.ok(noAccept.doc.getElementById("policyGate"), "gate shown");
  assert.match(noAccept.doc.getElementById("policyGate").textContent, /Review . accept our policies/);

  const fullAccept = { u1: Object.fromEntries(PUBLISHED_ALL.map((p) => [p.type, { version: p.version, timestamp: 1 }])) };
  const accepted = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL, policyAcceptances: fullAccept }, apiImpl: () => ({ data: { ok: true } }) });
  accepted.w.eval(`enforcePolicyGate()`);
  assert.equal(accepted.doc.getElementById("policyGate"), null, "no gate once current versions are accepted");
});

test("Login policy gate: unauthenticated visitor and offline user get no gate (nothing to enforce against)", () => {
  const noUser = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, hasCurrentUser: false, apiImpl: () => ({ data: { ok: true } }) });
  noUser.w.eval(`enforcePolicyGate()`);
  assert.equal(noUser.doc.getElementById("policyGate"), null);
  const offline = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, firebaseAvailable: false, apiImpl: () => ({ data: { ok: true } }) });
  offline.w.eval(`enforcePolicyGate()`);
  assert.equal(offline.doc.getElementById("policyGate"), null);
});

test("acceptAllPolicies: requires the checkbox, sends the exact contract per policy, records ONLY after server confirms, and closes the gate", async () => {
  const { w, doc, t } = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, apiImpl: () => ({ data: { ok: true } }) });
  w.eval(`enforcePolicyGate()`);
  const btn = () => doc.getElementById("pgAcceptBtn");
  w.eval(`acceptAllPolicies(document.getElementById('pgAcceptBtn'))`);
  await sleep(20);
  assert.match(doc.getElementById("pgError").textContent, /tick the box/);
  assert.equal(t.calls.length, 0, "nothing sent before the checkbox is ticked");

  doc.getElementById("pgAgree").checked = true;
  w.eval(`acceptAllPolicies(document.getElementById('pgAcceptBtn'))`);
  await sleep(30);
  assert.equal(t.calls.length, 4);
  for (const c of t.calls) {
    assert.equal(c.path, "/privacy/policy/accept");
    assert.deepEqual(JSON.parse(JSON.stringify(Object.keys(c.body).sort())), ["policyType", "version"]);
    // no uid/user identity is ever sent from the browser
  }
  assert.deepEqual(JSON.parse(JSON.stringify(t.calls.map((c) => c.body.policyType).sort())), ["cookie_policy", "data_rights", "privacy_policy", "terms_of_service"]);
  assert.equal(Object.keys(t.DB.policyAcceptances.u1).length, 4);
  assert.equal(doc.getElementById("policyGate"), null, "gate removes itself once nothing is left to accept");
});

test("acceptAllPolicies: a failure stops at that policy, records nothing for it, keeps the gate open, and shows the real reason", async () => {
  const { w, doc, t } = buildSandbox({
    dbExtra: { policyVersions: PUBLISHED_ALL },
    apiImpl: (path, body) => { if (body.policyType === "cookie_policy") throw Object.assign(new Error("Too many requests"), { code: "functions/resource-exhausted", status: 429 }); return { data: { ok: true } }; },
  });
  w.eval(`enforcePolicyGate()`);
  doc.getElementById("pgAgree").checked = true;
  w.eval(`acceptAllPolicies(document.getElementById('pgAcceptBtn'))`);
  await sleep(50);
  assert.ok(doc.getElementById("policyGate"), "gate stays open");
  assert.match(doc.getElementById("pgError").textContent, /reached the limit/);
  assert.equal(t.DB.policyAcceptances.u1 ? Object.keys(t.DB.policyAcceptances.u1).length < 4 : true, true, "the failed policy (and anything after it) is not recorded");
});

test("acceptPolicy: never records locally before the server confirms, and a malformed 200 counts as failure", async () => {
  const bad = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, apiImpl: () => ({ data: {} }) }); // no ok:true
  await bad.w.eval(`acceptPolicy('privacy_policy', null, {quiet:true})`);
  await sleep(20);
  assert.deepEqual(JSON.parse(JSON.stringify(bad.t.DB.policyAcceptances)), {});
  const thrown = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, apiImpl: () => { throw Object.assign(new Error("x"), { status: 500 }); } });
  await thrown.w.eval(`acceptPolicy('privacy_policy', null, {quiet:true})`);
  await sleep(20);
  assert.deepEqual(JSON.parse(JSON.stringify(thrown.t.DB.policyAcceptances)), {});
});

test("acceptPolicy: offline never fabricates an acceptance and never calls the server", async () => {
  const { w, t } = buildSandbox({ dbExtra: { policyVersions: PUBLISHED_ALL }, firebaseAvailable: false, apiImpl: () => ({ data: { ok: true } }) });
  await w.eval(`acceptPolicy('privacy_policy', null, {quiet:true})`);
  await sleep(20);
  assert.equal(t.calls.length, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(t.DB.policyAcceptances)), {});
});

// ------------------------------------------------------------------------------------------
// Source-level pins: login markup, boot-time hooks, and the /privacy/request category list the
// Worker actually accepts (guards PART 1/2's category contract from silently drifting).
// ------------------------------------------------------------------------------------------
test("Login page: has a read-only Policies & Terms area wired to the same POLICY_CONTENT; nothing is auto-accepted by signing in", () => {
  assert.match(html, /id="loginPolicies"/);
  assert.match(mod, /function renderLoginPolicies\(\)\{[\s\S]{0,400}Object\.keys\(POLICY_CONTENT\)/);
  assert.match(mod, /renderLoginPolicies\(\);\nconst sess=sessionStorage/);
  // doLogin() itself never calls acceptPolicy / writes policyAcceptances
  const doLoginSrc = mod.slice(mod.indexOf("window.doLogin = async"), mod.indexOf("$(\"usernameInput\").addEventListener"));
  assert.doesNotMatch(doLoginSrc, /acceptPolicy|policyAcceptances/);
});

test("The gate is wired into every path that can start a session: completeLogin, applyRemoteJson, and the restored-session boot branch", () => {
  assert.match(mod, /startSessionWatcher\(\);\n\s*enforcePolicyGate\(\);\n\}\nfunction isSessionExpired/, "completeLogin");
  assert.match(mod, /applyingRemote = false;\n\s*serverViewReceived = true;\n\s*if\(currentUser\) render\(\);\n\s*enforcePolicyGate\(\);\n\}/, "applyRemoteJson");
  assert.match(mod, /startSessionWatcher\(\);\n\s*enforcePolicyGate\(\);\n\s*\} else \{/, "restored-session boot branch");
});

test("Worker contract pins: /privacy/policy/accept payload shape and the accepted /privacy/request categories are unchanged", () => {
  assert.match(mod, /callWorkerApi\("\/privacy\/policy\/accept", \{ policyType: type, version: policy\.version \}/);
  const categories = [...doc_options()];
  function doc_options(){ const m = mod.match(/pr_category">([\s\S]*?)<\/select>/); return [...m[1].matchAll(/value="(\w+)"/g)].map((x) => x[1]); }
  assert.deepEqual(categories, ["access", "correction", "consent_question", "complaint", "security_concern", "other"]);
});
