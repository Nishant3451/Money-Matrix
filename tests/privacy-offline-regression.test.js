// ============================================================================================
// HARDENING CORRECTION #1 -- Offline privacy operations must never falsely succeed.
//
// acceptPolicy(), submitPrivacyRequest(), requestDeletion(), updatePrivacyRequestStatus(), and
// publishCurrentPolicyVersions() used to have `if(!firebaseAvailable){ ...mutate DB directly...
// save(true); }` branches that fabricated authoritative privacy records and reported success
// with zero server involvement. This file extracts the ACTUAL functions from index.html (same
// technique as tests/flavor-alert-customsection-adversarial.test.js: real jsdom execution of the
// real shipped source, not a reimplementation) and proves, for each one, that when
// `firebaseAvailable` is false:
//   1. callWorkerApi is never called AND DB's authoritative privacy field is never mutated, and
//   2. a clear "unavailable offline" message is shown -- never "submitted"/"recorded"/"saved"/
//      "published"/"accepted".
// A second block proves the normal ONLINE path (firebaseAvailable = true) is unchanged: it still
// calls the real endpoint and updates DB only from the server's response.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

function extractWindowFn(source, name) {
  const marker = `window.${name} = `;
  const start = source.indexOf(marker);
  if (start === -1) throw new Error(`window.${name} not found in index.html`);
  const bodyStart = start + marker.length;
  const openBrace = source.indexOf("{", bodyStart);
  let depth = 0, i = openBrace;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(bodyStart, i + 1);
}

const FN_SOURCE = {
  acceptPolicy: extractWindowFn(html, "acceptPolicy"),
  submitPrivacyRequest: extractWindowFn(html, "submitPrivacyRequest"),
  requestDeletion: extractWindowFn(html, "requestDeletion"),
  updatePrivacyRequestStatus: extractWindowFn(html, "updatePrivacyRequestStatus"),
  publishCurrentPolicyVersions: extractWindowFn(html, "publishCurrentPolicyVersions"),
};

/** Builds a jsdom window with every global these functions touch stubbed out, defines the one
 * real (extracted-from-index.html) function under test on it, and returns handles for
 * inspecting what happened. `formValues` seeds what `$(id).value` returns (for the functions
 * that read form fields). `firebaseAvailable` controls the scenario under test. */
function makeHarness({ firebaseAvailable, formValues = {}, initialDB = {} }) {
  const dom = new JSDOM(`<!DOCTYPE html><body></body>`, { runScripts: "dangerously" });
  const { window } = dom;
  window.__calls = { callWorkerApi: [], save: [], toast: [], handleError: [], handleSuccess: [], render: 0 };
  window.firebaseAvailable = firebaseAvailable;
  window.currentUser = { id: "u1", username: "alice", role: "admin" };
  window.DB = Object.assign(
    { privacyRequests: [], policyAcceptances: {}, policyVersions: [], privacyConsents: {}, users: [{ id: "u1", username: "alice", role: "admin" }] },
    initialDB
  );
  window.__formValues = formValues;
  window.$ = (id) => ({ get value() { return window.__formValues[id] ?? ""; }, set value(v) { window.__formValues[id] = v; } });
  window.callWorkerApi = async (...args) => {
    window.__calls.callWorkerApi.push(args);
    // Canned success responses for the ONLINE-path tests; the OFFLINE-path tests assert this is
    // never reached at all, so what it returns there is moot.
    const [pathArg, body] = args;
    if (pathArg === "/privacy/policy/accept") return { data: { ok: true } };
    if (pathArg === "/privacy/request") return { data: { request: { id: "req_server_1", uid: "u1", ...body, status: "requested", submittedAt: Date.now(), adminNotes: "" } } };
    if (pathArg === "/privacy/delete") return { data: { request: { id: "req_server_del", uid: "u1", category: "deletion", status: "requested", submittedAt: Date.now(), adminNotes: "" } } };
    if (pathArg === "/privacy/request/status") return { data: { request: { id: body.requestId, status: body.status, adminNotes: body.adminNotes, updatedAt: Date.now() } } };
    if (pathArg === "/privacy/policy/publish") return { data: { policyVersions: [{ type: body.type, version: body.version, effectiveDate: body.effectiveDate, status: body.status }] } };
    throw new Error(`unexpected callWorkerApi path in test: ${pathArg}`);
  };
  window.mmBtnBusy = () => ({
    success: (label) => window.__calls.handleSuccess.push(label),
    error: (label) => window.__calls.handleError.push(label),
  });
  window.toast = (msg) => window.__calls.toast.push(msg);
  window.closeModal = () => {};
  window.renderPrivacyTabBody = () => { window.__calls.render++; };
  window.renderPrivacyCenter = () => { window.__calls.render++; };
  window.save = (...a) => window.__calls.save.push(a);
  window.showConfirmModal = (opts) => { window.__confirmPromise = opts.onConfirm(); };
  window.POLICY_CONTENT = {
    privacy_policy: { title: "Privacy Policy", version: "2.0", body: "policy text" },
  };
  window.PRIVACY_POLICY_VERSION = "2.0";
  return { window };
}

function defineAndCall(window, fnName, argsExpr) {
  const code = `window.${fnName} = ${FN_SOURCE[fnName]}; window.__resultPromise = window.${fnName}(${argsExpr});`;
  window.eval(code);
  return window.__resultPromise;
}

// ---------------------------------------------------------------------------------------------
// OFFLINE: none of these may call callWorkerApi, mutate the authoritative DB field, or report
// success.
// ---------------------------------------------------------------------------------------------

test("OFFLINE acceptPolicy: does not call the server, does not write DB.policyAcceptances, shows 'unavailable offline'", async () => {
  const { window } = makeHarness({ firebaseAvailable: false });
  await defineAndCall(window, "acceptPolicy", `"privacy_policy", null`);
  assert.deepEqual(window.__calls.callWorkerApi, []);
  assert.deepEqual(window.DB.policyAcceptances, {}, "no acceptance record may be fabricated offline");
  assert.equal(window.__calls.save.length, 0, "must not persist a fabricated acceptance");
  assert.ok(window.__calls.toast.some((m) => /unavailable offline/i.test(m)), `expected an 'unavailable offline' toast, got: ${JSON.stringify(window.__calls.toast)}`);
  assert.ok(!window.__calls.toast.some((m) => /accepted/i.test(m)), "must never claim the policy was accepted");
});

test("OFFLINE submitPrivacyRequest: does not call the server, does not write DB.privacyRequests, shows 'unavailable offline'", async () => {
  const { window } = makeHarness({ firebaseAvailable: false, formValues: { pr_category: "access", pr_desc: "please show my data" } });
  await defineAndCall(window, "submitPrivacyRequest", `null`);
  assert.deepEqual(window.__calls.callWorkerApi, []);
  assert.deepEqual(window.DB.privacyRequests, [], "no privacy request may be fabricated offline");
  assert.equal(window.__calls.save.length, 0);
  assert.ok(window.__calls.toast.some((m) => /unavailable offline/i.test(m)));
  assert.ok(!window.__calls.toast.some((m) => /submitted/i.test(m)), "must never claim the request was submitted");
});

test("OFFLINE requestDeletion: does not call the server, does not write DB.privacyRequests, shows 'unavailable offline'", async () => {
  const { window } = makeHarness({ firebaseAvailable: false });
  window.eval(`window.requestDeletion = ${FN_SOURCE.requestDeletion}; window.requestDeletion();`);
  await window.__confirmPromise;
  assert.deepEqual(window.__calls.callWorkerApi, []);
  assert.deepEqual(window.DB.privacyRequests, [], "no deletion request may be fabricated offline");
  assert.equal(window.__calls.save.length, 0);
  assert.ok(window.__calls.toast.some((m) => /unavailable offline/i.test(m)));
  assert.ok(!window.__calls.toast.some((m) => /submitted/i.test(m)), "must never claim a deletion request was submitted");
});

test("OFFLINE updatePrivacyRequestStatus: does not call the server, does not mutate the existing request, shows 'unavailable offline'", async () => {
  const existing = { id: "req1", uid: "someone", status: "requested", adminNotes: "", submittedAt: 1, updatedAt: 1 };
  const { window } = makeHarness({
    firebaseAvailable: false,
    formValues: { pra_status: "completed", pra_notes: "handled" },
    initialDB: { privacyRequests: [existing] },
  });
  await defineAndCall(window, "updatePrivacyRequestStatus", `"req1", null`);
  assert.deepEqual(window.__calls.callWorkerApi, []);
  assert.deepEqual(window.DB.privacyRequests[0], existing, "the existing request record must be completely untouched offline");
  assert.equal(window.__calls.save.length, 0);
  assert.ok(window.__calls.toast.some((m) => /unavailable offline/i.test(m)));
  assert.ok(!window.__calls.toast.some((m) => /updated/i.test(m)), "must never claim the request was updated");
});

test("OFFLINE publishCurrentPolicyVersions: does not call the server, does not write DB.policyVersions, shows 'unavailable offline'", async () => {
  const { window } = makeHarness({ firebaseAvailable: false });
  await defineAndCall(window, "publishCurrentPolicyVersions", `null`);
  assert.deepEqual(window.__calls.callWorkerApi, []);
  assert.deepEqual(window.DB.policyVersions, [], "no policy version may be fabricated/published offline");
  assert.equal(window.__calls.save.length, 0);
  assert.ok(window.__calls.toast.some((m) => /unavailable offline/i.test(m)));
  assert.ok(!window.__calls.toast.some((m) => /published/i.test(m)), "must never claim a policy version was published");
});

// ---------------------------------------------------------------------------------------------
// ONLINE regression guard: the normal path must be completely unaffected by this fix -- it still
// calls the real endpoint and only updates DB from what the (mocked) server actually returned.
// ---------------------------------------------------------------------------------------------

test("ONLINE acceptPolicy: calls the server and records the acceptance from its response", async () => {
  const { window } = makeHarness({ firebaseAvailable: true });
  await defineAndCall(window, "acceptPolicy", `"privacy_policy", null`);
  assert.equal(window.__calls.callWorkerApi.length, 1);
  assert.equal(window.__calls.callWorkerApi[0][0], "/privacy/policy/accept");
  assert.ok(window.DB.policyAcceptances.u1.privacy_policy, "acceptance should be recorded after a real server call");
});

test("ONLINE submitPrivacyRequest: calls the server and stores the server's own request record (not a client-fabricated one)", async () => {
  const { window } = makeHarness({ firebaseAvailable: true, formValues: { pr_category: "access", pr_desc: "please show my data" } });
  await defineAndCall(window, "submitPrivacyRequest", `null`);
  assert.equal(window.__calls.callWorkerApi.length, 1);
  assert.equal(window.__calls.callWorkerApi[0][0], "/privacy/request");
  assert.equal(window.DB.privacyRequests[0].id, "req_server_1", "the stored record must be the SERVER's id, proving it came from the response, not a client-generated one");
});

test("ONLINE requestDeletion: calls the server and stores the server's own request record", async () => {
  const { window } = makeHarness({ firebaseAvailable: true });
  window.eval(`window.requestDeletion = ${FN_SOURCE.requestDeletion}; window.requestDeletion();`);
  await window.__confirmPromise;
  assert.equal(window.__calls.callWorkerApi.length, 1);
  assert.equal(window.__calls.callWorkerApi[0][0], "/privacy/delete");
  assert.equal(window.DB.privacyRequests[0].id, "req_server_del");
});

test("ONLINE publishCurrentPolicyVersions: calls the server for each policy type and stores the server's returned list", async () => {
  const { window } = makeHarness({ firebaseAvailable: true });
  await defineAndCall(window, "publishCurrentPolicyVersions", `null`);
  assert.ok(window.__calls.callWorkerApi.length >= 1);
  assert.equal(window.__calls.callWorkerApi[0][0], "/privacy/policy/publish");
  assert.equal(window.DB.policyVersions[0].type, "privacy_policy");
});
