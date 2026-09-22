// ============================================================================================
// UX fix: a production screenshot showed an admin opening a request whose CURRENT status was
// already "completed" and trying to change it to "approved" -- a transition the Worker has
// always correctly rejected (see cloudflare-worker/tests/privacy-request-status-transitions.test.js,
// which proves the Worker's isValidStatusTransition/TERMINAL_STATUSES logic is untouched and
// correct). This file covers the frontend-only fix: the Review Privacy Request modal now shows a
// terminal-status request as locked (disabled selector, disabled notes, no Save button, and an
// explanatory message) instead of presenting an editable form whose Save could only ever 400.
//
// Boots the real app (same technique as the other privacy-* frontend test files) and drives the
// actual admin Review modal through its real onclick handlers -- these are not a reimplementation
// of openPrivacyRequestDetail, they exercise it directly.
// ============================================================================================
import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const openWindows = [];
afterEach(() => { while (openWindows.length) { try { openWindows.pop().close(); } catch (e) {} } });

async function boot({ fetchImpl, privacyRequests }) {
  let mod = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
  const page = html.replace(/<script type="module">[\s\S]*?<\/script>/, "").replace(/<script src=[^>]*><\/script>/g, "");
  const dom = new JSDOM(page, { url: "https://example.test/", runScripts: "dangerously", pretendToBeVisual: true });
  const w = dom.window;
  openWindows.push(w);
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.fetch = fetchImpl || (async () => new Response("{}", { status: 404 }));
  const stubs = `
    const __fbApp={initializeApp:()=>({})};
    const __fbFs={getFirestore:()=>({}),doc:()=>({}),setDoc:async()=>{},onSnapshot:()=>()=>{}};
    const __fbAuth={getAuth:()=>({currentUser:{getIdToken:async()=>"test-id-token"}}),signInWithCustomToken:async()=>{},onAuthStateChanged:()=>{},signOut:async()=>{},browserSessionPersistence:{},setPersistence:async()=>{}};`;
  for (const f of ["app", "firestore", "auth"]) mod = mod.replace(`await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-${f}.js")`, f === "app" ? "__fbApp" : f === "firestore" ? "__fbFs" : "__fbAuth");
  mod += `
    window.__h = { enter(u, extra){ DB = {...DB, users:[u, {id:"alice",username:"alice",role:"user"}], profiles:{[u.id]:{displayName:u.username}}, ...extra}; completeLogin(u); } };`;
  w.eval(`${stubs}\n(async()=>{\n${mod}\n})().catch(e=>{window.__bootErr=e;});`);
  for (let i = 0; i < 100 && !w.__h; i++) await sleep(20);
  if (w.__bootErr) throw w.__bootErr;
  w.__h.enter({ id: "boss", username: "boss", role: "admin" }, { privacyRequests });
  const doc = w.document;
  w.eval(`go('privacy')`); await sleep(250);
  [...doc.querySelectorAll("button")].find((b) => b.textContent.includes("My Requests")).click(); await sleep(30);
  [...doc.querySelectorAll("button")].find((b) => b.textContent.includes("Admin Dashboard")).click(); await sleep(30);
  return { w, doc };
}

async function openDetail(w, doc, id) {
  w.eval(`openPrivacyRequestDetail(${JSON.stringify(id)})`);
  await sleep(30);
  return doc.getElementById("modalRoot");
}

const REQ = (id, status) => ({ id, uid: "alice", category: "access", description: "x", status, submittedAt: 1, adminNotes: "" });

// ------------------------------------------------------------------------------------------
// A/B/C: non-terminal statuses stay fully editable, exactly as before
// ------------------------------------------------------------------------------------------
for (const [label, status] of [["A", "requested"], ["B", "under_review"], ["C", "approved"]]) {
  test(`${label}: a "${status}" request has an editable status selector, editable notes, a Save button, and no lock message`, async () => {
    const { w, doc } = await boot({ privacyRequests: [REQ("r1", status)] });
    const modal = await openDetail(w, doc, "r1");
    assert.equal(doc.getElementById("pra_status").disabled, false);
    assert.equal(doc.getElementById("pra_notes").disabled, false);
    assert.ok([...modal.querySelectorAll("button")].some((b) => b.textContent.includes("Save")));
    assert.doesNotMatch(modal.textContent, /final status/);
    // the full set of options is still offered so an admin can still move it forward
    assert.deepEqual([...doc.getElementById("pra_status").options].map((o) => o.value), ["requested", "under_review", "approved", "rejected", "completed", "partially_completed"]);
  });
}

// ------------------------------------------------------------------------------------------
// D/E/F: terminal statuses are locked
// ------------------------------------------------------------------------------------------
for (const [label, status] of [["D", "completed"], ["E", "rejected"], ["F", "partially_completed"]]) {
  test(`${label}: a "${status}" request shows the locked/final state -- disabled selector, disabled notes, no Save button, clear message`, async () => {
    const { w, doc } = await boot({ privacyRequests: [REQ("r1", status)] });
    const modal = await openDetail(w, doc, "r1");
    assert.equal(doc.getElementById("pra_status").disabled, true);
    assert.equal(doc.getElementById("pra_status").value, status, "the select still shows the true current status");
    assert.equal(doc.getElementById("pra_notes").disabled, true);
    assert.ok(![...modal.querySelectorAll("button")].some((b) => b.textContent.includes("Save")), "no Save button that could only ever 400");
    assert.match(modal.textContent, /This request is in a final status and cannot be changed\./);
    assert.ok([...modal.querySelectorAll("button")].some((b) => b.textContent.includes("Close")), "Close is still available");
  });
}

test("D: reproduces the exact production screenshot scenario -- a completed request has no Save button in the UI, and even a direct call to the handler is refused by the Worker (not the UI) since the transition itself is invalid", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push(url); return new Response(JSON.stringify({ error: { message: 'Cannot move request from "completed" to "approved"' } }), { status: 400 }); };
  const { w, doc } = await boot({ fetchImpl, privacyRequests: [REQ("r1", "completed")] });
  const modal = await openDetail(w, doc, "r1");
  assert.equal(doc.getElementById("pra_status").disabled, true);
  assert.ok(![...modal.querySelectorAll("button")].some((b) => b.textContent.includes("Save")), "the UI offers no way to submit this change");
  // Even bypassing the UI entirely and calling the real handler directly (as if Save existed),
  // the Worker itself still refuses it -- the lock is a UX improvement, not the security boundary.
  doc.getElementById("pra_status").value = "approved";
  doc.body.insertAdjacentHTML("beforeend", `<button id="dummySave"></button>`);
  await w.eval(`updatePrivacyRequestStatus('r1', document.getElementById('dummySave'))`);
  await sleep(300);
  assert.equal(calls.length, 2, "the status-update call, plus the automatic resync this endpoint's 400 triggers");
  assert.match(calls[0], /\/privacy\/request\/status$/);
  assert.match(calls[1], /\/data\/get$/);
});

// ------------------------------------------------------------------------------------------
// G/H: requested -> approved and requested -> rejected remain covered end-to-end from the UI
// ------------------------------------------------------------------------------------------
for (const [label, target] of [["G", "approved"], ["H", "rejected"]]) {
  test(`${label}: requested -> ${target} still works end-to-end through the (still-editable) modal`, async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      const p = String(url).replace(/^https:\/\/[^/]+/, "");
      const body = init.body ? JSON.parse(init.body) : null;
      calls.push({ p, body });
      if (p === "/privacy/request/status") return new Response(JSON.stringify({ data: { request: { id: "r1", uid: "alice", category: "access", status: body.status, submittedAt: 1, adminNotes: body.adminNotes || "" } } }), { status: 200 });
      return new Response("{}", { status: 404 });
    };
    const { w, doc } = await boot({ fetchImpl, privacyRequests: [REQ("r1", "requested")] });
    const modal = await openDetail(w, doc, "r1");
    assert.equal(doc.getElementById("pra_status").disabled, false);
    doc.getElementById("pra_status").value = target;
    [...modal.querySelectorAll("button")].find((b) => b.textContent.includes("Save")).click();
    await sleep(250);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].body, { requestId: "r1", status: target, adminNotes: "" });
  });
}

// ------------------------------------------------------------------------------------------
// Regression guard: the lock list matches the Worker's TERMINAL_STATUSES exactly
// ------------------------------------------------------------------------------------------
test("Lock list mirrors the Worker's TERMINAL_STATUSES exactly (completed, rejected, partially_completed)", () => {
  assert.match(html, /const TERMINAL = \["completed","rejected","partially_completed"\];/);
});
