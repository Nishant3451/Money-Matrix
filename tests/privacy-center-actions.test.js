// ============================================================================================
// Privacy Center action tests: My Data, Submit Request, Request Account Deletion, Export.
//
// These BOOT THE REAL APP: the actual module <script> from index.html is evaluated inside jsdom
// (only the Firebase CDN imports are replaced by stubs, and `fetch` is replaced by a recorder /
// fake Worker), a user is signed in, and the buttons are clicked through the real DOM and real
// inline onclick handlers. So these exercise the complete click path
//   button -> onclick -> privacy state/tab -> render -> callWorkerApi -> response handling -> UI
// rather than a re-typed copy of it.
//
// The Worker itself (endpoints, auth, admin-only checks, rate limits) is covered by
// cloudflare-worker/tests/privacy-*.test.js and is intentionally NOT re-tested here; this file
// pins the request each button sends to the Worker's existing contract, and how the UI copes
// with every kind of response.
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

// The app starts intervals (autosave, session watcher); close every booted window after each test
// so they can't keep the test process alive.
const openWindows = [];
afterEach(() => { while (openWindows.length) { try { openWindows.pop().close(); } catch (e) {} } });
const unhandled = [];
process.on("unhandledRejection", (r) => unhandled.push(r));

async function boot({ role = "user", fetchImpl, firebase = true, dbExtra = {}, shortTimeoutMs = 0 } = {}) {
  let mod = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
  const page = html.replace(/<script type="module">[\s\S]*?<\/script>/, "").replace(/<script src=[^>]*><\/script>/g, "");
  const dom = new JSDOM(page, { url: "https://example.test/", runScripts: "dangerously", pretendToBeVisual: true });
  const w = dom.window;
  openWindows.push(w);
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.fetch = fetchImpl;
  w.URL.createObjectURL = () => "blob:x"; w.URL.revokeObjectURL = () => {};
  const errors = [];
  w.addEventListener("error", (e) => errors.push(e.message));

  const stubs = `
    const __fbApp={initializeApp:()=>({})};
    const __fbFs={getFirestore:()=>({}),doc:()=>({}),setDoc:async()=>{},onSnapshot:()=>()=>{}};
    const __fbAuth={getAuth:()=>({currentUser:{getIdToken:async()=>"test-id-token"}}),signInWithCustomToken:async()=>{},onAuthStateChanged:()=>{},signOut:async()=>{},browserSessionPersistence:{},setPersistence:async()=>{}};`;
  for (const f of ["app", "firestore", "auth"]) {
    const before = mod;
    mod = mod.replace(`await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-${f}.js")`, f === "app" ? "__fbApp" : f === "firestore" ? "__fbFs" : "__fbAuth");
    assert.notEqual(mod, before, `firebase-${f} import stub applied`);
  }
  if (!firebase) mod = mod.replace('const isLocalFileTest = location.protocol === "file:";', "const isLocalFileTest = true;");
  if (shortTimeoutMs) {
    const before = mod;
    mod = mod.replace("const PRIVACY_API_TIMEOUT_MS = 30000;", `const PRIVACY_API_TIMEOUT_MS = ${shortTimeoutMs};`);
    assert.notEqual(mod, before, "timeout constant present");
  }
  mod += `
    window.__h = {
      enter(u, extra){ DB = {...DB, users:[u], profiles:{[u.id]:{displayName:u.username}}, ...extra}; completeLogin(u); },
      get tab(){ return privacyTab; }, get cache(){ return privacyMyDataCache; },
      get requests(){ return DB.privacyRequests; }, adminHtml(){ return privacyAdminHtml(); },
      policyKeys(){ return Object.keys(POLICY_CONTENT); }, policyTitles(){ return Object.values(POLICY_CONTENT).map(p=>p.title); }
    };`;
  w.eval(`${stubs}\n(async()=>{\n${mod}\n})().catch(e=>{window.__bootErr=e;});`);
  for (let i = 0; i < 100 && !w.__h; i++) await sleep(20);
  if (w.__bootErr) throw w.__bootErr;
  const user = { id: "u1", username: "bob", role };
  w.__h.enter(user, dbExtra);
  const doc = w.document;
  const btn = (text, scope = doc) => [...scope.querySelectorAll("button")].find((b) => b.textContent.includes(text));
  const openPrivacy = async () => { w.eval(`go('privacy')`); await sleep(250); };
  const toasts = () => [...doc.querySelectorAll(".toast")].map((t) => t.textContent.trim());
  return { w, doc, h: w.__h, btn, openPrivacy, toasts, errors };
}

// A fake Worker that follows the documented contract for the privacy endpoints and records every call.
function fakeWorker(overrides = {}) {
  const calls = [];
  const impl = async (url, init) => {
    const p = String(url).replace(/^https:\/\/[^/]+/, "");
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ path: p, method: init && init.method, headers: init && init.headers, body });
    if (overrides[p]) return overrides[p](body, init);
    if (p === "/privacy/export") return json({ data: { export: { exportedAt: new Date().toISOString(), account: { id: "u1", username: "bob", role: "user" }, profile: null, preferences: null, consents: [], policyAcceptances: {}, privacyRequests: [], ownActivityLog: [], ownRecords: null } } });
    if (p === "/privacy/request") return json({ data: { ok: true, request: { id: "req_1", uid: "u1", category: body.category, description: body.description, status: "requested", submittedAt: Date.now(), adminNotes: "" } } });
    if (p === "/privacy/delete") return json({ data: { ok: true, request: { id: "req_del", uid: "u1", category: "deletion", description: "Account deletion requested by user.", status: "requested", submittedAt: Date.now(), adminNotes: "" } } });
    return json({ error: { message: "Not found" } }, 404);
  };
  impl.calls = calls;
  return impl;
}
const json = (o, status = 200) => new Response(JSON.stringify(o), { status });

// ------------------------------------------------------------------------------------------
// Navigation + My Data
// ------------------------------------------------------------------------------------------
test("My Data: the tab button and the Overview quick-link both switch to the My Data tab and render its controls (normal user)", async () => {
  const fw = fakeWorker();
  const { doc, h, btn, openPrivacy, errors } = await boot({ role: "user", fetchImpl: fw });
  await openPrivacy();
  assert.equal(h.tab, "overview");
  // quick link inside the Overview body (the second "My Data" button on the page)
  const quick = [...doc.querySelectorAll("#privacyTabBody button")].find((b) => b.textContent.includes("My Data"));
  quick.click(); await sleep(30);
  assert.equal(h.tab, "mydata");
  assert.ok(btn("Load My Data"), "Load button rendered");
  assert.ok(doc.getElementById("myDataStatus"), "inline status region rendered");
  assert.match(doc.getElementById("privacyTabBody").textContent, /Nothing is loaded yet/);
  btn("Overview").click(); await sleep(30);
  assert.equal(h.tab, "overview");
  // tab bar button (first "My Data" button on the page, above the tab body)
  [...doc.querySelectorAll("button")].find((b) => b.textContent.trim() === "My Data").click(); await sleep(30);
  assert.equal(h.tab, "mydata");
  assert.deepEqual(errors, []);
  assert.equal(fw.calls.length, 0, "switching tabs makes no network call (export is rate-limited, so never automatic)");
});

test("Export My Data: Load My Data POSTs /privacy/export with an empty body and the verified bearer token, then renders and caches the snapshot", async () => {
  const fw = fakeWorker();
  const { doc, h, btn, openPrivacy } = await boot({ fetchImpl: fw });
  await openPrivacy(); btn("My Data").click(); await sleep(30);
  btn("Load My Data").click(); await sleep(200);
  assert.equal(fw.calls.length, 1);
  const c = fw.calls[0];
  assert.equal(c.path, "/privacy/export"); assert.equal(c.method, "POST");
  assert.deepEqual(c.body, {}, "no identity or other data is sent from the browser");
  assert.equal(c.headers.Authorization, "Bearer test-id-token");
  assert.ok(h.cache && h.cache.account.username === "bob");
  const preview = doc.getElementById("myDataPreview").textContent;
  assert.match(preview, /bob/); assert.match(preview, /Download JSON/); assert.match(preview, /Download CSV/);
});

// ------------------------------------------------------------------------------------------
// Submit Request
// ------------------------------------------------------------------------------------------
test("Submit Request: sends exactly {category, description} to /privacy/request, lists the SERVER's record, and shows clear success", async () => {
  const fw = fakeWorker();
  const { doc, h, btn, openPrivacy, toasts } = await boot({ role: "user", fetchImpl: fw });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  assert.equal(h.tab, "requests");
  assert.ok(doc.getElementById("pr_category") && doc.getElementById("pr_desc"), "request form rendered");
  // an allowed category (must be one the Worker accepts) + details
  const allowed = ["access", "correction", "consent_question", "complaint", "security_concern", "other"];
  assert.deepEqual([...doc.getElementById("pr_category").options].map((o) => o.value), allowed);
  doc.getElementById("pr_category").value = "correction";
  doc.getElementById("pr_desc").value = "My email address is wrong";
  btn("Submit Request").click(); await sleep(200);
  assert.equal(fw.calls.length, 1);
  assert.equal(fw.calls[0].path, "/privacy/request");
  assert.deepEqual(fw.calls[0].body, { category: "correction", description: "My email address is wrong" });
  assert.equal(h.requests[0].id, "req_1");
  assert.equal(doc.querySelectorAll("#privacyTabBody table tbody tr").length, 1);
  assert.match(doc.getElementById("pr_status").textContent, /Request submitted/);
  assert.ok(toasts().includes("Request submitted"));
  assert.equal(doc.getElementById("pr_desc").value, "", "form cleared after success");
});

test("Submit Request: an empty description is refused client-side with no network call", async () => {
  const fw = fakeWorker();
  const { btn, openPrivacy, toasts } = await boot({ fetchImpl: fw });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  btn("Submit Request").click(); await sleep(50);
  assert.equal(fw.calls.length, 0);
  assert.ok(toasts().some((t) => /describe your request/i.test(t)));
});

// ------------------------------------------------------------------------------------------
// Request Account Deletion
// ------------------------------------------------------------------------------------------
test("Request Account Deletion: opens the confirm flow, POSTs {confirm:true} to /privacy/delete, and never deletes anything itself", async () => {
  const fw = fakeWorker();
  const { w, doc, h, btn, openPrivacy, toasts } = await boot({ role: "user", fetchImpl: fw });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  btn("Request Account Deletion").click(); await sleep(30);
  const modal = doc.getElementById("modalRoot");
  assert.match(modal.textContent, /NOT deleted immediately/);
  assert.equal(fw.calls.length, 0, "opening the dialog sends nothing");
  btn("Request Deletion", modal).click(); await sleep(300);
  assert.equal(fw.calls.length, 1);
  assert.equal(fw.calls[0].path, "/privacy/delete");
  assert.deepEqual(fw.calls[0].body, { confirm: true });
  assert.equal(h.requests[0].category, "deletion");
  assert.match(doc.getElementById("pr_status").textContent, /Nothing has been deleted yet/);
  assert.ok(toasts().some((t) => /Deletion request submitted/.test(t)));
  assert.ok(!fw.calls.some((c) => /setPin|data\/save/.test(c.path)), "no destructive/other endpoint is touched");
  assert.equal(w.eval("typeof window.deleteAccount"), "undefined", "no immediate-delete function exists in the UI");
});

test("Request Account Deletion: Cancel sends nothing, and a double-tap on Confirm files only ONE request", async () => {
  const fw = fakeWorker({ "/privacy/delete": async () => { await sleep(80); return json({ data: { ok: true, request: { id: "req_del", uid: "u1", category: "deletion", status: "requested", submittedAt: Date.now(), adminNotes: "" } } }); } });
  const { w, doc, h, btn, openPrivacy } = await boot({ fetchImpl: fw });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  btn("Request Account Deletion").click(); await sleep(30);
  btn("Cancel", doc.getElementById("modalRoot")).click(); await sleep(250);
  assert.equal(fw.calls.length, 0);
  btn("Request Account Deletion").click(); await sleep(30);
  w.eval(`window.__mmConfirmYes(); window.__mmConfirmYes();`);
  await sleep(400);
  assert.equal(fw.calls.length, 1, "second confirm while the first is in flight is ignored");
  assert.equal(h.requests.length, 1);
});

// ------------------------------------------------------------------------------------------
// Permissions
// ------------------------------------------------------------------------------------------
test("Permissions: a normal signed-in user can use all three actions; Admin tab/functions stay admin-only; admins keep them", async () => {
  const user = await boot({ role: "user", fetchImpl: fakeWorker() });
  await user.openPrivacy();
  const tabLabels = [...user.doc.querySelectorAll("#pageBody > .card button")].map((b) => b.textContent.trim());
  assert.ok(["Overview", "Policies", "Consent & Preferences", "My Data", "My Requests"].every((l) => tabLabels.includes(l)));
  assert.ok(!tabLabels.includes("Admin Dashboard"), "no Admin tab for a normal user");
  user.w.eval(`setPrivacyTab('admin')`);
  assert.equal(user.h.tab, "overview", "forcing the admin tab as a user falls back to Overview");
  assert.match(user.h.adminHtml(), /Not authorized/);
  assert.doesNotMatch(user.h.adminHtml(), /Review|Publish Current Code Versions/);

  const admin = await boot({ role: "admin", fetchImpl: fakeWorker() });
  await admin.openPrivacy();
  const adminTabs = [...admin.doc.querySelectorAll("#pageBody > .card button")].map((b) => b.textContent.trim());
  assert.ok(adminTabs.includes("Admin Dashboard"));
  admin.btn("Admin Dashboard").click(); await sleep(30);
  assert.match(admin.doc.getElementById("privacyTabBody").textContent, /Publish Current Code Versions/);
});

// ------------------------------------------------------------------------------------------
// Failure handling (no crash, visible + specific message, button usable again, nothing fabricated)
// ------------------------------------------------------------------------------------------
const FAILURES = [
  ["429 rate limit", () => json({ error: { message: "Too many requests" } }, 429), /reached the limit/],
  ["503 unavailable", () => json({ error: { message: "x" } }, 503), /temporarily unavailable/],
  ["403 forbidden", () => json({ error: { message: "x" } }, 403), /not authorized/],
  ["400 rejected", () => json({ error: { message: "Invalid category" } }, 400), /rejected this request/],
  ["500 server error", () => json({ error: { message: "x" } }, 500), /Couldn't/],
  ["409 conflict", () => json({ error: { message: "x" } }, 409), /conflicted/],
  ["200 with a non-JSON body", () => new Response("<html>oops</html>", { status: 200 }), /Couldn't/],
  ["200 without the expected data", () => json({ data: {} }), /Couldn't/],
];
for (const [name, respond, expected] of FAILURES) {
  test(`Failure (${name}): Submit, Deletion and My Data each show a specific message, recover, and fabricate nothing`, async () => {
    const before = unhandled.length;
    const fw = fakeWorker({ "/privacy/export": respond, "/privacy/request": respond, "/privacy/delete": respond });
    const { doc, h, btn, openPrivacy, errors } = await boot({ fetchImpl: fw });
    await openPrivacy(); btn("My Requests").click(); await sleep(30);
    doc.getElementById("pr_desc").value = "details";
    btn("Submit Request").click(); await sleep(250);
    assert.match(doc.getElementById("pr_status").textContent, expected, "submit: inline message");
    assert.equal(btn("Submit Request").disabled, false, "submit button usable again");
    btn("Request Account Deletion").click(); await sleep(30);
    btn("Request Deletion", doc.getElementById("modalRoot")).click(); await sleep(300);
    assert.match(doc.getElementById("pr_status").textContent, expected, "deletion: inline message");
    assert.equal((h.requests || []).length, 0, "no request record was fabricated");
    btn("My Data").click(); await sleep(30);
    btn("Load My Data").click(); await sleep(250);
    assert.match(doc.getElementById("myDataStatus").textContent, expected, "my data: inline message");
    assert.equal(btn("Load My Data").disabled, false);
    assert.equal(h.cache, null, "nothing reported as loaded");
    btn("My Requests").click(); await sleep(30);
    assert.ok(doc.getElementById("pr_desc"), "My Requests tab still renders afterwards");
    assert.deepEqual(errors, []); assert.equal(unhandled.length, before, "no unhandled promise rejection");
  });
}

test("Failure (network error): clear 'couldn't reach the server' message, no crash", async () => {
  const { doc, btn, openPrivacy, errors } = await boot({ fetchImpl: async () => { throw new TypeError("Failed to fetch"); } });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  doc.getElementById("pr_desc").value = "x"; btn("Submit Request").click(); await sleep(200);
  assert.match(doc.getElementById("pr_status").textContent, /Couldn't reach the server/);
  assert.deepEqual(errors, []);
});

test("Failure (hung request): times out with a message instead of leaving the button stuck on 'Loading…'", async () => {
  const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))));
  const { doc, btn, openPrivacy } = await boot({ fetchImpl: hang, shortTimeoutMs: 150 });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  doc.getElementById("pr_desc").value = "x"; btn("Submit Request").click(); await sleep(50);
  assert.equal(btn("Submit Request").disabled, true, "busy while waiting");
  await sleep(300);
  assert.equal(btn("Submit Request").disabled, false);
  assert.match(doc.getElementById("pr_status").textContent, /took too long.*My Requests/);
  btn("My Data").click(); await sleep(30); btn("Load My Data").click(); await sleep(350);
  assert.match(doc.getElementById("myDataStatus").textContent, /took too long/);
  assert.equal(btn("Load My Data").disabled, false);
});

test("Failure text is authored client-side: a hostile server error message can never reach the DOM", async () => {
  const evil = () => json({ error: { message: "<img src=x onerror=window.__pwn=1>" } }, 500);
  const { w, doc, btn, openPrivacy } = await boot({ fetchImpl: fakeWorker({ "/privacy/request": evil }) });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  doc.getElementById("pr_desc").value = "x"; btn("Submit Request").click(); await sleep(200);
  assert.equal(doc.querySelector("#pr_status img"), null); assert.equal(w.__pwn, undefined);
  assert.doesNotMatch(doc.body.innerHTML, /onerror=window\.__pwn/);
});

test("Malformed stored request records cannot break the My Requests tab", async () => {
  const { doc, btn, openPrivacy, errors } = await boot({ fetchImpl: fakeWorker(), dbExtra: { privacyRequests: [null, { id: "x", uid: "u1", category: "access" }, { id: "y", uid: "u1", category: "other", status: "under_review", submittedAt: 5 }] } });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  assert.equal(doc.querySelectorAll("#privacyTabBody table tbody tr").length, 2);
  assert.deepEqual(errors, []);
});

// ------------------------------------------------------------------------------------------
// Offline: privacy mutations stay blocked (existing tests cover the extracted functions; this
// pins the same guarantee through the real click path)
// ------------------------------------------------------------------------------------------
test("Offline: Submit and Deletion never call the server or fabricate a record, and say so", async () => {
  const fw = fakeWorker();
  const { doc, h, btn, openPrivacy, toasts } = await boot({ fetchImpl: fw, firebase: false });
  await openPrivacy(); btn("My Requests").click(); await sleep(30);
  doc.getElementById("pr_desc").value = "x"; btn("Submit Request").click(); await sleep(100);
  btn("Request Account Deletion").click(); await sleep(30);
  btn("Request Deletion", doc.getElementById("modalRoot")).click(); await sleep(300);
  assert.equal(fw.calls.length, 0);
  assert.equal((h.requests || []).length, 0);
  assert.ok(toasts().some((t) => /unavailable offline/i.test(t)));
  assert.ok(!toasts().some((t) => /submitted/i.test(t)));
});

// ------------------------------------------------------------------------------------------
// callWorkerApi contract for these calls + regression guards for the rest of the Privacy Center
// ------------------------------------------------------------------------------------------
test("callWorkerApi: keeps the HTTP status on errors; 429 now matches the 'Too many' check; only Privacy calls opt into a timeout", () => {
  assert.match(html, /resp\.status === 429\) \{[\s\S]*?new Error\("Too many requests"\)[\s\S]*?status: 429/);
  assert.match(html, /new Error\("Request failed"\), \{ code: "functions\/internal", status: resp\.status \}/);
  assert.match(html, /callWorkerApi\("\/privacy\/export", \{\}, PRIVACY_CALL_OPTS\)/);
  assert.match(html, /callWorkerApi\("\/privacy\/request", \{ category, description \}, /);
  assert.match(html, /callWorkerApi\("\/privacy\/delete", \{ confirm: true \}, /);
  for (const other of ['"/data/get", {}', '"/data/save", payload', '"/user/setPin", payload']) assert.ok(html.includes(`callWorkerApi(${other})`), `${other} unchanged (no timeout added)`);
});

test("Existing Privacy Center is intact: four policies, versions, read + accept path, sidebar entry", async () => {
  const { h, w, doc, btn, openPrivacy } = await boot({ fetchImpl: fakeWorker() });
  assert.equal(JSON.stringify(h.policyTitles()), JSON.stringify(["Privacy Policy", "Terms of Service", "Cookie & Storage Policy", "Data Deletion & User Rights"]));
  assert.equal(JSON.stringify(h.policyKeys()), JSON.stringify(["privacy_policy", "terms_of_service", "cookie_policy", "data_rights"]));
  assert.ok(doc.querySelector('[data-tab="privacy"]'), "sidebar entry present");
  await openPrivacy(); btn("Policies").click(); await sleep(30);
  assert.equal(doc.querySelectorAll("#privacyTabBody table tbody tr").length, 4);
  w.eval(`viewPolicy('cookie_policy')`);
  assert.match(doc.getElementById("modalRoot").textContent, /Cookie & Storage Policy/);
  // Not yet published server-side -> no accept button, just an explanatory note (policy gate test covers the published case).
  assert.equal(btn("I Accept This Version", doc.getElementById("modalRoot")), undefined);
  assert.match(doc.getElementById("modalRoot").textContent, /hasn't been published/);
});
