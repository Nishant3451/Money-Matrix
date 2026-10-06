// ============================================================================================
// Regression tests for two production bugs:
//
//  1. Logging out could flash a misleading "Sync error" — the session was terminated while
//     authenticated work (Firestore listener, /data/get, debounced /data/save, pagehide flush)
//     was still live, and each of those failed and was reported as an ordinary sync failure.
//  2. The Edit Quotation line-item grid was unusably cramped (7 tiny columns in a 500px modal).
//
// As in the other suites, the ACTUAL functions are extracted from index.html and run in a
// sandbox with fakes for fetch/auth — nothing here re-implements the logic under test.
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
const css = html.match(/<style>([\s\S]*?)<\/style>/)[1];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function extractFunction(source, name) {
  let m = source.match(new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`));
  if (m) {
    const open = source.indexOf("{", source.indexOf(")", m.index));
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
const line = (re) => mod.match(re)[0];

// ------------------------------------------------------------------ session-lifecycle sandbox
const LIFECYCLE_SRC = [
  line(/^let authGeneration = 0;$/m),
  line(/^let sessionEnding = false;$/m),
  line(/^let metaUnsub = null;$/m),
  line(/^const isSessionEndError = .*$/m),
  extractFunction(mod, "stopCloudSync"),
  extractFunction(mod, "beginSessionTermination"),
  extractFunction(mod, "beginSession"),
  extractFunction(mod, "callWorkerApi"),
  extractFunction(mod, "fetchAuthorizedData"),
  extractFunction(mod, "cloudSave"),
  extractFunction(mod, "flushPendingSave"),
  extractFunction(mod, "setSync"),
].join("\n");

function makeEnv(fetchImpl) {
  const dom = new JSDOM(`<div id="syncBar"></div><div id="dashSyncStatus"><i></i></div><span id="dashSyncText"></span>`, { url: "https://example.test/" });
  const calls = { forceLogout: [], render: 0, applyRemote: 0, gate: 0, save: 0 };
  const ctx = {
    document: dom.window.document, console, setTimeout, clearTimeout, JSON, Object, Error, Promise, Date,
    localStorage: dom.window.localStorage, location: { reload() {} },
    LOGIN_ENDPOINT: "https://worker.test", AbortController,
    auth: { currentUser: { getIdToken: async () => "tok" } },
    fetch: fetchImpl,
    $: (id) => dom.window.document.getElementById(id),
    timeAgo: () => "now",
    firebaseAvailable: true, cloudSyncStarted: true, requestedDataScope: null, writeTimer: null, pendingRemoteJson: null,
    isDirty: false, lastCloudJson: "", currentUser: { id: "u" }, serverViewReceived: false, applyingRemote: false,
    DB: {}, calls,
    forceLogout: (msg) => { calls.forceLogout.push(msg); ctx.beginSessionTermination(); },
    render: () => { calls.render++; },
    enforcePolicyGate: () => { calls.gate++; },
    applyRemoteJson: () => { calls.applyRemote++; },
    isModalOpen: () => false, takeSnapshot() {}, persistLocal() {}, toast() {},
    JSON_: JSON,
  };
  ctx.getAppDataFn = () => ctx.callWorkerApi("/data/get", {});
  ctx.saveAppDataFn = (p) => ctx.callWorkerApi("/data/save", p);
  vm.createContext(ctx);
  vm.runInContext(LIFECYCLE_SRC, ctx);
  const bar = () => ctx.$("syncBar").textContent;
  const barStyle = () => ctx.$("syncBar").style.background;
  return { ctx, calls, bar, barStyle, run: (s) => vm.runInContext(s, ctx) };
}
const ok200 = (json = "{}") => ({ ok: true, status: 200, json: async () => ({ data: { json } }), clone() { return this; } });
const status = (n, body) => ({ ok: false, status: n, json: async () => body ?? {}, clone() { return this; } });
const deferred = () => { let resolve, reject; const p = new Promise((a, b) => { resolve = a; reject = b; }); return { p, resolve, reject }; };

test("logout while /data/get is in flight: late response is dropped — no error, no render, no data applied", async () => {
  const d = deferred();
  const env = makeEnv(() => d.p);
  const pending = env.ctx.fetchAuthorizedData();
  await sleep(5);
  env.run("beginSessionTermination()"); // == what go('logout') does first
  d.resolve(ok200('{"users":["stale-private-data"]}'));
  await pending;
  assert.equal(env.bar(), "", "syncBar must not be touched after logout");
  assert.equal(env.calls.applyRemote, 0, "stale authenticated data must never be applied after logout");
  assert.equal(env.calls.render, 0);
  assert.equal(env.calls.gate, 0);
  assert.equal(env.calls.forceLogout.length, 0);
});

test("logout while /data/get is in flight: fetch rejects (aborted by reload / token revoked) — NOT reported as Sync error", async () => {
  const d = deferred();
  const env = makeEnv(() => d.p);
  const pending = env.ctx.fetchAuthorizedData();
  await sleep(5);
  env.run("beginSessionTermination()");
  d.reject(new TypeError("Failed to fetch"));
  await pending;
  assert.equal(env.bar(), "");
});

test("a 401 that arrives AFTER logout does not fire a second forceLogout or an error", async () => {
  const d = deferred();
  const env = makeEnv(() => d.p);
  const pending = env.ctx.fetchAuthorizedData();
  await sleep(5);
  env.run("beginSessionTermination()");
  d.resolve(status(401));
  await pending;
  assert.equal(env.calls.forceLogout.length, 0);
  assert.equal(env.bar(), "");
});

test("a request started after logout never hits the network and fails with the internal session/ended code", async () => {
  let fetched = 0;
  const env = makeEnv(() => { fetched++; return Promise.resolve(ok200()); });
  env.run("beginSessionTermination()");
  await assert.rejects(env.ctx.callWorkerApi("/data/get", {}), (e) => e.code === "session/ended");
  await env.ctx.fetchAuthorizedData();
  assert.equal(fetched, 0);
  assert.equal(env.bar(), "");
});

test("signed-out auth (currentUser null) mid-request during logout is the session ending, not 'Not signed in'", async () => {
  const d = deferred();
  const env = makeEnv(() => d.p);
  env.ctx.auth.currentUser.getIdToken = async () => { throw new Error("auth/user-token-expired"); };
  const pending = env.ctx.fetchAuthorizedData();
  env.run("beginSessionTermination()");
  await pending;
  assert.equal(env.bar(), "");
});

test("network failure while LOGGED IN still shows the sync error (not globally suppressed)", async () => {
  const env = makeEnv(() => Promise.reject(new TypeError("Failed to fetch")));
  await env.ctx.fetchAuthorizedData();
  assert.equal(env.bar(), "Sync error — check network");
  assert.match(env.barStyle(), /danger/);
});

test("HTTP 500 while logged in still shows the sync error", async () => {
  const env = makeEnv(() => Promise.resolve(status(500)));
  await env.ctx.fetchAuthorizedData();
  assert.equal(env.bar(), "Sync error — check network");
});

test("session expiration (401 on a live session, after the forced token refresh) calls forceLogout with the session-expired message, not a sync error", async () => {
  let n = 0;
  const env = makeEnv(() => { n++; return Promise.resolve(status(401)); });
  await env.ctx.fetchAuthorizedData();
  assert.equal(n, 2, "one retry with a force-refreshed token before giving up");
  assert.deepEqual(env.calls.forceLogout, ["Your session expired — please log in again."]);
  assert.notEqual(env.bar(), "Sync error — check network");
});

test("401 surfaces as functions/unauthenticated; 403 as functions/permission-denied — still distinguishable from each other and from ordinary failures", async () => {
  const e401 = await makeEnv(() => Promise.resolve(status(401))).ctx.callWorkerApi("/x", {}).catch((e) => e);
  const e403 = await makeEnv(() => Promise.resolve(status(403, { error: { code: "FORBIDDEN" } }))).ctx.callWorkerApi("/x", {}).catch((e) => e);
  const e500 = await makeEnv(() => Promise.resolve(status(500))).ctx.callWorkerApi("/x", {}).catch((e) => e);
  assert.equal(e401.code, "functions/unauthenticated");
  assert.equal(e403.code, "functions/permission-denied");
  assert.equal(e500.code, "functions/internal");
});

test("policy gate: POLICY_ACCEPTANCE_REQUIRED on a live session still shows the gate (and is not a sync error, nor permission-denied)", async () => {
  const body = { error: { code: "POLICY_ACCEPTANCE_REQUIRED" }, data: { policyVersions: ["v1"], policyAcceptances: {} } };
  const env = makeEnv(() => Promise.resolve(status(403, body)));
  await env.ctx.fetchAuthorizedData();
  assert.equal(env.calls.gate, 1);
  assert.equal(env.bar(), "Policy acceptance required");
  assert.deepEqual(env.run("DB.policyVersions"), ["v1"]);
});

test("policy gate: a POLICY_ACCEPTANCE_REQUIRED response that lands AFTER logout must not touch the logged-out UI", async () => {
  const d = deferred();
  const env = makeEnv(() => d.p);
  const pending = env.ctx.fetchAuthorizedData();
  await sleep(5);
  env.run("beginSessionTermination()");
  d.resolve(status(403, { error: { code: "POLICY_ACCEPTANCE_REQUIRED" }, data: { policyVersions: ["v1"], policyAcceptances: {} } }));
  await pending;
  assert.equal(env.calls.gate, 0, "no policy gate over the login screen");
  assert.equal(env.calls.render, 0);
  assert.equal(env.bar(), "");
  assert.equal(env.run("DB.policyVersions"), undefined, "no server data written into DB after logout");
});

test("a queued debounced save that fails because the session ended is not reported as 'Save error'", async () => {
  const env = makeEnv(() => Promise.reject(new TypeError("Failed to fetch")));
  const p = env.ctx.cloudSave(true);   // immediate push, in flight
  env.run("beginSessionTermination()");
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(env.bar(), "");
});

test("a genuine save failure while logged in is still reported", async () => {
  const env = makeEnv(() => Promise.reject(new TypeError("Failed to fetch")));
  const r = await env.ctx.cloudSave(true);
  assert.equal(r.ok, false);
  assert.equal(env.bar(), "Save error");
});

test("beginSessionTermination cancels the pending debounce timer and held remote data, and detaches the Firestore listener", () => {
  const env = makeEnv(() => Promise.resolve(ok200()));
  env.run("metaUnsub = () => { globalThis.__detached = (globalThis.__detached || 0) + 1; }");
  env.run("writeTimer = setTimeout(() => { globalThis.__fired = true; }, 20); pendingRemoteJson = '{\"secret\":1}'");
  env.run("beginSessionTermination()");
  assert.equal(env.ctx.__detached, 1, "onSnapshot listener unsubscribed (its revoked-auth error was one source of the false error)");
  assert.equal(env.run("writeTimer"), null, "debounced save timer cleared");
  assert.equal(env.run("pendingRemoteJson"), null);
  assert.equal(env.run("cloudSyncStarted"), false, "a later login can start sync again");
  return sleep(40).then(() => assert.equal(env.ctx.__fired, undefined, "the cancelled debounced save never fires"));
});

test("beginSessionTermination is idempotent (several 401s at once tear down once)", () => {
  const env = makeEnv(() => Promise.resolve(ok200()));
  assert.equal(env.run("beginSessionTermination()"), true);
  assert.equal(env.run("beginSessionTermination()"), false);
});

test("pagehide/visibility flush during logout does not fire a save", () => {
  let fetched = 0;
  const env = makeEnv(() => { fetched++; return Promise.resolve(ok200()); });
  env.run("isDirty = true");
  env.run("beginSessionTermination()");
  env.run("flushPendingSave()");
  assert.equal(fetched, 0);
});

test("setSync: error painting is suppressed only while the session is ending; success/progress messages unaffected", () => {
  const env = makeEnv(() => Promise.resolve(ok200()));
  env.run(`setSync("Sync error — check network", true)`);
  assert.equal(env.bar(), "Sync error — check network");
  env.run(`setSync("ok", false)`); env.run("beginSessionTermination()");
  env.run(`setSync("Sync error — check network", true)`);
  assert.equal(env.bar(), "ok", "no error painted during termination");
});

test("a new login starts a fresh, live session after a previous logout", async () => {
  const env = makeEnv(() => Promise.resolve(ok200("{}")));
  env.run("beginSessionTermination()");
  env.run("beginSession()");
  const r = await env.ctx.callWorkerApi("/data/get", {});
  assert.ok(r.data);
});

test("source wiring: go('logout') ends the session BEFORE signOut; forceLogout/timeout paths and the listener error path are guarded", () => {
  const logout = mod.slice(mod.indexOf('if(id==="logout")'));
  assert.ok(logout.indexOf("beginSessionTermination()") > -1 && logout.indexOf("beginSessionTermination()") < logout.indexOf("signOut(auth)"));
  assert.match(extractFunction(mod, "forceLogout"), /beginSessionTermination\(\)/);
  assert.match(mod, /beginSessionTermination\(\);\s*\n\s*if\(auth && signOut\)\{ signOut\(auth\)\.catch\(\(\)=>\{\}\); \}/, "page-load timeout path");
  const start = extractFunction(mod, "startCloud");
  assert.match(start, /metaUnsub = onSnapshot/);
  assert.match(start, /if\(sessionEnding \|\| !auth \|\| !auth\.currentUser\) return;\s*\n\s*setSync\("Sync error/);
  assert.match(extractFunction(mod, "doLogin"), /beginSession\(\)/);
});

test("server-side security untouched: the Worker is not changed by this fix and the client still sends the bearer token + policy 403 mapping", () => {
  const src = extractFunction(mod, "callWorkerApi");
  assert.match(src, /Authorization.*Bearer/);
  assert.match(src, /POLICY_ACCEPTANCE_REQUIRED/);
  assert.match(src, /functions\/permission-denied/);
});

// ------------------------------------------------------------------ quotation layout
test("quotation CSS: line-item layout is container-query driven (no fixed 7-column squeeze), with a stacked default", () => {
  assert.doesNotMatch(css, /grid-template-columns:1\.3fr 1\.3fr 60px 90px 80px 90px 40px/);
  assert.match(css, /#quoteItemsWrap\{container-type:inline-size/);
  assert.match(css, /@container qlines \(min-width:940px\)/);
  assert.match(css, /@container qlines \(min-width:520px\)/);
  assert.match(css, /@container qlines \(max-width:330px\)/);
  // single-row layout: every fixed column adds up to leave real room for product + name
  const one = css.match(/@container qlines \(min-width:940px\)\{[^}]*grid-template-columns:([^;]+);/)[1];
  assert.match(one, /^minmax\(0,1fr\) minmax\(0,1fr\) 76px 110px 88px 136px 44px$/);
  // controls are real touch targets and mobile inputs don't trigger iOS zoom
  assert.match(css, /\.qlf select,\.qlf input\{[^}]*min-height:42px/);
  assert.match(css, /input,select,textarea,\.qlf select,\.qlf input\{font-size:16px\}/);
});

test("modal CSS: viewport-safe height, internal scroll, sticky header + footer, wide variant, background scroll lock", () => {
  assert.match(css, /\.modal\{[^}]*max-height:calc\(100dvh - 32px\)[^}]*overflow-y:auto/);
  assert.match(css, /\.modal>\.modal-head:first-child\{position:sticky;top:calc\(var\(--modal-pad\) \* -1\)/);
  assert.match(css, /\.modal>\.modal-btns:last-child\{position:sticky;bottom:calc\(var\(--modal-pad\) \* -1\)/);
  assert.match(css, /\.modal\.modal-wide\{max-width:1040px\}/);
  assert.match(css, /html\.mm-modal-open\{overflow:hidden\}/);
});

function quoteEnv() {
  const dom = new JSDOM(`<div id="modalRoot"></div><div id="quoteItemsWrap"></div><div id="quoteTotals"></div>`, { runScripts: "outside-only" });
  const ctx = {
    document: dom.window.document, window: dom.window, console, Math, JSON, Number, String,
    quoteLineItems: [], mmReducedMotion: () => true,
    policyGateActive: () => false, enforcePolicyGate() {},
    esc: (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
    $: (id) => dom.window.document.getElementById(id),
    money: (n) => "₹" + Number(n || 0).toLocaleString("en-IN"),
    data: () => ({ products: [{ id: "p1", name: "Shake Mix", defaultPrice: 3450 }, { id: "p2", name: "Tea", defaultPrice: 500 }] }),
  };
  vm.createContext(ctx);
  vm.runInContext([
    extractFunction(mod, "lineTotal"), extractFunction(mod, "renderQuoteItems"), extractFunction(mod, "renderQuoteTotals"),
    extractFunction(mod, "updateQuoteLine"), extractFunction(mod, "addQuoteLine"), extractFunction(mod, "removeQuoteLine"),
    extractFunction(mod, "showModal"),
    "window.updateQuoteLine=updateQuoteLine; window.addQuoteLine=addQuoteLine; window.removeQuoteLine=removeQuoteLine;",
  ].join("\n"), ctx);
  ctx.window.quoteLineItems = null;
  return { ctx, doc: dom.window.document, run: (s) => vm.runInContext(s, ctx) };
}

test("quotation line items: every control has an associated label, and delete has an accessible name", () => {
  const { ctx, doc } = quoteEnv();
  ctx.quoteLineItems = [{ productId: "", productName: "A", qty: 2, price: 100, discountPercent: 10 }, { productId: "p1", productName: "Shake Mix", qty: 1, price: 3450, discountPercent: 0 }];
  ctx.renderQuoteItems();
  const controls = [...doc.querySelectorAll("#quoteItemsWrap input, #quoteItemsWrap select")];
  assert.equal(controls.length, 10, "5 controls per row × 2 rows");
  for (const c of controls) {
    assert.ok(c.id, "control needs an id");
    assert.ok(doc.querySelector(`label[for="${c.id}"]`), `label for ${c.id}`);
  }
  const ids = controls.map((c) => c.id); assert.equal(new Set(ids).size, ids.length, "ids unique per row");
  for (const b of doc.querySelectorAll(".qlf-del button")) assert.match(b.getAttribute("aria-label"), /^Remove item \d+$/);
  for (const t of doc.querySelectorAll(".qlf-total-val")) assert.ok(t.getAttribute("aria-labelledby"));
  assert.equal(doc.querySelectorAll(".quote-line-row").length, 2);
});

test("quotation calculations unchanged: qty × price − discount, per-line and grand totals", () => {
  const { ctx, doc } = quoteEnv();
  ctx.quoteLineItems = [{ productId: "", productName: "A", qty: 2, price: 100, discountPercent: 10 }];
  ctx.renderQuoteItems();
  assert.equal(doc.getElementById("lineTotal_0").textContent, "₹180");
  ctx.updateQuoteLine(0, "qty", "3");
  assert.equal(doc.getElementById("lineTotal_0").textContent, "₹270");
  ctx.updateQuoteLine(0, "discountPercent", "50");
  assert.equal(doc.getElementById("lineTotal_0").textContent, "₹150");
  const t = doc.getElementById("quoteTotals").textContent;
  assert.match(t, /Subtotal₹300/); assert.match(t, /Total Discount-₹150/); assert.match(t, /Grand Total₹150/);
});

test("quotation product selection fills name + default price; add / delete line work; totals stay in sync", () => {
  const { ctx, doc } = quoteEnv();
  ctx.quoteLineItems = [];
  ctx.addQuoteLine();
  ctx.updateQuoteLine(0, "productId", "p1");
  assert.equal(doc.getElementById("qi_name_0").value, "Shake Mix");
  assert.equal(doc.getElementById("qi_price_0").value, "3450");
  ctx.addQuoteLine();
  assert.equal(doc.querySelectorAll(".quote-line-row").length, 2);
  ctx.removeQuoteLine(0);
  assert.equal(doc.querySelectorAll(".quote-line-row").length, 1);
  assert.match(doc.getElementById("quoteTotals").textContent, /Grand Total₹0/);
});

test("quotation line item content is escaped (no XSS regression from the markup rewrite)", () => {
  const { ctx, doc } = quoteEnv();
  ctx.quoteLineItems = [{ productId: "", productName: `"><img src=x onerror=alert(1)>`, qty: 1, price: 1, discountPercent: 0 }];
  ctx.renderQuoteItems();
  assert.equal(doc.querySelectorAll("#quoteItemsWrap img").length, 0);
  assert.equal(doc.getElementById("qi_name_0").value, `"><img src=x onerror=alert(1)>`);
});

test("showModal: wide variant + dialog semantics (role, aria-modal, labelled by title, close button named, focus moved in, page scroll locked)", () => {
  const { ctx, doc } = quoteEnv();
  ctx.showModal(`<div class="modal-head"><h3>Edit Quotation</h3><button class="modal-close"><i></i></button></div><input id="x">`, { wide: true });
  const m = doc.querySelector(".modal");
  assert.ok(m.classList.contains("modal-wide"));
  assert.equal(m.getAttribute("role"), "dialog");
  assert.equal(m.getAttribute("aria-modal"), "true");
  assert.equal(doc.getElementById(m.getAttribute("aria-labelledby")).textContent, "Edit Quotation");
  assert.equal(doc.querySelector(".modal-close").getAttribute("aria-label"), "Close dialog");
  assert.equal(doc.activeElement, m);
  assert.ok(doc.documentElement.classList.contains("mm-modal-open"));
  ctx.showModal(`<p>plain</p>`);
  assert.ok(!doc.querySelector(".modal").classList.contains("modal-wide"), "default modals keep their normal width");
});

// ============================================================================================
// UX / accessibility / navigation regressions (mobile-menu, toasts, titles, labels, policy links)
// ============================================================================================
test("mobile menu: hamburger is a labelled, stateful control; the resize/Escape/backdrop paths that used to strand the UI are wired", () => {
  assert.match(html, /<button class="menu-btn"[^>]*aria-label="Open navigation menu"[^>]*aria-controls="appSidebar"[^>]*aria-expanded="false"/);
  assert.match(html, /<div class="sidebar" id="appSidebar">/);
  // rotating / resizing past the breakpoint with the menu open left a full-screen backdrop over the desktop layout
  assert.match(mod, /matchMedia\('\(max-width:900px\)'\)\.addEventListener\('change', e=>\{ if\(!e\.matches\) closeSidebar\(\); \}\)/);
  assert.match(extractFunction(mod, "toggleSidebar"), /syncMenuAria\(opening\)/);
  assert.match(extractFunction(mod, "closeSidebar"), /syncMenuAria\(false\)/);
  // Escape closes an open sidebar (after modals get first refusal) and returns focus to the button
  assert.match(mod, /if\(sb && sb\.classList\.contains\('open'\)\)\{ closeSidebar\(\); const mb=document\.querySelector\('\.menu-btn'\); if\(mb\) mb\.focus\(\); \}/);
  // closed off-canvas sidebar is not tabbable / readable
  assert.match(css, /\.sidebar\{transform:translateX\(-100%\); visibility:hidden;/);
  assert.match(css, /\.sidebar\.open\{transform:translateX\(0\); visibility:visible;/);
});

test("navigation items are keyboard-operable buttons with aria-current on the active page; logo returns to Dashboard", () => {
  assert.match(extractFunction(mod, "buildNav"), /role="button" tabindex="0"\$\{n\.id===activePage\?' aria-current="page"':''\}/);
  assert.match(mod, /e\.key===" "\) && e\.target && e\.target\.classList && e\.target\.classList\.contains\('nav-item'\)\)\{ e\.preventDefault\(\); e\.target\.click\(\)/);
  assert.match(html, /<a class="brand-link" href=".\/" onclick="event\.preventDefault\(\);go\('dashboard'\)"/);
});

test("policy gate still wins over every navigation entry: go() cannot un-gate, render() forces Privacy Center, modals other than policy reading are refused", () => {
  const render = extractFunction(mod, "render");
  assert.match(render, /if\(policyGateActive\(\) && activePage !== "privacy"\) activePage = "privacy";/);
  assert.match(extractFunction(mod, "showModal"), /if\(policyGateActive\(\) && !\(opts && opts\.allowDuringGate\)\)\{ enforcePolicyGate\(\); return; \}/);
  // the logo / nav route through go() -> render(), never around it
  const goSrc = mod.slice(mod.indexOf("window.go=id=>{"), mod.indexOf("function showSkeleton"));
  assert.ok(goSrc.length > 100, "go() source located");
  assert.doesNotMatch(goSrc, /policyGateActive|serverViewReceived\s*=\s*false/, "go() must not touch gate state");
  assert.match(goSrc, /activePage=id; buildNav\(\); render\(\);/, "go() only sets the page then re-renders through the guarded render()");
});

test("document title is set only AFTER every render() authorization guard, for built-in and custom sections", () => {
  const render = extractFunction(mod, "render");
  const guardEnd = render.indexOf('if(activePage==="sectionmanager" && !isSuperAdmin()) activePage="dashboard";');
  assert.ok(guardEnd > -1);
  const calls = [...render.matchAll(/setDocTitle\(\);/g)].map((m) => m.index);
  assert.equal(calls.length, 2, "built-in path + custom-section path");
  for (const i of calls) assert.ok(i > guardEnd, "title must not be computed before the guards settle activePage");
});

test("head: accurate description, noindex for a private app, viewport-fit, no fabricated SEO copy", () => {
  assert.match(html, /<meta name="description" content="MoneyMatrix — a private business management workspace for authorised team members/);
  assert.match(html, /<meta name="robots" content="noindex, nofollow"/);
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover"/);
});

function toastEnv() {
  const dom = new JSDOM(`<body></body>`);
  const ctx = { document: dom.window.document, setTimeout: (f) => 0, mmDismissToast() {}, String };
  vm.createContext(ctx);
  vm.runInContext(line(/^function toast\(m\).*$/m), ctx);
  return { ctx, doc: dom.window.document };
}
test("toast: failures/validation render as errors (alert role, exclamation icon); successes stay status + check icon; explicit kind wins", () => {
  const { ctx, doc } = toastEnv();
  const errors = ["Name required", "Couldn't update PIN — try again", "Change rejected — refreshing…", "Your session expired — please log in again.", "Current PIN is incorrect", "Permission denied", "Sync failed"];
  const oks = ["Member added", "Payment updated", "Data Import Successful", "Deletion request submitted — an administrator will review it", "Import complete: 3 added, 0 overridden, 2 skipped"];
  for (const m of errors) { doc.body.innerHTML = ""; ctx.toast(m); const t = doc.querySelector(".toast"); assert.ok(t.classList.contains("toast-error"), m); assert.equal(t.getAttribute("role"), "alert", m); assert.ok(t.querySelector(".fa-exclamation-circle"), m); }
  for (const m of oks) { doc.body.innerHTML = ""; ctx.toast(m); const t = doc.querySelector(".toast"); assert.ok(!t.classList.contains("toast-error"), m); assert.equal(t.getAttribute("role"), "status", m); assert.ok(t.querySelector(".fa-check-circle"), m); }
  doc.body.innerHTML = ""; ctx.toast("Saved", "error"); assert.ok(doc.querySelector(".toast-error"));
  doc.body.innerHTML = ""; ctx.toast("Required field cleared", "success"); assert.ok(!doc.querySelector(".toast-error"));
});
test("toast: the message is still inserted as HTML only because callers esc() it — an already-escaped payload stays inert", () => {
  const { ctx, doc } = toastEnv();
  ctx.toast("Merged &quot;&lt;img src=x onerror=alert(1)&gt;&quot;");
  assert.equal(doc.querySelectorAll(".toast img").length, 0);
});

test("linkifyEmails: links addresses in ESCAPED policy text and cannot be used to inject markup or attributes", () => {
  const ctx = { esc: (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])) };
  vm.createContext(ctx); vm.runInContext(extractFunction(mod, "linkifyEmails"), ctx);
  const out = ctx.linkifyEmails(ctx.esc("Contact: nisha.sheth+x@example.co.in."));
  assert.equal(out, 'Contact: <a href="mailto:nisha.sheth+x@example.co.in">nisha.sheth+x@example.co.in</a>.');
  const evil = ctx.linkifyEmails(ctx.esc(`"><img src=x onerror=alert(1)>a@b.co "onmouseover="alert(1)@x.io`));
  const d = new JSDOM(`<div>${evil}</div>`).window.document;
  assert.equal(d.querySelectorAll("img").length, 0);
  for (const a of d.querySelectorAll("a")) { assert.ok(/^mailto:[A-Za-z0-9._%+@.-]+$/.test(a.getAttribute("href"))); assert.equal(a.attributes.length, 1); }
  assert.match(mod, /\$\{linkifyEmails\(esc\(policy\.body\)\)\}/, "policy body is escaped BEFORE linkifying");
});

test("mmAssociateLabels: ties orphan labels to the control that follows; never overrides existing for=, wrapped controls, hidden controls, or a control another label owns", () => {
  const dom = new JSDOM(`<div id="r">
    <div class="g"><label id="l1">Username</label><input id="u"></div>
    <div class="g"><label id="l2">Wrapped <input id="w"></label></div>
    <div class="g"><label id="l3" for="explicit">Has for</label><input id="other"><input id="explicit"></div>
    <div class="g"><label id="l4">Nested control</label><div><select id="s"><option>a</option></select></div></div>
    <div class="g"><label id="l5">PIN</label><input id="pin" aria-hidden="true" tabindex="-1"></div>
    <div class="g"><label id="l6">No id yet</label><input></div>
    <div class="g"><label id="l7">Dup A</label><input id="dup"></div><div class="g"><label id="l8">Dup B</label><input id="dup2"></div>
  </div>`);
  const ctx = { document: dom.window.document };
  vm.createContext(ctx); vm.runInContext(line(/^let mmLabelSeq = 0;$/m) + "\n" + extractFunction(mod, "mmAssociateLabels"), ctx);
  ctx.mmAssociateLabels(dom.window.document.body);
  const $ = (id) => dom.window.document.getElementById(id);
  assert.equal($("l1").htmlFor, "u");
  assert.equal($("l2").htmlFor, "", "wrapped control needs no for=");
  assert.equal($("l3").htmlFor, "explicit", "existing for= untouched");
  assert.equal($("l4").htmlFor, "s", "control inside the following wrapper");
  assert.equal($("l5").htmlFor, "", "aria-hidden / tabindex=-1 capture inputs are skipped");
  const gen = $("l6").htmlFor; assert.match(gen, /^mm_f_\d+$/); assert.equal($("l6").nextElementSibling.id, gen, "control given a generated id");
  assert.equal($("l7").htmlFor, "dup"); assert.equal($("l8").htmlFor, "dup2");
  // idempotent: a second pass changes nothing
  const before = dom.window.document.body.innerHTML; ctx.mmAssociateLabels(dom.window.document.body);
  assert.equal(dom.window.document.body.innerHTML, before);
});

test("modal keyboard contract: Escape + Tab trap + focus return + scroll unlock are all implemented in the shared modal code", () => {
  const sm = extractFunction(mod, "showModal");
  assert.match(sm, /__mmModalReturnFocus = document\.activeElement/);
  assert.match(mod, /root\.innerHTML="";\s*\n\s*document\.documentElement\.classList\.remove\('mm-modal-open'\)/);
  assert.match(mod, /e\.key==="Tab" && root/);
});
