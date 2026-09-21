// ============================================================================================
// Regression tests for the "fix/feature pass" that followed commit f0bcb75:
//   1. Dashboard Quick Add: the action buttons opened their form and closeModal()'s deferred
//      fade-out then wiped it, so nothing appeared to happen.
//   2. "Marathon Payments" -> "Payments" (user-facing text only; the internal `marathon`
//      permission/data key must be unchanged).
//   3. Payments totals (Total/Pending x Received/Sent).
//   4. Privacy Center reachable from the sidebar; policies + tools visible on its first screen.
//
// index.html is one monolithic browser script, so — like the other tests in this folder — these
// pull the ACTUAL shipped source out of index.html at test time rather than copying it.
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

function extractFunction(source, name) {
  const m = source.match(new RegExp(`function\\s+${name}\\s*\\(`));
  if (!m) throw new Error(`function ${name} not found`);
  const open = source.indexOf("{", m.index);
  let depth = 0, i = open;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(m.index, i + 1);
}
function between(source, startMarker, endMarker) {
  const a = source.indexOf(startMarker);
  const b = source.indexOf(endMarker, a);
  if (a < 0 || b < 0) throw new Error(`markers not found: ${startMarker} .. ${endMarker}`);
  return source.slice(a, b);
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Quick Add harness: real showModal/closeModal/openQuickAddMenu/quickAddGo ----------
const showModalSrc = html.match(/^function showModal\(html\)\{.*$/m)[0];
const reducedMotionSrc = html.match(/^const mmReducedMotion = .*$/m)[0];
const closeModalSrc = between(html, "window.closeModal=()=>{", "document.addEventListener('keydown'");
const quickAddSrc = between(html, "const QUICK_ADD_ACTIONS", "/* ===== Dashboard ===== */");

function buildQuickAddEnv({ perms, reducedMotion = false }) {
  const dom = new JSDOM(`<!DOCTYPE html><body><div id="modalRoot"></div></body>`, { runScripts: "dangerously" });
  const w = dom.window;
  w.matchMedia = () => ({ matches: reducedMotion });
  w.eval(`
    var $ = (id) => document.getElementById(id);
    var pendingRemoteJson = null, isDirty = false, applyRemoteJson = () => {};
    var __perms = ${JSON.stringify(perms)};
    var canWrite = (s) => !!__perms[s];
    ${showModalSrc}
    ${reducedMotionSrc}
    ${closeModalSrc}
    // stand-ins for the three real form openers: like the real ones, they just call showModal()
    var memberModal = () => showModal('<div id="memberFormMarker">member form</div>');
    var coachModal  = () => showModal('<div id="coachFormMarker">coach form</div>');
    var supModal    = () => showModal('<div id="supFormMarker">supervisor form</div>');
    ${quickAddSrc}
  `);
  return { w, doc: w.document, setPerm: (k, v) => w.eval(`__perms[${JSON.stringify(k)}] = ${v}`) };
}
const ALL = { club: true, coaches: true, supervisors: true };

test("ROOT CAUSE: the old `closeModal(); openForm()` pattern is wiped by closeModal()'s deferred clear", async () => {
  const { w, doc } = buildQuickAddEnv({ perms: ALL });
  w.eval(`openQuickAddMenu()`);
  // exactly what the old inline onclick="closeModal();memberModal()" did
  w.eval(`closeModal(); memberModal();`);
  assert.ok(doc.getElementById("memberFormMarker"), "form is present immediately after the click…");
  await wait(300);
  assert.equal(doc.getElementById("memberFormMarker"), null, "…and is wiped once the fade-out finishes (the reported 'nothing happens')");
});

for (const reducedMotion of [false, true]) {
  test(`Quick Add: "+" opens the menu and each action opens its form and keeps it open (reducedMotion=${reducedMotion})`, async () => {
    for (const [kind, label, marker] of [["member", "Add Member", "memberFormMarker"], ["coach", "Add Coach", "coachFormMarker"], ["supervisor", "Add Supervisor", "supFormMarker"]]) {
      const { w, doc } = buildQuickAddEnv({ perms: ALL, reducedMotion });
      // the real "+" button markup from renderDash(), clicked through the DOM
      doc.body.insertAdjacentHTML("beforeend", `<button id="plus" onclick="openQuickAddMenu()"></button>`);
      doc.getElementById("plus").click();
      assert.match(doc.getElementById("modalRoot").textContent, /Quick Add/);
      const btn = [...doc.querySelectorAll("#modalRoot button")].find((b) => b.textContent.includes(label));
      assert.ok(btn, `${label} button rendered`);
      btn.click();
      await wait(400);
      assert.ok(doc.getElementById(marker), `${label}: form is open after the close animation finished`);
    }
  });
}

test("Quick Add: no new permissions — only actions the user can write are offered or executable", async () => {
  const { w, doc, setPerm } = buildQuickAddEnv({ perms: { club: true, coaches: false, supervisors: false } });
  w.eval(`openQuickAddMenu()`);
  const text = doc.getElementById("modalRoot").textContent;
  assert.match(text, /Add Member/);
  assert.doesNotMatch(text, /Add Coach|Add Supervisor/);
  // forging the call directly does nothing
  w.eval(`quickAddGo('coach'); quickAddGo('supervisor');`);
  await wait(300);
  assert.equal(doc.getElementById("coachFormMarker"), null);
  assert.equal(doc.getElementById("supFormMarker"), null);
  // permission revoked between the click and the (200ms-later) open -> still nothing opens
  w.eval(`quickAddGo('member')`);
  setPerm("club", false);
  await wait(300);
  assert.equal(doc.getElementById("memberFormMarker"), null);
});

test("Quick Add: unknown / prototype-key arguments are ignored (no lookup escape)", async () => {
  const { w, doc } = buildQuickAddEnv({ perms: ALL });
  for (const k of ["constructor", "__proto__", "toString", "hasOwnProperty", "", "x');alert(1);//"]) {
    w.eval(`quickAddGo(${JSON.stringify(k)})`);
  }
  await wait(300);
  assert.equal(doc.getElementById("modalRoot").innerHTML, "");
});

test("Quick Add: handlers are static strings (no interpolated data => no XSS surface) and the old pattern is gone", () => {
  const block = quickAddSrc;
  assert.doesNotMatch(block, /\$\{(?!options\})/, "template only interpolates the pre-built options string");
  assert.doesNotMatch(html, /closeModal\(\);\s*(memberModal|coachModal|supModal|txModal)\(/);
  assert.match(html, /canWrite\('club'\)\|\|canWrite\('coaches'\)\|\|canWrite\('supervisors'\)\) \? `<button class="dash-quick-toggle" onclick="openQuickAddMenu\(\)"/, "the '+' is still permission-gated in renderDash");
});

// ---------- Payment totals ----------
const totalsSandbox = {};
vm.createContext(totalsSandbox);
vm.runInContext(extractFunction(html, "computePaymentTotals"), totalsSandbox);
const computePaymentTotals = (x) => JSON.parse(JSON.stringify(totalsSandbox.computePaymentTotals(x)));

test("Payment totals: the four buckets follow the stated definitions with no double counting", () => {
  const txs = [
    { type: "received", status: "completed", amount: 1000 },
    { status: "completed", amount: 250 },                     // no type => received/credit
    { type: "sent", status: "completed", amount: 400 },
    { type: "received", status: "pending", amount: 70 },
    { type: "sent", status: "pending", amount: 30 },
    { type: "sent", status: "pending", amount: "5" },        // numeric string
  ];
  assert.deepEqual(computePaymentTotals(txs), { totalReceived: 1250, totalSent: 400, pendingReceived: 70, pendingSent: 35 });
});

test("Payment totals: pending never leaks into completed totals; unknown status and bad amounts are ignored safely", () => {
  const t = computePaymentTotals([
    { type: "received", status: "pending", amount: 999 },
    { type: "sent", status: "cancelled", amount: 500 },
    { type: "received", status: undefined, amount: 500 },
    { type: "received", status: "completed", amount: "abc" },
    { type: "received", status: "completed", amount: null },
    null,
  ]);
  assert.deepEqual(t, { totalReceived: 0, totalSent: 0, pendingReceived: 999, pendingSent: 0 });
  assert.deepEqual(computePaymentTotals(undefined), { totalReceived: 0, totalSent: 0, pendingReceived: 0, pendingSent: 0 });
});

test("Payments page: totals are computed from the same authorized dataset the table uses (data().transactions), unaffected by search/filter", () => {
  const fn = extractFunction(html, "renderMarathon");
  assert.match(fn, /paymentTotalsHtml\(data\(\)\.transactions\)/);
  const totalsHtmlFn = extractFunction(html, "paymentTotalsHtml");
  for (const label of ["Total Received", "Total Sent", "Pending Received", "Pending Sent"]) assert.ok(totalsHtmlFn.includes(label), label);
  // page is still gated by the existing 'marathon' view permission in render()
  assert.match(html, /NAV\.find\(n=>n\.id===activePage\)\?\.req && !canView\(activePage\)\) activePage = "dashboard"/);
});

// ---------- Rename ----------
test("Rename: no user-facing 'Marathon Payment(s)' remains; internal `marathon` key is unchanged", () => {
  const withoutComments = html.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const hits = [...withoutComments.matchAll(/[^\n]*Marathon (Payment|Flow|Log)[^\n]*/gi)].map((m) => m[0].trim());
  // the only permitted occurrence is the display-time mapping for OLD persisted activity entries
  assert.equal(hits.length, 1, hits.join("\n"));
  assert.match(hits[0], /a\.label==='Marathon Payment'\?'Payment'/);
  assert.match(html, /\{id:"marathon",label:"Payments",icon:"fa-running", req:"marathon"/);
  assert.match(html, /\{id:'marathon', name:'Payments', icon:'fa-running', desc:/);
  assert.match(html, /\{id:'marathon', name:'Payments', icon:'fa-running'\}/);
  assert.match(html, /marathon:"write", club:"write"/, "default permission key retained");
  assert.match(html, /titles=\{dashboard:"Dashboard Overview",marathon:"Payments"/);
  assert.match(html, /marathon:"Payments", club:"Club Membership"/, "I18N label (which overrides the page title) renamed");
});

// ---------- Privacy Center visibility ----------
test("Privacy Center: has a sidebar entry for every signed-in user, and the route + admin tab are intact", () => {
  assert.match(html, /\{id:"privacy",label:"Privacy Center",icon:"fa-user-shield", always:true, section:"Account"\}/);
  assert.match(html, /privacy:renderPrivacyCenter/);
  const nav = between(html, "const NAV=[", "];");
  const line = nav.split("\n").find((l) => l.includes('id:"privacy"'));
  assert.doesNotMatch(line, /req:|adminOnly|superAdminOnly/, "not hidden behind any role/permission");
  assert.match(extractFunction(html, "renderPrivacyCenter"), /if\(isAdmin\(\)\) tabs\.push\(\{ id:'admin'/);
});

test("Privacy Center: overview shows the four policies plus Consent & Preferences, My Data, My Requests", () => {
  const src = extractFunction(html, "privacyQuickLinksHtml");
  assert.match(src, /Object\.keys\(POLICY_CONTENT\)/);
  for (const l of ["Consent & Preferences", "My Data", "My Requests"]) assert.ok(src.includes(l), l);
  const policySrc = between(html, "const POLICY_CONTENT = {", "let privacyTab");
  for (const t of ["Privacy Policy", "Terms of Service", "Cookie & Storage Policy", "Data Deletion & User Rights"]) assert.ok(policySrc.includes(`title: "${t}"`), t);
  assert.match(extractFunction(html, "privacyOverviewHtml"), /privacyQuickLinksHtml\(\)/);
});

test("Build marker: meta tag and JS constant agree", () => {
  const meta = html.match(/<meta name="app-build" content="([^"]+)"/)[1];
  const js = html.match(/const APP_BUILD = "([^"]+)"/)[1];
  assert.equal(meta, js);
});
