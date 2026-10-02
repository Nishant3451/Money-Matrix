// Client side of the Data Scope + Payment-status features. The SERVER is the security boundary (see
// cloudflare-worker/tests/data-scope.test.js); these tests pin that the client only ever NARROWS what the server already
// authorized, in the right order (authorized -> scope -> status), and never offers an option the server would reject.
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

function extractFunction(source, name) {
  const m = source.match(new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`));
  if (!m) throw new Error(`${name} not found`);
  const open = source.indexOf("{", source.indexOf(")", m.index));
  let depth = 0, i = open;
  for (; i < source.length; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") { depth--; if (depth === 0) break; } }
  return source.slice(m.index, i + 1);
}
const line = (re) => mod.match(re)[0];
const SRC = [
  line(/^let serverDataScope = null;.*$/m), line(/^const SCOPE_LABELS = .*$/m), line(/^let maraScope = null, .*$/m), line(/^const PAYMENT_STATUS_OPTIONS = .*$/m),
  ...["effectiveScopeKey", "scopeOwnerSet", "filterRecordsByOwner", "paymentStatusKey", "filterPaymentsByStatus", "scopedRecords", "scopeControlHtml", "scopeNoteText"].map((n) => extractFunction(mod, n)),
].join("\n");

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function env({ shared = true, viewingAs = "adm" } = {}) { // the app sets viewingAs to the user's OWN id at login
  const DB = { settings: { dataSharing: shared }, shared: { transactions: [], quotations: [] }, perUser: {} };
  const ctx = { DB, viewingAs, currentUser: { id: "adm" }, esc, data: () => (DB.settings.dataSharing ? DB.shared : DB.perUser[ctx.viewingAs || ctx.currentUser.id]) };
  vm.createContext(ctx); vm.runInContext(SRC, ctx);
  return { ctx, DB, run: (s) => vm.runInContext(s, ctx), set: (ds) => vm.runInContext("serverDataScope = " + JSON.stringify(ds), ctx) };
}
const ADMIN_DS = { allowed: ["mine_downline", "mine", "downline"], default: "mine_downline", active: "mine_downline", owners: { mine: ["adm"], downline: ["low", "leaf"], mine_downline: ["adm", "low", "leaf"] } };
const SUPER_DS = { allowed: ["all", "mine"], default: "all", active: "all", owners: { mine: ["sa"], downline: [], mine_downline: ["sa"] } };
const P = [
  { id: "a", ownerId: "adm", status: "pending" }, { id: "b", ownerId: "adm", status: "completed" }, { id: "c", ownerId: "low", status: "pending" },
  { id: "d", ownerId: "leaf", status: "completed" }, { id: "w", ownerId: "adm", status: "refunded" }, { id: "n", ownerId: "adm" },
];
const ids = (a) => Array.from(a, (x) => x.id); // Array.from => main-realm array (vm-realm arrays are not prototype-equal under strict deepEqual)

// ------------------------------------------------------------------ payment status filter
test("status filter: All / Pending / Completed use the REAL status values (pending, completed) — no new status system", () => {
  const { ctx, run } = env();
  assert.deepEqual(JSON.parse(JSON.stringify(run("PAYMENT_STATUS_OPTIONS"))), [["all", "All"], ["pending", "Pending"], ["completed", "Completed"]]);
  assert.deepEqual(ids(ctx.filterPaymentsByStatus(P, "all")), ["a", "b", "c", "d", "w", "n"]);
  assert.deepEqual(ids(ctx.filterPaymentsByStatus(P, "pending")), ["a", "c"]);
  assert.deepEqual(ids(ctx.filterPaymentsByStatus(P, "completed")), ["b", "d"]);
  // the same literals the Payments form stores
  assert.match(mod, /<option value="completed"[^>]*>[^<]*<\/option>/);
  assert.match(mod, /<option value="pending"/);
});
test("status filter: unknown / invalid FILTER values fall back to All; records with unknown or missing status appear under All only", () => {
  const { ctx } = env();
  for (const bad of ["refunded", "PENDING", "Pending ", "", null, undefined, 0, {}, [], ["pending"], "__proto__", "constructor", "all,pending"]) {
    assert.deepEqual(ids(ctx.filterPaymentsByStatus(P, bad)), ["a", "b", "c", "d", "w", "n"], JSON.stringify(bad));
    assert.equal(ctx.paymentStatusKey(bad), "all");
  }
  assert.ok(!ids(ctx.filterPaymentsByStatus(P, "pending")).includes("w") && !ids(ctx.filterPaymentsByStatus(P, "completed")).includes("w"));
  assert.ok(!ids(ctx.filterPaymentsByStatus(P, "pending")).includes("n"));
});
test("status filter: tolerates junk records and never mutates or invents records", () => {
  const { ctx } = env(); const input = [null, undefined, 5, "x", { id: "ok", status: "pending" }]; const snap = JSON.stringify(input);
  assert.deepEqual(ids(ctx.filterPaymentsByStatus(input.filter(Boolean).filter((r) => typeof r === "object"), "pending")), ["ok"]);
  ctx.filterPaymentsByStatus(P, "pending"); assert.equal(JSON.stringify(input), snap);
  for (const s of ["all", "pending", "completed", "zzz"]) for (const r of ctx.filterPaymentsByStatus(P, s)) assert.ok(P.includes(r), "output is always a subset of the input (same objects)");
});

// ------------------------------------------------------------------ scope
test("scope: only keys the server listed are usable; anything else falls back to the server's default (never 'all')", () => {
  const { ctx } = env();
  assert.equal(ctx.effectiveScopeKey(ADMIN_DS, "downline"), "downline");
  for (const bad of ["all", "upline", null, undefined, "__proto__", "ALL", 1]) assert.equal(ctx.effectiveScopeKey(ADMIN_DS, bad), "mine_downline", JSON.stringify(bad));
  assert.equal(ctx.effectiveScopeKey(SUPER_DS, "all"), "all");
  assert.equal(ctx.effectiveScopeKey(null, "all"), null);
});
test("scopeOwnerSet fails closed: not-allowed key => undefined, missing owner list => undefined, 'all' => null (superadmin only)", () => {
  const { ctx } = env();
  assert.equal(ctx.scopeOwnerSet(ADMIN_DS, "all"), undefined, "an admin descriptor can never yield an unrestricted set");
  assert.equal(ctx.scopeOwnerSet(SUPER_DS, "all"), null);
  assert.equal(ctx.scopeOwnerSet({ allowed: ["mine"], owners: {} }, "mine"), undefined);
  assert.deepEqual([...ctx.scopeOwnerSet(ADMIN_DS, "downline")].sort(), ["leaf", "low"]);
  assert.deepEqual(ids(ctx.filterRecordsByOwner(P, undefined)), [], "undefined owners => nothing");
  assert.deepEqual(ids(ctx.filterRecordsByOwner(P, null)), ["a", "b", "c", "d", "w", "n"]);
});
test("M/N. pipeline order: scope is applied BEFORE status, so a Pending filter can never surface an out-of-scope record — even one present in a stale local cache", () => {
  const { ctx, DB, set } = env();
  DB.shared.transactions = [...P, { id: "x-top", ownerId: "top", status: "pending" }, { id: "x-other", ownerId: "other", status: "pending" }, { id: "x-legacy", status: "pending" }];
  set(ADMIN_DS);
  for (const status of ["all", "pending", "completed", "bogus"]) {
    const out = ctx.filterPaymentsByStatus(ctx.scopedRecords("transactions", "mine_downline"), status);
    for (const forbidden of ["x-top", "x-other", "x-legacy"]) assert.ok(!ids(out).includes(forbidden), `${status}: ${forbidden}`);
  }
  assert.deepEqual(ids(ctx.filterPaymentsByStatus(ctx.scopedRecords("transactions", "mine_downline"), "pending")), ["a", "c"]);
  // a requested scope the descriptor does not offer cannot widen it either
  assert.ok(!ids(ctx.scopedRecords("transactions", "all")).includes("x-other"));
});
test("scope narrows within the authorized set: mine / downline / mine_downline", () => {
  const { ctx, DB, set } = env(); DB.shared.transactions = P; set(ADMIN_DS);
  assert.deepEqual(ids(ctx.scopedRecords("transactions", "mine")), ["a", "b", "w", "n"].filter((i) => P.find((r) => r.id === i).ownerId === "adm"));
  assert.deepEqual(ids(ctx.scopedRecords("transactions", "downline")), ["c", "d"]);
  assert.deepEqual(ids(ctx.scopedRecords("transactions", null)), ["a", "b", "c", "d", "w", "n"], "default = widest allowed");
});
test("superadmin 'All Data' returns everything, including records with no owner; 'mine' narrows", () => {
  const { ctx, DB, set } = env(); DB.shared.transactions = [...P, { id: "legacy" }]; set({ ...SUPER_DS, owners: { mine: ["adm"], downline: [], mine_downline: ["adm"] } });
  assert.equal(ctx.scopedRecords("transactions", "all").length, 7);
  assert.deepEqual(ids(ctx.scopedRecords("transactions", "mine")), ["a", "b", "w", "n"]);
});
test("no server scope (local / offline mode, or before the first sync): nothing is filtered by scope and no control is rendered", () => {
  const { ctx, DB } = env(); DB.shared.transactions = P;
  assert.equal(ctx.scopedRecords("transactions", "mine").length, 6);
  assert.equal(ctx.scopeControlHtml("mara", "mine", "setMaraScope"), "");
});
test("per-user storage (viewingAs = own id, as at login): other people's buckets are listed read-only (__foreign); the caller's own bucket is untouched", () => {
  const { ctx, DB, set } = env({ shared: false });
  DB.perUser = { adm: { transactions: [{ id: "mine1", ownerId: "adm" }] }, low: { transactions: [{ id: "low1", ownerId: "low" }] }, leaf: { transactions: [] }, top: { transactions: [{ id: "top1" }] } };
  set(ADMIN_DS);
  const r = ctx.scopedRecords("transactions", "mine_downline");
  assert.deepEqual(ids(r).sort(), ["low1", "mine1"]);
  assert.ok(!r.find((x) => x.id === "mine1").__foreign && r.find((x) => x.id === "low1").__foreign === true);
  assert.equal(DB.perUser.low.transactions[0].__foreign, undefined, "stored records are never flagged (copies only)");
  assert.deepEqual(ids(ctx.scopedRecords("transactions", "mine")), ["mine1"]);
  assert.ok(!ids(r).includes("top1"));
});
test("per-user storage while an admin is 'viewing as' ANOTHER user: the existing single-bucket view applies, still filtered by the server's owner set", () => {
  const { ctx, DB, set } = env({ shared: false, viewingAs: "low" });
  DB.perUser = { adm: { transactions: [{ id: "mine1", ownerId: "adm" }] }, low: { transactions: [{ id: "low1", ownerId: "low" }, { id: "alien", ownerId: "other" }] } };
  set(ADMIN_DS);
  assert.deepEqual(ids(ctx.scopedRecords("transactions", "mine_downline")), ["low1"], "alien (owner outside the server scope) is never shown");
});

// ------------------------------------------------------------------ control rendering
test("controls: only server-allowed scopes are rendered — an admin never sees 'All Data'; a superadmin does", () => {
  const { ctx, set } = env();
  set(ADMIN_DS); const a = new JSDOM(`<div>${ctx.scopeControlHtml("mara", null, "setMaraScope")}</div>`).window.document;
  assert.deepEqual([...a.querySelectorAll("option")].map((o) => o.value), ["mine_downline", "mine", "downline"]);
  assert.ok(!/All Data/.test(a.body.textContent));
  assert.equal(a.querySelector("select").id, "mara_scope"); assert.equal(a.querySelector("label").htmlFor, "mara_scope");
  set(SUPER_DS); const s = new JSDOM(`<div>${ctx.scopeControlHtml("mara", null, "setMaraScope")}</div>`).window.document;
  assert.deepEqual([...s.querySelectorAll("option")].map((o) => o.value), ["all", "mine"]);
  assert.equal(s.querySelector("option[selected]").value, "all");
});
test("controls: a single allowed scope is shown as a read-only chip (the active scope stays visible, nothing to mis-click)", () => {
  const { ctx, set } = env(); set({ allowed: ["mine"], default: "mine", owners: { mine: ["u"] } });
  const d = new JSDOM(`<div>${ctx.scopeControlHtml("quote", null, "setQuoteScope")}</div>`).window.document;
  assert.equal(d.querySelectorAll("select").length, 0); assert.match(d.querySelector(".scope-chip").textContent, /My Data/);
});
test("controls: descriptor values are escaped (a hostile key can't break out of the attribute or inject markup)", () => {
  // NB: <img> inside <select> is dropped by the HTML parser itself, so the payload must break out of the ATTRIBUTE.
  const { ctx, set } = env(); const evil = 'mine" data-evil="1" onfocus="alert(1)';
  set({ allowed: [evil, "mine"], default: "mine", owners: {} });
  const d = new JSDOM(`<div>${ctx.scopeControlHtml("mara", null, "setMaraScope")}</div>`).window.document;
  const opts = [...d.querySelectorAll("option")];
  assert.equal(opts.length, 2);
  for (const o of opts) { assert.ok(!o.hasAttribute("data-evil") && !o.hasAttribute("onfocus"), "no injected attributes"); }
  assert.equal(opts[0].value, evil, "the hostile text is carried verbatim as a VALUE, inert");
});
test("note: states the active scope and counts so users never have to guess why records are (not) shown", () => {
  const { ctx, set } = env(); set(ADMIN_DS);
  assert.equal(ctx.scopeNoteText("downline", 2, 5, "payments", " · Status: Pending"), "Data Scope: My Downline · Status: Pending · Showing 2 of 5 payments");
  assert.match(ctx.scopeNoteText(null, 1, 1, "quotations"), /^Data Scope: My Data \+ Downline/);
});

// ------------------------------------------------------------------ wiring (source)
test("applyRemoteJson keeps the server's dataScope descriptor OUT of DB (never persisted, never echoed back on save)", () => {
  const fn = extractFunction(mod, "applyRemoteJson");
  assert.match(fn, /serverDataScope = view\.dataScope/);
  assert.match(fn, /delete view\.dataScope;\s*\n\s*DB = \{\.\.\.DB,\.\.\.view\};/);
});
test("Payments: scope + status sit before the existing search/type filters; totals still use the full authorized set; pipeline order is scope -> status", () => {
  const page = extractFunction(mod, "renderMarathon"), results = extractFunction(mod, "renderMarathonResults");
  assert.match(page, /paymentTotalsHtml\(data\(\)\.transactions\)/, "totals unchanged (not narrowed by the new filters)");
  assert.ok(page.indexOf("scopeControlHtml('mara'") < page.indexOf('id="mara_status"') && page.indexOf('id="mara_status"') < page.indexOf('id="search_marathon"'));
  assert.ok(results.indexOf("scopedRecords('transactions', maraScope)") < results.indexOf("filterPaymentsByStatus(inScope, maraStatus)"), "scope before status");
  assert.match(results, /marathonFilter!=="all"/, "existing type filter retained"); assert.match(results, /maraSearch/, "existing search retained");
  assert.match(mod, /window\.setMaraStatus=v=>\{ maraStatus=paymentStatusKey\(v\);/, "invalid status values are normalised");
  assert.match(results, /tx\.__foreign/, "records from other people's buckets are view-only");
});
test("Quotations: scope control before the existing search; list comes from scopedRecords; foreign rows are view-only", () => {
  const page = extractFunction(mod, "renderQuotations"), results = extractFunction(mod, "renderQuotationsResults");
  assert.ok(page.indexOf("scopeControlHtml('quote'") < page.indexOf('id="search_quotations"'));
  assert.match(results, /scopedRecords\('quotations', quoteScope\)/); assert.match(results, /quoteSearch/); assert.match(results, /q\.__foreign/);
});
test("the internal 'marathon' key and the existing data model are unchanged (no new collections, no renamed keys)", () => {
  assert.match(mod, /canWrite\('marathon'\)/); assert.doesNotMatch(mod, /DB\.shared\.(scopedPayments|paymentsByScope|dataScope)/);
  assert.match(extractFunction(mod, "renderMarathon"), /id="marathon_results"/);
});
