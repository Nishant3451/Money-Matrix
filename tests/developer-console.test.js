// Client tests for the Developer Console, the Developer role helpers and the "Assigned To" field.
// Functions are extracted from index.html and run in a sandbox with fakes (nothing is re-implemented).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "index.html"), "utf8");
const mod = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];

function extractFunction(source, name) {
  let m = source.match(new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`));
  let head, open;
  if (m) { open = source.indexOf("{", source.indexOf(")", m.index)); head = source.slice(m.index, open); }
  else {
    m = source.match(new RegExp(`window\\.${name}\\s*=\\s*(async\\s*)?\\(?([^)=]*)\\)?\\s*=>\\s*\\{`));
    if (!m) throw new Error(name + " not found");
    open = m.index + m[0].length - 1; head = `${m[1] || ""}function ${name}(${m[2]}) `;
  }
  let depth = 0, i = open;
  for (; i < source.length; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") { depth--; if (depth === 0) break; } }
  return head + source.slice(open, i + 1);
}
const same = (a, b) => assert.equal(JSON.stringify(a), JSON.stringify(b));
const names = ["devCtl","devAllRecords","devRecLabel","devErr","devRefresh","devPolicyCall","devAuditRows","renderDevConsole","isDeveloper","apiErrorText"];
const winNames = ["devSelectUser","devSelectColl","devToggleScope","devResetScope","devToggleGlobal","devAssign","devAclSave","devToggleDisabled"];
const SRC = "let devSel=null, devColl='transactions', devMsg='';\n" + [...names, ...winNames].map((n) => extractFunction(mod, n)).join("\n");

function env(role, over = {}) {
  const dom = new JSDOM(`<div id="pageBody"></div><div id="modalRoot"></div>`);
  const calls = [];
  const ctx = {
    document: dom.window.document, console, JSON, Object, Number, String, Array, Date, Promise, Error,
    $: (id) => dom.window.document.getElementById(id),
    esc: (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
    sj: (v) => JSON.stringify(v).replace(/"/g, "&quot;"),
    money: (n) => "$" + n, toast: () => {}, showModal: () => {}, closeModal: () => {}, isSessionEndError: () => false,
    save: async () => ({ ok: true }), fetchAuthorizedData: async () => {}, render: () => {},
    activePage: "devconsole", calls,
    currentUser: { id: "dev", role },
    DB: { users: [{ id: "dev", username: "dev", role: "developer" }, { id: "sa", username: "sa", role: "superadmin" }, { id: "u1", username: "<img onerror=x>", role: "user" }],
      profiles: {}, shared: { transactions: [{ id: "p1", name: "Pay", amount: 5, ownerId: "u1" }, { id: "p0", name: "Old", amount: 1 }], quotations: [] }, perUser: {}, settings: { dataSharing: true } },
    serverDataScope: { control: { scopePolicy: { rev: 3, global: { superadminAll: true }, users: {} }, accessAudit: [{ ts: 1, actor: "dev", action: "assign", coll: "transactions", recId: "p1", from: null, to: "u1" }], recordAclAudit: [], effective: { u1: { role: "user", allowed: ["mine"], max: "mine" } } } },
    callWorkerApi: async (p, b) => { calls.push([p, b]); return {}; },
    ownerLabel: (u) => (u ? (ctx.DB.users.find((x) => x.id === u) || {}).username || u : "Unassigned (legacy record)"),
    ...over,
  };
  vm.createContext(ctx);
  vm.runInContext(SRC, ctx);
  return { ctx, dom, run: (s) => vm.runInContext(s, ctx) };
}

test("Developer Console is gated to the Developer in nav, render guard and page map", () => {
  assert.match(mod, /id:"devconsole"[^}]*developerOnly:true/);
  assert.match(mod, /if\(n\.developerOnly && !isDeveloper\(\)\) return ""/);
  assert.match(mod, /activePage==="devconsole" && !isDeveloper\(\)\) activePage="dashboard"/);
  assert.match(mod, /devconsole:renderDevConsole/);
  const e = env("superadmin");
    e.run("renderDevConsole()");
  assert.equal(e.ctx.activePage, "dashboard", "a non-developer never gets the console");
  assert.equal(e.dom.window.document.getElementById("pageBody").innerHTML, "");
});

test("console renders effective scope, records, legacy option and audit; escapes names", () => {
  const e = env("developer");
  e.run("devSel='u1'; renderDevConsole()");
  const body = e.dom.window.document.getElementById("pageBody").innerHTML;
  assert.match(body, /Legacy \/ unassigned records/);
  assert.match(body, /Pay/);
  assert.match(body, /Audit history/);
  assert.ok(!body.includes("<img onerror=x>"), "usernames are escaped");
  e.run("devSel='__legacy'; renderDevConsole()");
  const legacy = e.dom.window.document.getElementById("pageBody").innerHTML;
  assert.match(legacy, /Old/); assert.ok(!/>Pay</.test(legacy));
});

test("scope toggle posts the stored revision and a narrow-only policy; a stale revision reloads", async () => {
  const e = env("developer");
  await e.run("devToggleScope('u1','upline',false)");
  same(e.ctx.calls[0], ["/scope/policy", { baseRev: 3, user: { uid: "u1", policy: { upline: false } } }]);
  await e.run("devToggleGlobal(false)");
  same(e.ctx.calls[1], ["/scope/policy", { baseRev: 3, global: { superadminAll: false } }]);
  e.ctx.callWorkerApi = async () => { throw Object.assign(new Error("x"), { serverCode: "POLICY_STALE" }); };
  await e.run("devToggleScope('u1','downline',false)");
  assert.match(e.run("devMsg"), /changed elsewhere/);
});

test("reassign calls /record/assign with the expected owner; server refusals show the server's message", async () => {
  const e = env("developer");
  e.dom.window.document.getElementById("modalRoot").innerHTML = `<select id="s"><option value="u1" selected>u1</option></select>`;
  await e.run("devAssign('transactions','p0',null,null,'s')");
  same(e.ctx.calls[0], ["/record/assign", { collection: "transactions", id: "p0", bucket: null, expectedOwner: null, targetUid: "u1" }]);
  const toasts = []; e.ctx.toast = (m) => toasts.push(m);
  e.ctx.callWorkerApi = async () => { throw Object.assign(new Error("x"), { serverMessage: "That person cannot be assigned this record" }); };
  await e.run("devAssign('transactions','p0',null,null,'s')");
  assert.equal(toasts[0], "That person cannot be assigned this record");
});

test("ACL save sends the grants ticked, or null to revert", async () => {
  const e = env("developer");
  e.dom.window.document.getElementById("modalRoot").innerHTML = `<input type="checkbox" checked data-acl-uid="u1" data-acl-perm="view"><input type="checkbox" checked data-acl-uid="u1" data-acl-perm="edit"><input type="checkbox" data-acl-uid="u2" data-acl-perm="view">`;
  await e.run("devAclSave('transactions','p1',null,2,false)");
  same(e.ctx.calls[0][1], { collection: "transactions", id: "p1", bucket: null, baseRev: 2, grants: [{ uid: "u1", perms: ["view", "edit"] }] });
  await e.run("devAclSave('transactions','p1',null,3,true)");
  assert.equal(e.ctx.calls[1][1].grants, null);
});

test("Assigned To fields exist on both forms, Payments/Quotations scopes stay independent, role helpers include the Developer", () => {
  assert.match(mod, /assigneeFieldHtml\('transactions','f_assignee'/);
  assert.match(mod, /assigneeFieldHtml\('quotations','q_assignee'/);
  assert.match(mod, /maraScope/); assert.match(mod, /quoteScope/);
  assert.match(mod, /function isDeveloper\(\)\{ return currentUser\?\.role==="developer"; \}/);
  assert.match(mod, /function isSuperAdmin\(\)\{[^}]*developer/);
});

test("disable / enable goes through the dedicated server endpoint, never the users blob; the Developer row has no button", async () => {
  const e = env("developer");
  await e.run("devToggleDisabled('u1')");
  same(e.ctx.calls[0], ["/user/disable", { targetUserId: "u1", disabled: true }]);
  e.ctx.DB.users.find((u) => u.id === "u1").disabled = true;
  await e.run("devToggleDisabled('u1')");
  same(e.ctx.calls[1], ["/user/disable", { targetUserId: "u1", disabled: false }]);
  await e.run("devToggleDisabled('dev')");
  assert.equal(e.ctx.calls.length, 2, "the Developer account is never sent for disabling");
  assert.ok(!/devToggleDisabled[\s\S]{0,200}save\(true\)/.test(mod.slice(mod.indexOf("window.devToggleDisabled"), mod.indexOf("window.devAssign"))));
});
