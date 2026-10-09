// Client side of "ownership is immutable": editing an EXISTING Payment/Quotation must never re-stamp ownerId (the old
// behaviour silently handed a downline member's record to whoever edited it). The Worker enforces the same rule
// (cloudflare-worker/tests/record-acl*.test.js); this pins that the client no longer even tries.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const mod = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
function extractArrowConst(source, name) {
  const start = source.indexOf(`const ${name} = (`);
  if (start < 0) throw new Error(`${name} not found`);
  const open = source.indexOf("{", source.indexOf("=>", start));
  let depth = 0, i = open;
  for (; i < source.length; i++) { if (source[i] === "{") depth++; else if (source[i] === "}") { depth--; if (depth === 0) break; } }
  return source.slice(start, i + 1);
}
function env(records, coll = "transactions") {
  const d = { transactions: [], quotations: [], members: [], [coll]: records };
  const calls = [];
  const ctx = { data: () => d, ACTIVITY_LABELS: { transactions: { nameKey: "customer" }, quotations: { nameKey: "customer" }, members: { nameKey: "name" } }, logActivity: () => {}, scopeIdFor: () => null, save: () => {}, closeModal: () => {}, render: () => {}, toast: (m) => calls.push(m) };
  vm.createContext(ctx);
  vm.runInContext(extractArrowConst(mod, "commitItem"), ctx);
  return { ctx, d };
}

for (const coll of ["transactions", "quotations"]) {
  test(`[${coll}] editing an existing record keeps its stored ownerId (and acl) instead of re-stamping the editor`, () => {
    const { ctx, d } = env([{ id: "r1", ownerId: "low", customer: "A", acl: { rev: 2, grants: [] } }], coll);
    vm.runInContext(`commitItem(${JSON.stringify(coll)}, { id: "r1", customer: "B", ownerId: "mid" }, "ok")`, ctx);
    assert.equal(d[coll][0].customer, "B", "the edit itself is applied");
    assert.equal(d[coll][0].ownerId, "low", "ownership is not transferred to the editor");
    assert.deepEqual(d[coll][0].acl, { rev: 2, grants: [] });
  });

  test(`[${coll}] a NEW record is stamped with the creator as before`, () => {
    const { ctx, d } = env([], coll);
    vm.runInContext(`commitItem(${JSON.stringify(coll)}, { id: "n1", customer: "X", ownerId: "mid" }, "ok")`, ctx);
    assert.equal(d[coll][0].ownerId, "mid");
    assert.equal("acl" in d[coll][0], false);
  });
}

test("other collections are untouched by the ownership rule (members keep their existing behaviour)", () => {
  const { ctx, d } = env([{ id: "m1", ownerId: "low", name: "A" }], "members");
  vm.runInContext(`commitItem("members", { id: "m1", name: "B", ownerId: "mid" }, "ok")`, ctx);
  assert.equal(d.members[0].ownerId, "mid");
});

test("legacy records with no stored ownerId keep the submitted one (nothing to preserve)", () => {
  const { ctx, d } = env([{ id: "r1", customer: "A" }]);
  vm.runInContext(`commitItem("transactions", { id: "r1", customer: "B", ownerId: "mid" }, "ok")`, ctx);
  assert.equal(d.transactions[0].ownerId, "mid");
});
