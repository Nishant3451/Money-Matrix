// ============================================================================================
// Adversarial regression tests for the three additional sinks found in the second independent
// audit: flavor management (deleteFlavor/addFlavorThenReopen), alert dismissal handlers, and
// custom-section delete handlers (performDelete/performDeleteCustom). Same real-DOM-execution
// methodology as tests/xss-regression.test.js — extracts the ACTUAL sj()/esc() from index.html
// and proves the generated onclick markup is inert against attacker-controlled persisted values.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

function extractConst(source, name) {
  const m = source.match(new RegExp(`^const ${name}\\s*=.*$`, "m"));
  if (!m) throw new Error(`const ${name} not found`);
  return m[0];
}
const { esc, sj } = new Function(`${extractConst(html, "esc")}\n${extractConst(html, "sj")}\nreturn {esc, sj};`)();

const PAYLOADS = [
  "x');window.__xss=true;//",
  "');window.__xss=true;//",
  "&#39;",
  "&quot;",
  "<svg/onload=window.__xss=true>",
];

function runHandler(fnName, argsExprList) {
  const html2 = `<!DOCTYPE html><html><body>
<button id="btn" onclick="${fnName}(${argsExprList.join(",")})"></button>
<script>window.__xss=false; window.__calledWith=null; window.${fnName}=function(...a){ window.__calledWith=a; };</script>
</body></html>`;
  const dom = new JSDOM(html2, { runScripts: "dangerously" });
  const { window } = dom;
  window.document.getElementById("btn").dispatchEvent(new window.Event("click"));
  return { window };
}

// ---------------------------------------------------------------------------------------------
// 1. Flavor management — the specific pattern flagged: esc(f).replace(/'/g,"\\'") is a no-op
//    because esc() already turned ' into an entity by the time replace() runs.
// ---------------------------------------------------------------------------------------------
test("deleteFlavor: a persisted flavor name cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    // Reproduces the FIXED real line: onclick="deleteFlavor(${sj(kind)},${sj(label)},${sj(f)})"
    const { window } = runHandler("deleteFlavor", [sj("formula1Flavors"), sj("Formula 1"), sj(payload)]);
    assert.equal(window.__xss, false, `flavor payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), ["formula1Flavors", "Formula 1", payload]);
  }
});

test("addFlavorThenReopen: a persisted section label cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    const { window } = runHandler("addFlavorThenReopen", [sj("afreshFlavors"), sj(payload)]);
    assert.equal(window.__xss, false, `label payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), ["afreshFlavors", payload]);
  }
});

test("REGRESSION: the original deleteFlavor esc()+replace() pattern was genuinely exploitable", () => {
  // Documents why the fix was necessary — replicates the exact vulnerable pre-fix expression.
  const payload = "x');window.__xss=true;//";
  const vulnerable = `esc(payload).replace(/'/g,"\\\\'")`; // what the old code did, conceptually
  const fakeOldOutput = esc(payload).replace(/'/g, "\\'"); // esc() already ate the ' — replace is a no-op
  const html2 = `<!DOCTYPE html><html><body>
<button id="btn" onclick="probe('${fakeOldOutput}')"></button>
<script>window.__xss=false; window.probe=function(v){};</script>
</body></html>`;
  const dom = new JSDOM(html2, { runScripts: "dangerously" });
  dom.window.document.getElementById("btn").dispatchEvent(new dom.window.Event("click"));
  assert.equal(dom.window.__xss, true, "the pre-fix pattern should have been exploitable, proving the fix mattered");
});

// ---------------------------------------------------------------------------------------------
// 2. Alert dismissal handlers
// ---------------------------------------------------------------------------------------------
test("dismissSingleAlert: a malicious member id cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    // Reproduces the FIXED real line: onclick="dismissSingleAlert(${sj(m.id+'_k1')})"
    const { window } = runHandler("dismissSingleAlert", [sj(payload + "_k1")]);
    assert.equal(window.__xss, false, `alert id payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), [payload + "_k1"]);
  }
});

test("dismissSingleAlert: a malicious duplicate-pair key cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    const { window } = runHandler("dismissSingleAlert", [sj("dupe_" + payload)]);
    assert.equal(window.__xss, false, `pair-key payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), ["dupe_" + payload]);
  }
});

// ---------------------------------------------------------------------------------------------
// 3. Custom section delete handlers (second-order sink: performDelete/performDeleteCustom
//    re-embed an already-received id into a NEW onclick string inside their own confirm modal)
// ---------------------------------------------------------------------------------------------
test("performDelete confirm button: a malicious record id cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    // Reproduces the FIXED real line: onclick="performDelete(${sj(coll)},${sj(id)})"
    const { window } = runHandler("performDelete", [sj("clients"), sj(payload)]);
    assert.equal(window.__xss, false, `delete-confirm id payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), ["clients", payload]);
  }
});

test("performDeleteCustom confirm button: a malicious section/record id cannot break out of the onclick JS-string argument", () => {
  for (const payload of PAYLOADS) {
    // Reproduces the FIXED real line: onclick="performDeleteCustom(${sj(sectionId)},${sj(id)})"
    const { window } = runHandler("performDeleteCustom", [sj(payload), sj(payload)]);
    assert.equal(window.__xss, false, `custom delete-confirm id payload executed: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__calledWith), [payload, payload]);
  }
});

// ---------------------------------------------------------------------------------------------
// 4. Access Control / rank-section second-order sinks found in the full re-sweep
// ---------------------------------------------------------------------------------------------
test("updatePerm/updateIndivPerm/setRankSecSearch/rank-and-merge handlers: malicious ids are inert", () => {
  const fns = ["updatePerm", "updateIndivPerm", "setRankSecSearch", "setRankSecTypeFilter",
    "executeRankChange", "confirmSupervisorPromotion", "renderMergePreview", "confirmMerge", "go"];
  for (const fn of fns) {
    for (const payload of PAYLOADS.slice(0, 2)) { // the two quote-breakout payloads are the critical ones here
      const { window } = runHandler(fn, [sj(payload)]);
      assert.equal(window.__xss, false, `${fn} executed payload: ${JSON.stringify(payload)}`);
    }
  }
});
