// ============================================================================================
// Client-side CSV export safety tests (Part B, task brief section 24).
//
// csvSafeFieldClient()/rowsToCsv() are extracted straight from index.html (same technique as
// tests/import-security.test.js) so this exercises the real shipped "My Data" CSV export code,
// not a reimplementation. No jsdom needed -- these are pure string functions.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

function extractFunction(source, name) {
  const startMatch = source.match(new RegExp(`function\\s+${name}\\s*\\(`));
  if (!startMatch) throw new Error(`function ${name} not found in index.html`);
  const start = startMatch.index;
  const openBrace = source.indexOf("{", start);
  let depth = 0, i = openBrace;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(start, i + 1);
}

function loadCsvHelpers() {
  const src = [extractFunction(html, "csvSafeFieldClient"), extractFunction(html, "rowsToCsv")].join("\n\n");
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(`${src}\nthis.csvSafeFieldClient = csvSafeFieldClient; this.rowsToCsv = rowsToCsv;`, sandbox);
  return sandbox;
}

test("csvSafeFieldClient neutralizes classic formula-injection leads (matches server-side behavior)", () => {
  const { csvSafeFieldClient } = loadCsvHelpers();
  assert.equal(csvSafeFieldClient("=cmd(|'/C calc'!A0)"), "'=cmd(|'/C calc'!A0)");
  assert.equal(csvSafeFieldClient("+123"), "'+123");
  assert.equal(csvSafeFieldClient("-123"), "'-123");
  assert.equal(csvSafeFieldClient("@SUM(A1:A2)"), "'@SUM(A1:A2)");
});

test("csvSafeFieldClient does not corrupt ordinary values", () => {
  const { csvSafeFieldClient } = loadCsvHelpers();
  assert.equal(csvSafeFieldClient("Rahul Patel"), "Rahul Patel");
  assert.equal(csvSafeFieldClient(42), "42");
  assert.equal(csvSafeFieldClient(null), "");
  assert.equal(csvSafeFieldClient(undefined), "");
});

test("csvSafeFieldClient quotes commas/quotes/newlines", () => {
  const { csvSafeFieldClient } = loadCsvHelpers();
  assert.equal(csvSafeFieldClient('Hello, "World"'), '"Hello, ""World"""');
});

test("rowsToCsv keeps a malicious field from becoming a live formula in the output", () => {
  const { rowsToCsv } = loadCsvHelpers();
  const csv = rowsToCsv([{ type: "=2+2", purpose: "ok" }], ["type", "purpose"], "CONSENTS");
  assert.ok(csv.includes("'=2+2"));
  assert.ok(!/(?:^|\r\n)=2\+2/.test(csv), "a bare (unescaped) formula must never appear at the start of a line");
});

// ============================================================================================
// PHASE 5 AUDIT ITEM #10: exportCSV() (the main "Financial Report" / transactions.csv export)
// previously built its rows with plain `"` -> `""` escaping ONLY (no leading =/+/-/@
// neutralization), unlike every other CSV export in this file -- a real, exploitable
// formula-injection gap in a financial export (Customer/Product/Notes/Client ID are all
// attacker-controllable). It has been changed to route every field through the same tested
// csvSafeFieldClient() used elsewhere. This proves the fix by extracting exportCSV's real
// source and checking it against the old vulnerable pattern and the new safe one.
// ============================================================================================
test("REGRESSION (would have failed before the fix): exportCSV no longer uses the old unsafe inline quoting, and now calls csvSafeFieldClient per-field", () => {
  const exportCsvSrc = extractFunctionAssignment(html, "exportCSV");
  assert.ok(
    !/`"\$\{String\(c\)\.replace\(\/"\/g,'""'\)\}"`/.test(exportCsvSrc),
    "the old unsafe inline-escaping pattern (no formula-injection neutralization) must be gone"
  );
  assert.ok(/csvSafeFieldClient\(c\)/.test(exportCsvSrc), "exportCSV must route each field through csvSafeFieldClient");
});

function extractFunctionAssignment(source, name) {
  const startMatch = source.match(new RegExp(`window\\.${name}\\s*=`));
  if (!startMatch) throw new Error(`window.${name}= not found in index.html`);
  const start = startMatch.index;
  const openBrace = source.indexOf("{", start);
  let depth = 0, i = openBrace;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") { depth--; if (depth === 0) break; }
  }
  return source.slice(start, i + 1);
}
