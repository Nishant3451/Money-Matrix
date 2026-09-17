// ============================================================================================
// Frontend client-logic tests (Phase 3 — Client System).
//
// index.html is a single monolithic browser script, not a set of importable modules, so these
// tests extract the ACTUAL function source for the pure (DOM-free) client-logic functions
// straight out of index.html at test-time and evaluate them in a small sandbox with a stubbed
// data() — this exercises the real shipped code rather than a hand-copied duplicate that could
// silently drift out of sync with it.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

// Extracts `function <name>(...) { ... }` by brace-matching (regex alone can't safely handle
// nested braces in a function body).
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

const FUNCTIONS = [
  "levenshtein",
  "normalizeClientName",
  "normalizeClientPhone",
  "normalizeClientEmail",
  "findClientById",
  "getClientMatches",
  "findClientDuplicates",
];

function buildSandbox(clients) {
  const src = FUNCTIONS.map((name) => extractFunction(html, name)).join("\n\n");
  const sandbox = { data: () => ({ clients }), console };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return sandbox;
}

test("all expected client-logic functions are present in index.html (extraction sanity check)", () => {
  for (const name of FUNCTIONS) {
    assert.doesNotThrow(() => extractFunction(html, name), `${name} should be extractable`);
  }
});

test("normalizeClientPhone strips everything but digits", () => {
  const sandbox = buildSandbox([]);
  assert.equal(sandbox.normalizeClientPhone("+91 98765-43210"), "919876543210");
  assert.equal(sandbox.normalizeClientPhone(""), "");
  assert.equal(sandbox.normalizeClientPhone(undefined), "");
});

test("normalizeClientEmail trims and lowercases", () => {
  const sandbox = buildSandbox([]);
  assert.equal(sandbox.normalizeClientEmail("  Rahul@Example.com "), "rahul@example.com");
});

test("normalizeClientName strips punctuation/case for comparison", () => {
  const sandbox = buildSandbox([]);
  assert.equal(sandbox.normalizeClientName("Rahul  Patel!"), "rahul  patel");
});

test("getClientMatches: empty query returns all clients sorted by name", () => {
  const clients = [{ id: "c2", name: "Zara" }, { id: "c1", name: "Amit" }];
  const sandbox = buildSandbox(clients);
  const result = Array.from(sandbox.getClientMatches(""));
  assert.deepEqual(result.map((c) => c.id), ["c1", "c2"]);
});

test("getClientMatches: search by name (substring, case-insensitive)", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", phone: "9876543210" }, { id: "c2", name: "Amit Shah" }];
  const sandbox = buildSandbox(clients);
  const result = Array.from(sandbox.getClientMatches("rahul"));
  assert.deepEqual(result.map((c) => c.id), ["c1"]);
});

test("getClientMatches: search by phone digits", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", phone: "98765-43210" }, { id: "c2", name: "Amit Shah", phone: "9825012345" }];
  const sandbox = buildSandbox(clients);
  const result = Array.from(sandbox.getClientMatches("9876543210"));
  assert.deepEqual(result.map((c) => c.id), ["c1"]);
});

test("getClientMatches: search by email substring", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", email: "rahul@gmail.com" }, { id: "c2", name: "Amit Shah", email: "amit@yahoo.com" }];
  const sandbox = buildSandbox(clients);
  const result = Array.from(sandbox.getClientMatches("gmail"));
  assert.deepEqual(result.map((c) => c.id), ["c1"]);
});

test("findClientById returns the matching client or null", () => {
  const clients = [{ id: "c1", name: "Rahul Patel" }];
  const sandbox = buildSandbox(clients);
  assert.equal(sandbox.findClientById("c1").name, "Rahul Patel");
  assert.equal(sandbox.findClientById("nope"), null);
  assert.equal(sandbox.findClientById(null), null);
});

test("findClientDuplicates: flags an exact phone match", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", phone: "9876543210" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("Different Name", "98765 43210", "", null);
  assert.deepEqual(dupes.map((c) => c.id), ["c1"]);
});

test("findClientDuplicates: flags an exact email match", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", email: "rahul@gmail.com" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("Different Name", "", "Rahul@Gmail.com", null);
  assert.deepEqual(dupes.map((c) => c.id), ["c1"]);
});

test("findClientDuplicates: flags an exact (normalized) name match", () => {
  const clients = [{ id: "c1", name: "Rahul Patel" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("rahul patel", "", "", null);
  assert.deepEqual(dupes.map((c) => c.id), ["c1"]);
});

test("findClientDuplicates: flags a near-exact (typo) name match via levenshtein", () => {
  const clients = [{ id: "c1", name: "Rahul Patel" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("Rahul Patell", "", "", null); // one extra letter
  assert.deepEqual(dupes.map((c) => c.id), ["c1"]);
});

test("findClientDuplicates: does NOT flag genuinely different people", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", phone: "9876543210", email: "rahul@gmail.com" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("Amit Shah", "9825012345", "amit@yahoo.com", null);
  assert.deepEqual(dupes, []);
});

test("findClientDuplicates: excludeId omits the record being edited from its own duplicate check", () => {
  const clients = [{ id: "c1", name: "Rahul Patel", phone: "9876543210" }];
  const sandbox = buildSandbox(clients);
  const dupes = sandbox.findClientDuplicates("Rahul Patel", "9876543210", "", "c1");
  assert.deepEqual(dupes, []);
});

// ---------------------------------------------------------------------------------------------
// Client field validation (Part A6) — UX/data-integrity safeguard, NOT a security boundary.
// ---------------------------------------------------------------------------------------------
test("validateClientFields: accepts fields within limits", () => {
  const sandbox = buildSandbox([]);
  const limitsSrc = html.match(/^const CLIENT_FIELD_LIMITS.*$/m)[0];
  const validateSrc = extractFunction(html, "validateClientFields");
  vm.runInContext(limitsSrc + "\n" + validateSrc, sandbox);
  const err = sandbox.validateClientFields({ name: "Rahul Patel", phone: "9876543210", email: "r@example.com", address: "123 Main St", notes: "" });
  assert.equal(err, null);
});

test("validateClientFields: rejects an oversized name", () => {
  const sandbox = buildSandbox([]);
  const limitsSrc = html.match(/^const CLIENT_FIELD_LIMITS.*$/m)[0];
  const validateSrc = extractFunction(html, "validateClientFields");
  vm.runInContext(limitsSrc + "\n" + validateSrc, sandbox);
  const err = sandbox.validateClientFields({ name: "x".repeat(200), phone: "", email: "", address: "", notes: "" });
  assert.match(err, /120 characters or fewer/);
});

test("validateClientFields: rejects oversized notes", () => {
  const sandbox = buildSandbox([]);
  const limitsSrc = html.match(/^const CLIENT_FIELD_LIMITS.*$/m)[0];
  const validateSrc = extractFunction(html, "validateClientFields");
  vm.runInContext(limitsSrc + "\n" + validateSrc, sandbox);
  const err = sandbox.validateClientFields({ name: "Ok Name", phone: "", email: "", address: "", notes: "x".repeat(2000) });
  assert.match(err, /1000 characters or fewer/);
});
