// ============================================================================================
// XSS regression tests — models the full real-browser execution path:
//
//   attacker/legitimate string -> HTML template generation (actual index.html code)
//     -> browser HTML parser (jsdom, same entity-decoding behavior as a real browser)
//       -> DOM attribute -> inline event-handler compilation -> execution
//
// These are NOT jsdom-only assertions about string shape — they actually construct the DOM via
// jsdom's HTML parser (which implements the same spec-mandated attribute entity-decoding a real
// browser does), attach the resulting element to a document, dispatch a real event, and check
// what code actually ran. This is the same technique used to originally prove the vulnerability.
//
// A real browser (Playwright/Chromium) was not available to install in this environment (the
// network sandbox only allows a fixed package-registry allowlist, and Chromium's download host
// is not on it) — this was not silently skipped, see the note at the bottom of this file.
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

// Pull the ACTUAL esc()/sj() implementations out of index.html so the test exercises the real
// shipped code, not a hand-copied duplicate.
function extractConst(source, name) {
  const m = source.match(new RegExp(`^const ${name}\\s*=.*$`, "m"));
  if (!m) throw new Error(`const ${name} not found`);
  return m[0];
}
const escSrc = extractConst(html, "esc");
const sjSrc = extractConst(html, "sj");
const helpers = new Function(`${escSrc}\n${sjSrc}\nreturn {esc, sj};`)();
const { esc, sj } = helpers;

const XSS_PAYLOADS = [
  "x');window.__xss=true;//",
  "');window.__xss=true;//",
  "x');alert(document.domain);//",
  '"><img src=x onerror=window.__xss=true>',
  "</script><script>window.__xss=true;</script>",
  "<svg/onload=window.__xss=true>",
  "back\\slash'and\"quotes",
  "&#39;&quot;&amp;", // already-encoded entities — must not get double-decoded into live quotes
  "&#x27;double&#x27;encoded",
];

const LEGITIMATE_VALUES = [
  "O'Brien",
  'Say "hello"',
  "Fish & Chips",
  "Ünïcödé Nàme",
  "😀 emoji name 🎉",
  "રાહુલ પટેલ", // Gujarati
  "(parens) [brackets]",
  "back\\slash\\path",
  "Name, With Comma",
];

function buildHandlerHtml(fnName, valueExpr) {
  // Reproduces the FIXED real pattern from index.html: onclick="fn(${sj(value)})"
  return `<!DOCTYPE html><html><body>
<button id="btn" onclick="${fnName}(${valueExpr})"></button>
<script>window.__called = undefined; window.__xss = false; window.${fnName} = function(v){ window.__called = v; };</script>
</body></html>`;
}

test("sj(): every XSS payload is inert when embedded as an onclick JS-string argument (real DOM parse)", () => {
  for (const payload of XSS_PAYLOADS) {
    const dom = new JSDOM(buildHandlerHtml("probe", sj(payload)), { runScripts: "dangerously" });
    const { window } = dom;
    window.document.getElementById("btn").dispatchEvent(new window.Event("click"));
    assert.equal(window.__xss, false, `payload executed code: ${JSON.stringify(payload)}`);
    assert.equal(window.__called, payload, `payload was not passed through intact as data: ${JSON.stringify(payload)}`);
  }
});

test("sj(): legitimate values with quotes/unicode/emoji/Gujarati/parens/backslashes survive intact", () => {
  for (const value of LEGITIMATE_VALUES) {
    const dom = new JSDOM(buildHandlerHtml("probe", sj(value)), { runScripts: "dangerously" });
    const { window } = dom;
    window.document.getElementById("btn").dispatchEvent(new window.Event("click"));
    assert.equal(window.__called, value, `legitimate value corrupted: ${JSON.stringify(value)} -> ${JSON.stringify(window.__called)}`);
  }
});

test("sj(): two-argument call site (openWhatsApp-style) — payload in first arg cannot escape into the second", () => {
  for (const payload of XSS_PAYLOADS) {
    // Reproduces the FIXED real pattern: onclick="openWhatsApp(${sj(phone)}, 'Hi')"
    const htmlStr = `<!DOCTYPE html><html><body>
<button id="btn" onclick="probe(${sj(payload)}, 'Hi')"></button>
<script>window.__xss=false; window.__args=null; window.probe=function(a,b){ window.__args=[a,b]; };</script>
</body></html>`;
    const dom = new JSDOM(htmlStr, { runScripts: "dangerously" });
    const { window } = dom;
    window.document.getElementById("btn").dispatchEvent(new window.Event("click"));
    assert.equal(window.__xss, false, `payload executed via second-arg breakout: ${JSON.stringify(payload)}`);
    assert.deepEqual(Array.from(window.__args || []), [payload, "Hi"], `arguments corrupted for payload: ${JSON.stringify(payload)}`);
  }
});

test("esc(): every XSS payload is inert as plain HTML text content (client name/phone/email/notes display)", () => {
  for (const payload of XSS_PAYLOADS) {
    const dom = new JSDOM(`<!DOCTYPE html><html><body><div id="root"><h3>${esc(payload)}</h3></div></body></html>`);
    const root = dom.window.document.getElementById("root");
    assert.equal(root.querySelector("img, svg, script, iframe"), null, `payload created a live element: ${JSON.stringify(payload)}`);
    assert.equal(root.textContent, payload, `payload text was altered: ${JSON.stringify(payload)}`);
  }
});

test("esc(): every XSS payload is inert as a double-quoted HTML attribute value", () => {
  for (const payload of XSS_PAYLOADS) {
    const dom = new JSDOM(`<!DOCTYPE html><html><body><input id="i" value="${esc(payload)}"></body></html>`);
    const el = dom.window.document.getElementById("i");
    assert.equal(el.getAttribute("value"), payload, `attribute value corrupted for: ${JSON.stringify(payload)}`);
    // and confirm the attribute boundary itself was never broken (only one <input> exists)
    assert.equal(dom.window.document.querySelectorAll("input").length, 1);
  }
});

test("REGRESSION (would have failed before the fix): the original vulnerable esc()-in-onclick pattern is provably broken by these same payloads", () => {
  // This documents WHY sj() is required — esc() alone is not a JS-string-context encoder.
  // Specifically the quote-breakout-style payloads (not the HTML-attribute-breakout style like
  // the <img onerror> payload, which esc() already correctly neutralizes on its own — this test
  // isolates the JS-string-literal-breakout mechanism that esc() does NOT protect against).
  const quoteBreakoutPayloads = ["x');window.__xss=true;//", "');window.__xss=true;//"];
  for (const payload of quoteBreakoutPayloads) {
    const vulnerableHtml = `<!DOCTYPE html><html><body>
<button id="btn" onclick="probe('${esc(payload)}')"></button>
<script>window.__xss=false; window.probe=function(v){ window.__called=v; };</script>
</body></html>`;
    const dom = new JSDOM(vulnerableHtml, { runScripts: "dangerously" });
    const { window } = dom;
    window.document.getElementById("btn").dispatchEvent(new window.Event("click"));
    // We EXPECT this old pattern to have been exploitable — proving the fix was necessary.
    assert.equal(window.__xss, true, `expected the pre-fix esc()-in-onclick pattern to be exploitable for: ${JSON.stringify(payload)}`);
  }
});

// ---------------------------------------------------------------------------------------------
// NOTE ON BROWSER TESTING SCOPE
// ---------------------------------------------------------------------------------------------
// A real Chromium/Playwright browser was attempted but could not be installed: this sandbox's
// network egress is restricted to a fixed allowlist (npm/GitHub/PyPI registries) and does not
// include Playwright's browser-binary download host. jsdom was used instead because it
// implements the same WHATWG HTML parsing spec (including attribute entity-decoding before
// script execution) that these tests depend on — the exact mechanism of the vulnerability — and
// `runScripts: "dangerously"` genuinely executes the resulting inline handlers as a browser
// would, rather than just inspecting the parsed attribute string. This is a real execution-path
// test, not a static string check, but it is not the same as a full Chromium instance and that
// distinction is being reported honestly rather than claimed as equivalent.
