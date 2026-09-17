// ============================================================================================
// HARDENING CORRECTION #2 -- Consent API integrity, Layer 1.
//
// Pure-function tests for isKnownConsentCategory() against explicit synthetic lists (never
// touches the real exported KNOWN_CONSENT_CATEGORIES), plus one test proving what actually
// ships in production: the real list is empty, so with no list argument nothing is "known" and
// every grant is rejected. See privacy-consent-known-category.test.js for the full-HTTP-handler
// tests, which need to register a synthetic category to exercise grant/withdraw at all -- kept
// in a separate file so that mutation can never leak into this file's "production is empty"
// assertion (module-level test registration in Node's test runner happens before any test body
// runs, so a same-file push() would corrupt this check regardless of where it's written).
// ============================================================================================
import test from "node:test";
import assert from "node:assert/strict";
import { isKnownConsentCategory, KNOWN_CONSENT_CATEGORIES } from "../lib/privacy.js";

const SYNTHETIC_LIST = [
  { type: "marketing_email", purpose: "promotional newsletter" },
  { type: "product_analytics", purpose: "usage analytics" },
];

test("valid known consent (exact type+purpose match) is accepted", () => {
  assert.equal(isKnownConsentCategory("marketing_email", "promotional newsletter", SYNTHETIC_LIST), true);
});

test("unknown consent type is rejected", () => {
  assert.equal(isKnownConsentCategory("sms_marketing", "promotional newsletter", SYNTHETIC_LIST), false);
});

test("known type with unknown/mismatched purpose is rejected (type alone is not enough)", () => {
  assert.equal(isKnownConsentCategory("marketing_email", "reselling your data to advertisers", SYNTHETIC_LIST), false);
});

test("known purpose with unknown/mismatched type is rejected (purpose alone is not enough)", () => {
  assert.equal(isKnownConsentCategory("some_other_type", "usage analytics", SYNTHETIC_LIST), false);
});

test("a forged/arbitrary category invented by the caller is rejected", () => {
  assert.equal(isKnownConsentCategory("literally_anything", "i made this up", SYNTHETIC_LIST), false);
});

test("'essential' is never a grantable consent category, even against a non-empty list that doesn't name it", () => {
  // essential/account-functionality processing is mandatory, not consent-based (see
  // index.html's privacyConsentHtml() -- it's rendered as an always-on, non-togglable item).
  // It must not become grantable just because a caller tries to name it as a consent type.
  assert.equal(isKnownConsentCategory("essential", "account functionality", SYNTHETIC_LIST), false);
});

test("PRODUCTION DEFAULT: KNOWN_CONSENT_CATEGORIES ships empty, so every category is rejected by default", () => {
  assert.equal(KNOWN_CONSENT_CATEGORIES.length, 0, "this application has no real optional processing today -- see lib/privacy.js's module comment for why the allow-list must stay empty until one genuinely exists");
  assert.equal(isKnownConsentCategory("anything", "anything"), false, "with no list argument, the real (empty) production list is used -- nothing is known");
  assert.equal(isKnownConsentCategory("marketing", "newsletter"), false);
});
