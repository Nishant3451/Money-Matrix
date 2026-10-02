// Role freshness: the Worker authorizes on the verified token's `role` claim, which can be OLDER than the user's
// stored role (a role-only edit in User Management changes appData.users[].role through /data/save and touches
// neither the credentials doc, the persisted Firebase claim nor any session). effectiveRole() makes the stored
// record win when — and only when — it carries LESS privilege than the token.
import test from "node:test";
import assert from "node:assert/strict";
import { effectiveRole, isFullAccessRole } from "../lib/authorization.js";

test("effectiveRole: a stored role with less privilege than the token wins (demotion is immediate)", () => {
  assert.equal(effectiveRole("admin", { role: "user" }), "user");
  assert.equal(effectiveRole("admin", { role: "supervisor" }), "supervisor");
  assert.equal(effectiveRole("superadmin", { role: "admin" }), "admin");
  assert.equal(effectiveRole("superadmin", { role: "user" }), "user");
});
test("effectiveRole: never RAISES privilege above the token (promotion needs a fresh login, as before)", () => {
  assert.equal(effectiveRole("user", { role: "admin" }), "user");
  assert.equal(effectiveRole("user", { role: "superadmin" }), "user");
  assert.equal(effectiveRole("admin", { role: "superadmin" }), "admin");
  assert.equal(effectiveRole("supervisor", { role: "admin" }), "supervisor");
});
test("effectiveRole: equal or same-rank roles keep the token role", () => {
  for (const r of ["superadmin", "admin", "user", "supervisor"]) assert.equal(effectiveRole(r, { role: r }), r);
  assert.equal(effectiveRole("user", { role: "supervisor" }), "user");
  assert.equal(effectiveRole("supervisor", { role: "user" }), "supervisor");
});
test("effectiveRole: no usable stored record => unchanged behaviour (token role)", () => {
  for (const stored of [null, undefined, {}, { role: "" }, { role: null }, { role: 5 }, { role: {} }, "admin", []]) {
    assert.equal(effectiveRole("admin", stored), "admin", JSON.stringify(stored));
  }
});
test("effectiveRole: hostile role strings cannot be abused (prototype keys rank as ordinary roles)", () => {
  for (const evil of ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"]) {
    assert.equal(effectiveRole("admin", { role: evil }), evil, "demotes to the odd role, which is NOT full access");
    assert.equal(isFullAccessRole(effectiveRole("admin", { role: evil })), false);
    assert.equal(effectiveRole(evil, { role: "admin" }), evil, "an odd token role is never promoted");
  }
});
test("effectiveRole: a demoted caller is no longer full-access", () => {
  assert.equal(isFullAccessRole(effectiveRole("admin", { role: "user" })), false);
  assert.equal(isFullAccessRole(effectiveRole("superadmin", { role: "admin" })), true, "still admin-level");
});
