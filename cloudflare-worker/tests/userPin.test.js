import test from "node:test";
import assert from "node:assert/strict";
import { authorizeSetUserPin } from "../lib/userPin.js";

test("a plain user can change their own PIN with currentPin", () => {
  const d = authorizeSetUserPin(
    { uid: "u1", role: "user" },
    { id: "u1", role: "user" },
    { targetUserId: "u1", newPin: "1234", currentPin: "0000" }
  );
  assert.equal(d.ok, true);
  assert.equal(d.op, "self");
});

test("self change without currentPin is rejected", () => {
  const d = authorizeSetUserPin({ uid: "u1", role: "user" }, { id: "u1", role: "user" }, { targetUserId: "u1", newPin: "1234" });
  assert.equal(d.ok, false);
});

test("a plain user cannot change someone else's PIN", () => {
  const d = authorizeSetUserPin(
    { uid: "u1", role: "user" },
    { id: "u2", role: "user" },
    { targetUserId: "u2", newPin: "1234" }
  );
  assert.equal(d.ok, false);
});

test("a plain user cannot create a new account", () => {
  const d = authorizeSetUserPin({ uid: "u1", role: "user" }, null, { targetUserId: "brandnew", newPin: "1234" });
  assert.equal(d.ok, false);
});

test("admin can create a user-role account", () => {
  const d = authorizeSetUserPin({ uid: "admin1", role: "admin" }, null, { targetUserId: "newu", newPin: "1234", role: "user" });
  assert.equal(d.ok, true);
  assert.equal(d.op, "create");
});

test("admin cannot grant the superadmin role", () => {
  const d = authorizeSetUserPin({ uid: "admin1", role: "admin" }, null, { targetUserId: "newu", newPin: "1234", role: "superadmin" });
  assert.equal(d.ok, false);
});

test("superadmin can grant the superadmin role", () => {
  const d = authorizeSetUserPin({ uid: "sa", role: "superadmin" }, null, { targetUserId: "newu", newPin: "1234", role: "superadmin" });
  assert.equal(d.ok, true);
});

test("admin cannot edit an existing superadmin account", () => {
  const d = authorizeSetUserPin(
    { uid: "admin1", role: "admin" },
    { id: "sa", role: "superadmin" },
    { targetUserId: "sa", newPin: "1234" }
  );
  assert.equal(d.ok, false);
});

test("admin cannot rename a username (superadmin-only)", () => {
  const d = authorizeSetUserPin(
    { uid: "admin1", role: "admin" },
    { id: "u2", role: "user" },
    { targetUserId: "u2", renameFrom: "u2old" }
  );
  assert.equal(d.ok, false);
});

test("superadmin CAN rename a username", () => {
  const d = authorizeSetUserPin(
    { uid: "sa", role: "superadmin" },
    { id: "u2", role: "user" },
    { targetUserId: "u2", renameFrom: "u2old" }
  );
  assert.equal(d.ok, true);
});

test("deleting yourself is always rejected", () => {
  const d = authorizeSetUserPin({ uid: "sa", role: "superadmin" }, { id: "sa", role: "superadmin" }, { targetUserId: "sa", delete: true });
  assert.equal(d.ok, false);
});

test("superadmin accounts can never be deleted, even by another superadmin", () => {
  const d = authorizeSetUserPin(
    { uid: "sa2", role: "superadmin" },
    { id: "sa1", role: "superadmin" },
    { targetUserId: "sa1", delete: true }
  );
  assert.equal(d.ok, false);
});

test("admin cannot delete another admin; superadmin can", () => {
  const asAdmin = authorizeSetUserPin(
    { uid: "admin1", role: "admin" },
    { id: "admin2", role: "admin" },
    { targetUserId: "admin2", delete: true }
  );
  assert.equal(asAdmin.ok, false);

  const asSuper = authorizeSetUserPin(
    { uid: "sa", role: "superadmin" },
    { id: "admin2", role: "admin" },
    { targetUserId: "admin2", delete: true }
  );
  assert.equal(asSuper.ok, true);
});

test("admin can delete a plain user", () => {
  const d = authorizeSetUserPin(
    { uid: "admin1", role: "admin" },
    { id: "u2", role: "user" },
    { targetUserId: "u2", delete: true }
  );
  assert.equal(d.ok, true);
  assert.equal(d.op, "delete");
});

test("a non-admin cannot escalate their own role via the update path (no such path exists for self)", () => {
  // Self path only ever produces op:"self", which carries no role field at all — role is never
  // read from the payload for self-changes, mirrored by handleSetUserPin only ever writing
  // {pinHash, role: entry.role} (the EXISTING role) on the self path.
  const d = authorizeSetUserPin(
    { uid: "u1", role: "user" },
    { id: "u1", role: "user" },
    { targetUserId: "u1", newPin: "1234", currentPin: "0000", role: "superadmin" }
  );
  assert.equal(d.op, "self"); // role field is simply ignored by the handler for this op
});
