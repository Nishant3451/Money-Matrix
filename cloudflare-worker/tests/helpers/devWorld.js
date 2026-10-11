// Test harness for the Developer / Superadmin hierarchy, scope policy and assignment tests.
// Builds on the record-ACL harness (real Worker + versioned fake Firestore + real Firebase-style ID tokens) and adds the two
// things the account-management / bootstrap / login paths need: a fake `moneymatrix/credentials` document and a fake Identity
// Toolkit (so claim writes and session revocations are observable). Lives in helpers/ so node --test does not run it.
import bcrypt from "bcryptjs";
import { decodeFirestoreFields, encodeFirestoreFields } from "../../lib/googleFirestore.js";
import { worker, ORIGIN, makeDoc, makeWorld, call, clone } from "./aclWorld.js";
export * from "./aclWorld.js";

//   top (admin) ── mid (admin) ── low (user)         dev  = developer      (no hierarchy node)
//   └─ peer (user)                                   root = superadmin     (no hierarchy node)
//   other (user, unrelated tree)                     sa2  = a second superadmin
export const DEV_SUPS = [
  { id: "n_top", supervisorId: null }, { id: "n_mid", supervisorId: "n_top" },
  { id: "n_low", supervisorId: "n_mid" }, { id: "n_peer", supervisorId: "n_top" },
  { id: "n_other", supervisorId: null },
];
export const DEV_USERS = [
  { id: "dev", username: "dev", role: "developer", linkedId: null },
  { id: "root", username: "root", role: "superadmin", linkedId: null },
  { id: "sa2", username: "sa2", role: "superadmin", linkedId: null },
  { id: "top", username: "top", role: "admin", linkedId: "n_top" },
  { id: "mid", username: "mid", role: "admin", linkedId: "n_mid" },
  { id: "low", username: "low", role: "user", linkedId: "n_low" },
  { id: "peer", username: "peer", role: "user", linkedId: "n_peer" },
  { id: "other", username: "other", role: "user", linkedId: "n_other" },
];
export const DEV_PERMS = { user: { marathon: "write", quotations: "write" } };

export const devDoc = (o = {}) => makeDoc({ users: DEV_USERS, sups: DEV_SUPS, permissions: DEV_PERMS, ...o });

/** makeWorld + fake credentials doc + fake Identity Toolkit. world.creds / world.identity are inspectable. */
export function makeDevWorld(initial, { credentials, env = {} } = {}) {
  const world = makeWorld(initial);
  world.creds = clone(credentials ?? {});
  world.identity = []; // { path, body }
  Object.assign(world.env, env);
  const baseInstall = world.install;
  world.install = () => {
    baseInstall();
    const inner = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const u = typeof url === "string" ? url : url.url;
      const method = init?.method || "GET";
      if (u.includes("/documents/moneymatrix/credentials")) {
        if (method === "GET") return new Response(JSON.stringify({ fields: encodeFirestoreFields(world.creds), updateTime: "c0" }), { status: 200 });
        if (method === "PATCH") {
          const fields = decodeFirestoreFields(JSON.parse(init.body).fields || {});
          const mask = new URL(u).searchParams.getAll("updateMask.fieldPaths").map((decoded) =>
            decoded.startsWith("`") && decoded.endsWith("`")
              ? decoded.slice(1, -1).replace(/\\`/g, "`").replace(/\\\\/g, "\\")
              : decoded
          );
          for (const k of mask) { if (Object.prototype.hasOwnProperty.call(fields, k)) world.creds[k] = fields[k]; else delete world.creds[k]; }
          return new Response("{}", { status: 200 });
        }
      }
      if (u.startsWith("https://identitytoolkit.googleapis.com/")) {
        world.identity.push({ path: u.split("/accounts")[1] ? `/accounts${u.split("/accounts")[1]}` : u, body: init?.body ? JSON.parse(init.body) : null });
        return new Response("{}", { status: 200 });
      }
      return inner(url, init);
    };
  };
  world.install();
  return world;
}

/** A request with NO bearer token (login, bootstrap). */
export async function callPublic(world, path, body, headers = {}) {
  world.install();
  const req = new Request(`https://worker.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "CF-Connecting-IP": "203.0.113.9", ...headers },
    body: JSON.stringify(body ?? {}),
  });
  const res = await worker.fetch(req, world.env, {});
  let json = null;
  try { json = await res.json(); } catch { /* empty */ }
  return { status: res.status, json };
}

/** A fresh bcrypt credentials entry for tests (cost 4: fast). */
export const credFor = (pin, role) => ({ pinHash: bcrypt.hashSync(pin, 4), role });

/** A signed-in client's view of /data/get (parsed) with an explicit scope request (or the server default). */
export async function getViewRaw(world, uid, scope, opts = {}) {
  return call(world, uid, "/data/get", scope === undefined ? {} : { scope }, opts);
}
