/**
 * Storage validation: storageUsage is gated on the storage:read scope. This
 * suite proves the *gate*: a token without the scope is refused with a public
 * "forbidden" message; a token that carries it passes the gate (its request is
 * no longer rejected as forbidden). Whether the downstream resolver then
 * succeeds is a separate concern — see storage/README notes.
 *
 *   cd apps/api/tests/integration && bun test storage
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstError, signupAndGetToken, requireServers } from "../_helpers";

const MASKED = "Internal server error";
const FORBIDDEN = "forbidden: requires storage:read scope";

let token: string; // no storage:read
let storageToken: string; // carries storage:read

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
  storageToken = await signupAndGetToken(["openid", "profile", "email", "storage:read"]);
});

describe("storageUsage scope gate", () => {
  test("without storage:read → public forbidden, not masked", async () => {
    const r = await gql(`{ storageUsage { totalBytes } }`, { token });
    expect(firstError(r)).toBe(FORBIDDEN);
    expect(firstError(r)).not.toBe(MASKED);
  });

  test("with storage:read → passes the scope gate (not forbidden)", async () => {
    const r = await gql(`{ storageUsage { totalBytes } }`, { token: storageToken });
    // The scope check no longer rejects the request; the granted token is
    // distinguished from the ungranted one above.
    expect(firstError(r)).not.toBe(FORBIDDEN);
  });
});
