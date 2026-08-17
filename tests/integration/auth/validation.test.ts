/**
 * Cross-cutting authentication. Every /graphql call is gated by the Bearer-JWT
 * middleware, which rejects at the HTTP layer (401) before a resolver runs —
 * so a missing or invalid token never reaches GraphQL as a field error.
 * Subject-specific scope + input rules live under their own directories.
 *
 *   cd apps/api/tests/integration && bun test auth
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, signupAndGetToken, requireServers } from "../_helpers";

let token: string;

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("authentication", () => {
  test("no Authorization header → 401, no data", async () => {
    const r = await gql(`{ contactCount }`);
    expect(r.status).toBe(401);
    expect(r.data).toBeNull();
  });

  test("garbage bearer token → 401", async () => {
    const r = await gql(`{ contactCount }`, { token: "not-a-real-jwt" });
    expect(r.status).toBe(401);
  });

  test("a valid token authenticates (positive control) → 200, no errors", async () => {
    // A query the server can still answer: contacts, calendar and memories are
    // encrypted envelopes now and have no GraphQL surface at all.
    const r = await gql(`{ myNotifications { id } }`, { token });
    expect(r.status).toBe(200);
    expect(r.errors).toBeUndefined();
    expect(Array.isArray((r.data as { myNotifications: unknown[] }).myNotifications)).toBe(true);
  });
});
