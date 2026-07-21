/**
 * Memories validation: making a memory searchable requires source text to embed.
 * Attempting it on a memory without source text is a resolver-level rule
 * violation and must return a public message, not the masked generic error.
 *
 *   cd apps/api/tests/integration && bun test memories
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstError, signupAndGetToken, requireServers } from "../_helpers";

const MASKED = "Internal server error";

let token: string;

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("setMemorySearchable input rule", () => {
  test("indexing a memory with no source text → public rule violation, not masked", async () => {
    const created = await gql(
      `mutation { createMemory(input: { title: "no source", searchable: false }) { id } }`,
      { token },
    );
    expect(created.errors).toBeUndefined();
    const id = (created.data as { createMemory: { id: string } }).createMemory.id;

    const r = await gql(
      `mutation($id: ID!) { setMemorySearchable(id: $id, searchable: true) { id } }`,
      { token, variables: { id } },
    );
    const msg = firstError(r);
    expect(msg).not.toBe(MASKED);
    expect(msg).toContain("source text");
  });
});
