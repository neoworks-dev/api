/**
 * Contacts validation. A missing required input field is rejected at the schema
 * boundary before the resolver runs: the response carries the
 * GRAPHQL_VALIDATION_FAILED extension code (the message itself is scrubbed by the
 * error presenter, so assert on the code, not the text). A well-formed input
 * round-trips.
 *
 *   cd apps/api/tests/integration && bun test contacts
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstErrorCode, signupAndGetToken, requireServers } from "../_helpers";

let token: string;

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("createContact input rule", () => {
  test("missing required formatted_name → GRAPHQL_VALIDATION_FAILED", async () => {
    const r = await gql(`mutation { createContact(input: { kind: "individual" }) { id } }`, {
      token,
    });
    expect(firstErrorCode(r)).toBe("GRAPHQL_VALIDATION_FAILED");
  });

  test("valid minimal contact → created", async () => {
    const r = await gql(
      `mutation { createContact(input: { formatted_name: "Ada Lovelace" }) { id formatted_name } }`,
      { token },
    );
    expect(r.errors).toBeUndefined();
    const c = (r.data as { createContact: { id: string; formatted_name: string } }).createContact;
    expect(c.id).toBeTruthy();
    expect(c.formatted_name).toBe("Ada Lovelace");
  });
});
