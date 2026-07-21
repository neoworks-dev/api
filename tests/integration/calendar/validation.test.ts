/**
 * Calendar validation: reads are gated by the auth middleware (401 without a
 * token), and a missing required create field is rejected at the schema boundary
 * with the GRAPHQL_VALIDATION_FAILED code.
 *
 *   cd apps/api/tests/integration && bun test calendar
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstErrorCode, signupAndGetToken, requireServers } from "../_helpers";

let token: string;

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("calendar auth + input rules", () => {
  test("listing events without a token → 401", async () => {
    const r = await gql(`{ events { id } }`);
    expect(r.status).toBe(401);
  });

  test("createCalendar missing required color → GRAPHQL_VALIDATION_FAILED", async () => {
    const r = await gql(`mutation { createCalendar(input: { name: "Personal" }) { id } }`, {
      token,
    });
    expect(firstErrorCode(r)).toBe("GRAPHQL_VALIDATION_FAILED");
  });
});
