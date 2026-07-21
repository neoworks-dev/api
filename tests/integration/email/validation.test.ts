/**
 * Email validation: sendEmail requires the email:write scope. Without it the
 * caller gets a public "forbidden" message, not the generic masked error.
 *
 *   cd apps/api/tests/integration && bun test email
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstError, signupAndGetToken, requireServers } from "../_helpers";

const MASKED = "Internal server error";

let token: string; // no email:write

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("sendEmail scope gate", () => {
  test("without email:write → public forbidden, not masked", async () => {
    const r = await gql(
      `mutation { sendEmail(input: { to: ["a@b.com"], subject: "s", text: "t" }) { delivered } }`,
      { token },
    );
    const msg = firstError(r);
    expect(msg).not.toBe(MASKED);
    expect(msg.toLowerCase()).toContain("forbidden");
    expect(msg).toContain("email:write");
  });
});
