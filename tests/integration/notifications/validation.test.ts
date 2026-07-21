/**
 * Notifications validation: sending requires the notification:write scope. A
 * token without it must get a public "forbidden" message — never the generic
 * "Internal server error" (which is what a non-public resolver error scrubs to).
 *
 *   cd apps/api/tests/integration && bun test notifications
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { gql, firstError, signupAndGetToken, requireServers } from "../_helpers";

const MASKED = "Internal server error";

let token: string; // openid/profile/email — no notification:write

beforeAll(async () => {
  await requireServers();
  token = await signupAndGetToken(["openid", "profile", "email"]);
});

describe("sendNotification scope gate", () => {
  test("without notification:write → public forbidden, not masked", async () => {
    const r = await gql(
      `mutation { sendNotification(input: { title: "hi", body: "x" }) { id } }`,
      { token },
    );
    const msg = firstError(r);
    expect(msg).not.toBe(MASKED);
    expect(msg.toLowerCase()).toContain("forbidden");
    expect(msg).toContain("notification:write");
  });
});
