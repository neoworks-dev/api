/**
 * Integration tests for the key management endpoints.
 * Requires both servers to be running: go run ./cmd/api (apps/api) and
 * go run ./cmd/oauth (apps/oauth) — the oauth flow used to obtain a token
 * lives in apps/oauth, while the Bearer-authenticated /api/v1/keys/* routes
 * are exercised on apps/api. Both share the same JWT signing key.
 *
 * Usage:
 *   cd tests/integration
 *   bun test
 *
 * Override server URLs:
 *   SERVER_URL=http://localhost:9091 OAUTH_SERVER_URL=http://localhost:9090 bun test
 */

import { describe, test, expect, beforeAll } from "bun:test";

const BASE = process.env.SERVER_URL ?? "http://localhost:8081";
const OAUTH_BASE = process.env.OAUTH_SERVER_URL ?? "http://localhost:8080";
const CLIENT_ID = "neoworks.dev";
const REDIRECT_URI = "http://neoworks.localhost/auth/callback";

// ── PKCE helpers ──────────────────────────────────────────────────────────────

function randomBase64url(bytes = 32): string {
  return btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))),
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// ── OAuth PKCE signup → access token ─────────────────────────────────────────

async function signupAndGetToken(
  email: string,
  password: string,
): Promise<{
  accessToken: string;
  signupDevicePublicKey: string;
  signupDeviceWrappedAMK: string;
}> {
  const verifier = randomBase64url(32);
  const challenge = await pkceChallenge(verifier);

  // 1. Kick off the authorize flow to get a login_challenge
  const authorizeURL = new URL(`${OAUTH_BASE}/oauth/authorize`);
  authorizeURL.searchParams.set("client_id", CLIENT_ID);
  authorizeURL.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeURL.searchParams.set("response_type", "code");
  authorizeURL.searchParams.set("scope", "openid profile email");
  authorizeURL.searchParams.set("state", "test");
  authorizeURL.searchParams.set("code_challenge", challenge);
  authorizeURL.searchParams.set("code_challenge_method", "S256");

  const authResp = await fetch(authorizeURL.toString(), { redirect: "manual" });
  if (authResp.status !== 302)
    throw new Error(`authorize: expected 302, got ${authResp.status}`);

  const loginURL = new URL(authResp.headers.get("location")!);
  const loginChallenge = loginURL.searchParams.get("login_challenge");
  if (!loginChallenge) throw new Error("no login_challenge in redirect");

  // 2. Submit signup form — server creates user, user_key, and device
  // records and redirects with code. The AMK wrapper fields are normally
  // generated client-side (see signup.html); the server stores them
  // opaquely, so random blobs are sufficient here.
  const signupDevicePublicKey = randomBase64url(32);
  const signupDeviceWrappedAMK = randomBase64url(48);
  const signupResp = await fetch(`${OAUTH_BASE}/auth/signup`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      first_name: "Test",
      last_name: "User",
      email,
      password,
      login_challenge: loginChallenge,
      password_wrapped_amk: randomBase64url(48),
      recovery_wrapped_amk: randomBase64url(48),
      argon2_salt: randomBase64url(16),
      argon2_time: "2",
      argon2_memory: "67108864",
      argon2_threads: "1",
      argon2_keylen: "32",
      device_public_key: signupDevicePublicKey,
      device_wrapped_amk: signupDeviceWrappedAMK,
    }),
  });
  if (signupResp.status !== 302) {
    throw new Error(
      `signup: expected 302, got ${signupResp.status}: ${await signupResp.text()}`,
    );
  }

  const callbackURL = new URL(signupResp.headers.get("location")!);
  const code = callbackURL.searchParams.get("code");
  if (!code) throw new Error(`no code in callback: ${callbackURL}`);

  // 3. Exchange code for tokens
  const tokenResp = await fetch(`${OAUTH_BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
    }),
  });
  if (!tokenResp.ok)
    throw new Error(`token exchange failed: ${await tokenResp.text()}`);

  const tokens = await tokenResp.json();
  if (!tokens.access_token) throw new Error("no access_token in response");
  return {
    accessToken: tokens.access_token,
    signupDevicePublicKey,
    signupDeviceWrappedAMK,
  };
}

// ── Test state ────────────────────────────────────────────────────────────────

let token: string;
let email: string;
let signupDevicePublicKey: string;
let signupDeviceWrappedAMK: string;

// Fake key material — server stores blobs opaquely, no real crypto needed here
const amk = randomBase64url(32);
const recoveryWrappedAMK = randomBase64url(48); // ciphertext is longer than plaintext
const passwordWrappedAMK = randomBase64url(48);
const argon2Salt = randomBase64url(16);
const devicePublicKey = randomBase64url(32);
const deviceWrappedAMK = randomBase64url(48);

function authHeaders() {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(async () => {
  // Bail out early if either server is not running
  try {
    await fetch(`${OAUTH_BASE}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(2000),
    });
  } catch {
    console.error(
      `\nOAuth server not reachable at ${OAUTH_BASE} — start it with: go run ./cmd/oauth\n`,
    );
    process.exit(1);
  }

  try {
    await fetch(`${BASE}/api/v1/auth/key-challenge?email=ping@test.example.com`, {
      signal: AbortSignal.timeout(2000),
    });
  } catch {
    console.error(
      `\nAPI server not reachable at ${BASE} — start it with: go run ./cmd/api\n`,
    );
    process.exit(1);
  }

  email = `keys-${Date.now()}@test.example.com`;
  const signup = await signupAndGetToken(email, "test-password-123");
  token = signup.accessToken;
  signupDevicePublicKey = signup.signupDevicePublicKey;
  signupDeviceWrappedAMK = signup.signupDeviceWrappedAMK;
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("key challenge (public)", () => {
  test("missing email → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/auth/key-challenge`);
    expect(r.status).toBe(400);
  });

  test("unknown email → 404", async () => {
    const r = await fetch(
      `${BASE}/api/v1/auth/key-challenge?email=nobody@example.com`,
    );
    expect(r.status).toBe(404);
  });

  test("known email with no password key → 404 (no password_wrapped_amk enrolled yet)", async () => {
    // Key material not yet registered, so 404 expected
    const r = await fetch(
      `${BASE}/api/v1/auth/key-challenge?email=${encodeURIComponent(email)}`,
    );
    expect(r.status).toBe(404);
  });
});

describe("register key material", () => {
  test("no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(401);
  });

  test("missing required fields → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ recovery_wrapped_amk: recoveryWrappedAMK }),
    });
    expect(r.status).toBe(400);
  });

  test("valid payload → 204", async () => {
    const r = await fetch(`${BASE}/api/v1/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        recovery_wrapped_amk: recoveryWrappedAMK,
        password_wrapped_amk: passwordWrappedAMK,
        argon2_salt: argon2Salt,
        argon2_time: 3,
        argon2_memory: 65536,
        argon2_threads: 4,
        argon2_keylen: 32,
        device_public_key: devicePublicKey,
        device_wrapped_amk: deviceWrappedAMK,
        device_name: "test-device",
      }),
    });
    expect(r.status).toBe(204);
  });
});

describe("key challenge after enrollment", () => {
  test("known email with password key → kdf params + ciphertext", async () => {
    const r = await fetch(
      `${BASE}/api/v1/auth/key-challenge?email=${encodeURIComponent(email)}`,
    );
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.password_wrapped_amk).toBe(passwordWrappedAMK);
    expect(body.argon2_salt).toBe(argon2Salt);
    expect(body.argon2_time).toBe(3);
    expect(body.argon2_memory).toBe(65536);
    expect(body.argon2_threads).toBe(4);
    expect(body.argon2_keylen).toBe(32);
  });
});

describe("device management", () => {
  test("list devices → includes the device registered with key material", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/devices`, {
      headers: authHeaders(),
    });
    expect(r.status).toBe(200);
    const devices = await r.json();
    expect(Array.isArray(devices)).toBe(true);
    expect(devices.length).toBeGreaterThanOrEqual(1);
    expect(devices[0].public_key).toBe(devicePublicKey);
  });

  test("register second device → 200 with device record", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/devices`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        public_key: randomBase64url(32),
        wrapped_amk: randomBase64url(48),
        name: "second-device",
      }),
    });
    expect(r.status).toBe(200);
    const d = await r.json();
    expect(d.public_key).toBeTruthy();
  });

  test("missing fields → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/devices`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "incomplete" }),
    });
    expect(r.status).toBe(400);
  });
});

describe("get my device", () => {
  test("no auth → 401", async () => {
    const r = await fetch(
      `${BASE}/api/v1/keys/devices/me?public_key=${encodeURIComponent(devicePublicKey)}`,
    );
    expect(r.status).toBe(401);
  });

  test("missing public_key → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/devices/me`, {
      headers: authHeaders(),
    });
    expect(r.status).toBe(400);
  });

  test("unknown public_key → 404", async () => {
    const r = await fetch(
      `${BASE}/api/v1/keys/devices/me?public_key=${encodeURIComponent(randomBase64url(32))}`,
      { headers: authHeaders() },
    );
    expect(r.status).toBe(404);
  });

  test("registered device → 200 with wrapped_amk", async () => {
    const r = await fetch(
      `${BASE}/api/v1/keys/devices/me?public_key=${encodeURIComponent(signupDevicePublicKey)}`,
      { headers: authHeaders() },
    );
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.wrapped_amk).toBe(signupDeviceWrappedAMK);
  });
});

describe("recovery", () => {
  test("get recovery → returns recovery_wrapped_amk", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/recovery`, {
      headers: authHeaders(),
    });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.recovery_wrapped_amk).toBe(recoveryWrappedAMK);
  });

  test("rotate recovery → 204, then get returns new blob", async () => {
    const newBlob = randomBase64url(48);
    const put = await fetch(`${BASE}/api/v1/keys/recovery`, {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ recovery_wrapped_amk: newBlob }),
    });
    expect(put.status).toBe(204);

    const get = await fetch(`${BASE}/api/v1/keys/recovery`, {
      headers: authHeaders(),
    });
    expect((await get.json()).recovery_wrapped_amk).toBe(newBlob);
  });

  test("rotate with missing field → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/recovery`, {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(400);
  });
});

describe("device invite (QR code flow)", () => {
  let inviteToken: string;
  const newDevicePublicKey = randomBase64url(32);
  const newDeviceWrappedAMK = randomBase64url(48);

  test("new device creates invite with its public key → gets token", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/device-invite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_public_key: newDevicePublicKey }),
    });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(typeof body.token).toBe("string");
    inviteToken = body.token;
  });

  test("poll before approval → 202", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/device-invite/${inviteToken}`);
    expect(r.status).toBe(202);
  });

  test("unknown token → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/device-invite/not-a-real-token`);
    expect(r.status).toBe(404);
  });

  test("trusted device approves invite → 204", async () => {
    const r = await fetch(
      `${BASE}/api/v1/keys/device-invite/${inviteToken}/approve`,
      {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          wrapped_amk: newDeviceWrappedAMK,
          device_name: "new-phone",
        }),
      },
    );
    expect(r.status).toBe(204);
  });

  test("poll after approval → 200 with wrapped_amk", async () => {
    const r = await fetch(`${BASE}/api/v1/keys/device-invite/${inviteToken}`);
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.wrapped_amk).toBe(newDeviceWrappedAMK);
  });

  test("approve without auth → 401", async () => {
    const token2 = (
      await fetch(`${BASE}/api/v1/keys/device-invite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_public_key: randomBase64url(32) }),
      }).then((r) => r.json())
    ).token;

    const r = await fetch(
      `${BASE}/api/v1/keys/device-invite/${token2}/approve`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ wrapped_amk: randomBase64url(48) }),
      },
    );
    expect(r.status).toBe(401);
  });
});
