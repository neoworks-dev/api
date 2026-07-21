/**
 * Shared e2e helpers: PKCE OAuth signup against the running oauth server and a
 * thin GraphQL fetcher against the running api server. Used by the validation
 * suite; kept out of *.test.ts so bun does not run it as a test file.
 *
 * Requires both servers up:
 *   go run ./cmd/oauth   (apps/oauth, default :8080)
 *   go run ./cmd/api     (apps/api,  default :8081)
 */

export const API_BASE = process.env.SERVER_URL ?? "http://localhost:8081";
export const OAUTH_BASE = process.env.OAUTH_SERVER_URL ?? "http://localhost:8080";

// neoworks.dev is a public, auto-granting client that is allowed openid/profile/
// email plus storage:read + tokens:read — enough to mint both an unscoped token
// and a storage:read-scoped one.
const CLIENT_ID = "neoworks.dev";
const REDIRECT_URI = "http://neoworks.localhost/auth/callback";

function randomBase64url(bytes = 32): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Creates a fresh user via the signup form and returns an access token carrying
 * exactly `scopes`. The client auto-grants, so no manual consent step is needed.
 * The AMK-wrapper fields are stored opaquely by the server, so random blobs work.
 */
export async function signupAndGetToken(
  scopes: string[] = ["openid", "profile", "email"],
): Promise<string> {
  const email = `validation-${Date.now()}-${Math.floor(Math.random() * 1e6)}@test.example.com`;
  const verifier = randomBase64url(32);
  const challenge = await pkceChallenge(verifier);

  const authorizeURL = new URL(`${OAUTH_BASE}/oauth/authorize`);
  authorizeURL.searchParams.set("client_id", CLIENT_ID);
  authorizeURL.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeURL.searchParams.set("response_type", "code");
  authorizeURL.searchParams.set("scope", scopes.join(" "));
  authorizeURL.searchParams.set("state", "test");
  authorizeURL.searchParams.set("code_challenge", challenge);
  authorizeURL.searchParams.set("code_challenge_method", "S256");

  const authResp = await fetch(authorizeURL.toString(), { redirect: "manual" });
  if (authResp.status !== 302) throw new Error(`authorize: expected 302, got ${authResp.status}`);
  const loginChallenge = new URL(authResp.headers.get("location")!).searchParams.get("login_challenge");
  if (!loginChallenge) throw new Error("no login_challenge in redirect");

  // Signup is gated on a verified email. In debug builds send-code echoes the
  // code back, so we can complete verification without a real inbox.
  const sendResp = await fetch(`${OAUTH_BASE}/auth/signup/send-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const sent = (await sendResp.json()) as { code?: string };
  if (!sent.code)
    throw new Error("send-code did not echo a code — is the oauth server running with DEBUG=true?");
  const verifyResp = await fetch(`${OAUTH_BASE}/auth/signup/verify-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code: sent.code }),
  });
  if (!verifyResp.ok) throw new Error(`verify-code failed: ${await verifyResp.text()}`);

  const signupResp = await fetch(`${OAUTH_BASE}/auth/signup`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      first_name: "Test",
      last_name: "User",
      email,
      password: "test-password-123",
      login_challenge: loginChallenge,
      password_wrapped_amk: randomBase64url(48),
      recovery_wrapped_amk: randomBase64url(48),
      argon2_salt: randomBase64url(16),
      argon2_time: "2",
      argon2_memory: "67108864",
      argon2_threads: "1",
      argon2_keylen: "32",
      device_public_key: randomBase64url(32),
      device_wrapped_amk: randomBase64url(48),
    }),
  });
  if (signupResp.status !== 302)
    throw new Error(`signup: expected 302, got ${signupResp.status}: ${await signupResp.text()}`);
  const code = new URL(signupResp.headers.get("location")!).searchParams.get("code");
  if (!code) throw new Error("no code in signup callback");

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
  if (!tokenResp.ok) throw new Error(`token exchange failed: ${await tokenResp.text()}`);
  const tokens = await tokenResp.json();
  if (!tokens.access_token) throw new Error("no access_token in token response");
  return tokens.access_token as string;
}

export interface GqlResult {
  status: number;
  data: unknown;
  errors: Array<{ message: string; path?: string[]; extensions?: { code?: string } }> | undefined;
}

/** POST a GraphQL operation to /graphql. `token` omitted → unauthenticated call. */
export async function gql(
  query: string,
  opts: { token?: string; variables?: Record<string, unknown> } = {},
): Promise<GqlResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const res = await fetch(`${API_BASE}/graphql`, {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables: opts.variables ?? {} }),
  });
  const json = (await res.json()) as { data?: unknown; errors?: GqlResult["errors"] };
  return { status: res.status, data: json.data ?? null, errors: json.errors };
}

/** First error message, or "" when the response carried no errors. */
export function firstError(r: GqlResult): string {
  return r.errors?.[0]?.message ?? "";
}

/** First error's extensions.code (e.g. GRAPHQL_VALIDATION_FAILED), or "". */
export function firstErrorCode(r: GqlResult): string {
  return r.errors?.[0]?.extensions?.code ?? "";
}

/** Exits the process with a hint when a required server is not reachable. */
export async function requireServers(): Promise<void> {
  try {
    await fetch(`${OAUTH_BASE}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(2000) });
  } catch {
    console.error(`\nOAuth server not reachable at ${OAUTH_BASE} — start it: go run ./cmd/oauth\n`);
    process.exit(1);
  }
  try {
    await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(2000) });
  } catch {
    console.error(`\nAPI server not reachable at ${API_BASE} — start it: go run ./cmd/api\n`);
    process.exit(1);
  }
}
