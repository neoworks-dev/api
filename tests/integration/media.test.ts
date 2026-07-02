/**
 * Integration tests for the media upload endpoints.
 * Requires the server + MinIO to be running: go run main.go
 *
 * Usage:
 *   cd tests/integration
 *   bun test media.test.ts
 */

import { describe, test, expect, beforeAll } from "bun:test";

const BASE = process.env.SERVER_URL ?? "http://localhost:8080";
const CLIENT_ID = "neoworks.dev";
const REDIRECT_URI = "http://localhost:5173/auth/callback";

// ── Auth helpers (mirrors keys.test.ts) ───────────────────────────────────────

function randomBase64url(bytes = 32): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function signupAndGetToken(email: string, password: string): Promise<string> {
  const verifier = randomBase64url(32);
  const challenge = await pkceChallenge(verifier);

  const authorizeURL = new URL(`${BASE}/oauth/authorize`);
  authorizeURL.searchParams.set("client_id", CLIENT_ID);
  authorizeURL.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeURL.searchParams.set("response_type", "code");
  authorizeURL.searchParams.set("scope", "openid profile email");
  authorizeURL.searchParams.set("state", "test");
  authorizeURL.searchParams.set("code_challenge", challenge);
  authorizeURL.searchParams.set("code_challenge_method", "S256");

  const authResp = await fetch(authorizeURL.toString(), { redirect: "manual" });
  if (authResp.status !== 302) throw new Error(`authorize: ${authResp.status}`);

  const loginURL = new URL(authResp.headers.get("location")!);
  const loginChallenge = loginURL.searchParams.get("login_challenge")!;

  const signupResp = await fetch(`${BASE}/auth/signup`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ first_name: "Test", last_name: "User", email, password, login_challenge: loginChallenge }),
  });
  if (signupResp.status !== 302) throw new Error(`signup: ${signupResp.status}: ${await signupResp.text()}`);

  const code = new URL(signupResp.headers.get("location")!).searchParams.get("code")!;

  const tokenResp = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier }),
  });
  const tokens = await tokenResp.json();
  if (!tokens.access_token) throw new Error("no access_token");
  return tokens.access_token;
}

// ── Chunk helpers ─────────────────────────────────────────────────────────────

async function sha256hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Simulates an AMK-encrypted chunk: just random bytes for test purposes. */
function randomChunk(size = 4096): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

type Chunk = { data: Uint8Array; hash: string; size: number };

async function makeChunk(size = 4096): Promise<Chunk> {
  const data = randomChunk(size);
  const hash = await sha256hex(data);
  return { data, hash, size };
}

/** Extracts just the ID string from a SurrealDB RecordID regardless of wire format. */
function recordId(v: any): string {
  if (typeof v === "string") {
    const i = v.indexOf(":");
    return i >= 0 ? v.slice(i + 1) : v;
  }
  if (v && typeof v === "object") {
    // { Table: "...", ID: "..." } or { tb: "...", id: "..." } form
    return String(v.ID ?? v.id ?? v.Id ?? v);
  }
  return String(v);
}

function auth(token: string) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

// ── Full upload flow helper ───────────────────────────────────────────────────

async function upload(token: string, chunks: Chunk[], filename = "file.bin", mimeType = "application/octet-stream"): Promise<any> {
  // 1. Check
  const checkResp = await fetch(`${BASE}/api/v1/media/check`, {
    method: "POST",
    headers: auth(token),
    body: JSON.stringify({ chunks: chunks.map((c) => ({ hash: c.hash, size: c.size })) }),
  });
  expect(checkResp.status).toBe(200);
  const { missing_chunks } = await checkResp.json();

  // 2. Upload only missing chunks
  for (const hash of missing_chunks) {
    const chunk = chunks.find((c) => c.hash === hash)!;
    const putResp = await fetch(`${BASE}/api/v1/media/chunks/${hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });
    expect([200, 201]).toContain(putResp.status);
  }

  // 3. Finalize
  const finalizeResp = await fetch(`${BASE}/api/v1/media`, {
    method: "POST",
    headers: auth(token),
    body: JSON.stringify({ filename, mime_type: mimeType, chunks: chunks.map((c) => ({ hash: c.hash, size: c.size })) }),
  });
  expect(finalizeResp.status).toBe(201);
  return finalizeResp.json();
}

// ── Test state ────────────────────────────────────────────────────────────────

let token: string;
let token2: string;

beforeAll(async () => {
  try {
    await fetch(`${BASE}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(2000) });
  } catch {
    console.error(`\nServer not reachable at ${BASE}\n`);
    process.exit(1);
  }

  const ts = Date.now();
  [token, token2] = await Promise.all([
    signupAndGetToken(`media-a-${ts}@test.example.com`, "test-password-123"),
    signupAndGetToken(`media-b-${ts}@test.example.com`, "test-password-123"),
  ]);
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("POST /api/v1/media/check", () => {
  test("no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chunks: [{ hash: "a".repeat(64), size: 1 }] }),
    });
    expect(r.status).toBe(401);
  });

  test("empty chunks array → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [] }),
    });
    expect(r.status).toBe(400);
  });

  test("invalid hash (not 64 hex chars) → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [{ hash: "not-a-hash", size: 1 }] }),
    });
    expect(r.status).toBe(400);
  });

  test("unknown hashes → all returned as missing", async () => {
    const chunks = await Promise.all([makeChunk(), makeChunk()]);
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: chunks.map((c) => ({ hash: c.hash, size: c.size })) }),
    });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.missing_chunks).toHaveLength(2);
    expect(body.missing_chunks).toContain(chunks[0].hash);
    expect(body.missing_chunks).toContain(chunks[1].hash);
  });
});

describe("PUT /api/v1/media/chunks/:hash", () => {
  test("no auth → 401", async () => {
    const chunk = await makeChunk();
    const r = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      body: chunk.data,
    });
    expect(r.status).toBe(401);
  });

  test("invalid hash in URL → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/media/chunks/not-a-hash`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: new Uint8Array([1, 2, 3]),
    });
    expect(r.status).toBe(400);
  });

  test("hash mismatch (body doesn't match URL hash) → 400", async () => {
    const chunk = await makeChunk();
    const wrongHash = "a".repeat(64);
    const r = await fetch(`${BASE}/api/v1/media/chunks/${wrongHash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });
    expect(r.status).toBe(400);
  });

  test("valid chunk → 201", async () => {
    const chunk = await makeChunk();
    const r = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });
    expect(r.status).toBe(201);
  });

  test("same chunk uploaded again → 200 (idempotent)", async () => {
    const chunk = await makeChunk();
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });
    const r = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });
    expect(r.status).toBe(200);
  });

  test("after upload: check returns chunk as not missing", async () => {
    const chunk = await makeChunk();
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });

    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    const body = await r.json();
    expect(body.missing_chunks).toHaveLength(0);
  });
});

describe("POST /api/v1/media (finalize)", () => {
  test("no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/media`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: "f.bin", mime_type: "application/octet-stream", chunks: [] }),
    });
    expect(r.status).toBe(401);
  });

  test("missing filename → 400", async () => {
    const chunk = await makeChunk();
    const r = await fetch(`${BASE}/api/v1/media`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ mime_type: "application/octet-stream", chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    expect(r.status).toBe(400);
  });

  test("chunk not uploaded yet → 422", async () => {
    const chunk = await makeChunk(); // not uploaded
    const r = await fetch(`${BASE}/api/v1/media`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ filename: "f.bin", mime_type: "application/octet-stream", chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    expect(r.status).toBe(422);
  });

  test("full flow → 201 with correct media record", async () => {
    const chunks = await Promise.all([makeChunk(1024), makeChunk(2048)]);
    const media = await upload(token, chunks, "photo.jpg", "image/jpeg");

    expect(media.filename).toBe("photo.jpg");
    expect(media.mime_type).toBe("image/jpeg");
    expect(media.size).toBe(1024 + 2048);
    expect(media.id).toBeTruthy();
    expect(media.version).toBeTruthy();
    expect(Array.isArray(media.chunks)).toBe(true);
    expect(media.chunks).toHaveLength(2);
  });

  test("multi-chunk upload: size is sum of all chunks", async () => {
    const sizes = [512, 1024, 2048, 4096];
    const chunks = await Promise.all(sizes.map(makeChunk));
    const media = await upload(token, chunks);
    expect(media.size).toBe(sizes.reduce((a, b) => a + b, 0));
  });
});

describe("GET /api/v1/media + GET /api/v1/media/:id", () => {
  let mediaId: string;

  beforeAll(async () => {
    const chunks = [await makeChunk()];
    const media = await upload(token, chunks, "listed.bin", "application/octet-stream");
    mediaId = recordId(media.id);
  });

  test("get own media → 200 with fields", async () => {
    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, { headers: auth(token) });
    expect(r.status).toBe(200);
    const m = await r.json();
    expect(recordId(m.id)).toBe(mediaId);
    expect(m.filename).toBe("listed.bin");
  });

  test("get unknown id → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/doesnotexist`, { headers: auth(token) });
    expect(r.status).toBe(404);
  });

  test("get other user's media → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, { headers: auth(token2) });
    expect(r.status).toBe(404);
  });

  test("list includes uploaded item", async () => {
    const r = await fetch(`${BASE}/api/v1/media`, { headers: auth(token) });
    expect(r.status).toBe(200);
    const items = await r.json();
    expect(Array.isArray(items)).toBe(true);
    const found = items.find((m: any) => recordId(m.id) === mediaId);
    expect(found).toBeTruthy();
  });

  test("list is scoped to authenticated user", async () => {
    const r = await fetch(`${BASE}/api/v1/media`, { headers: auth(token2) });
    const items = await r.json();
    const leaked = items.find((m: any) => recordId(m.id) === mediaId);
    expect(leaked).toBeUndefined();
  });

  test("list no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/media`);
    expect(r.status).toBe(401);
  });
});

describe("PUT /api/v1/media/:id (update)", () => {
  let mediaId: string;
  let versionId: string;
  let originalChunk: Chunk;

  beforeAll(async () => {
    originalChunk = await makeChunk(1024);
    const media = await upload(token, [originalChunk], "original.txt", "text/plain");
    mediaId = recordId(media.id);
    versionId = recordId(media.version);
  });

  test("missing parent_version_id → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, {
      method: "PUT",
      headers: auth(token),
      body: JSON.stringify({ filename: "renamed.txt" }),
    });
    expect(r.status).toBe(400);
  });

  test("rename only → new version, filename updated", async () => {
    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, {
      method: "PUT",
      headers: auth(token),
      body: JSON.stringify({ parent_version_id: versionId, filename: "renamed.txt" }),
    });
    expect(r.status).toBe(200);
    const m = await r.json();
    expect(m.filename).toBe("renamed.txt");
    expect(m.mime_type).toBe("text/plain"); // unchanged
    expect(m.size).toBe(1024); // unchanged
    // version has advanced
    const newVersionId = recordId(m.version);
    expect(newVersionId).not.toBe(versionId);
    versionId = newVersionId; // advance for next test
  });

  test("replace chunks → size recalculated", async () => {
    const newChunk = await makeChunk(8192);
    // Upload the new chunk first
    await fetch(`${BASE}/api/v1/media/chunks/${newChunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: newChunk.data,
    });

    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, {
      method: "PUT",
      headers: auth(token),
      body: JSON.stringify({
        parent_version_id: versionId,
        chunks: [{ hash: newChunk.hash, size: newChunk.size }],
      }),
    });
    expect(r.status).toBe(200);
    const m = await r.json();
    expect(m.size).toBe(8192);
    versionId = recordId(m.version);
  });

  test("update non-existent → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/doesnotexist`, {
      method: "PUT",
      headers: auth(token),
      body: JSON.stringify({ parent_version_id: versionId, filename: "x" }),
    });
    expect(r.status).toBe(404);
  });

  test("cannot update other user's media → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, {
      method: "PUT",
      headers: auth(token2),
      body: JSON.stringify({ parent_version_id: versionId, filename: "hijacked" }),
    });
    expect(r.status).toBe(404);
  });
});

describe("deduplication", () => {
  test("uploading identical chunks twice: second check shows none missing", async () => {
    const chunk = await makeChunk(2048);

    // First upload
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });

    // Second check — should be empty
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    const { missing_chunks } = await r.json();
    expect(missing_chunks).toHaveLength(0);
  });

  test("same chunk hash is missing for a different user (per-user scope)", async () => {
    const chunk = await makeChunk(2048);

    // Upload as user1
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });

    // Check as user2 — chunk is scoped to user1, so user2 must still upload it
    const r = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token2),
      body: JSON.stringify({ chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    const { missing_chunks } = await r.json();
    expect(missing_chunks).toContain(chunk.hash);
  });

  test("two uploads of same file by same user share chunks (no double-upload)", async () => {
    const chunk = await makeChunk(4096);

    // First upload — uploads chunk
    const checkBefore = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    const { missing_chunks: missing1 } = await checkBefore.json();
    // upload if missing
    if (missing1.includes(chunk.hash)) {
      await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` },
        body: chunk.data,
      });
    }
    await upload(token, [chunk], "first-copy.bin");

    // Second upload of same content — check should show 0 missing
    const checkAfter = await fetch(`${BASE}/api/v1/media/check`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    const { missing_chunks: missing2 } = await checkAfter.json();
    expect(missing2).toHaveLength(0);

    // Finalize second copy directly (skip upload step — chunk already stored)
    const r = await fetch(`${BASE}/api/v1/media`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({ filename: "second-copy.bin", mime_type: "application/octet-stream", chunks: [{ hash: chunk.hash, size: chunk.size }] }),
    });
    expect(r.status).toBe(201);
  });
});

describe("GET /api/v1/media/chunks/:hash (download)", () => {
  test("no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/media/chunks/${"a".repeat(64)}`);
    expect(r.status).toBe(401);
  });

  test("invalid hash → 400", async () => {
    const r = await fetch(`${BASE}/api/v1/media/chunks/not-a-hash`, { headers: auth(token) });
    expect(r.status).toBe(400);
  });

  test("unknown hash → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/chunks/${"a".repeat(64)}`, { headers: auth(token) });
    expect(r.status).toBe(404);
  });

  test("uploaded chunk downloads with matching bytes", async () => {
    const chunk = await makeChunk(2048);
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });

    const r = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token) });
    expect(r.status).toBe(200);
    expect(r.headers.get("content-length")).toBe(String(chunk.size));
    const body = new Uint8Array(await r.arrayBuffer());
    expect(body).toEqual(chunk.data);
  });

  test("other user cannot download (per-user scope) → 404", async () => {
    const chunk = await makeChunk(1024);
    await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      body: chunk.data,
    });

    const r = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token2) });
    expect(r.status).toBe(404);
  });
});

describe("DELETE /api/v1/media/:id", () => {
  test("no auth → 401", async () => {
    const r = await fetch(`${BASE}/api/v1/media/doesnotexist`, { method: "DELETE" });
    expect(r.status).toBe(401);
  });

  test("delete non-existent → 404", async () => {
    const r = await fetch(`${BASE}/api/v1/media/doesnotexist`, { method: "DELETE", headers: auth(token) });
    expect(r.status).toBe(404);
  });

  test("cannot delete other user's media → 404, original untouched", async () => {
    const chunk = await makeChunk(512);
    const media = await upload(token, [chunk], "owned.bin");
    const mediaId = recordId(media.id);

    const r = await fetch(`${BASE}/api/v1/media/${mediaId}`, { method: "DELETE", headers: auth(token2) });
    expect(r.status).toBe(404);

    const check = await fetch(`${BASE}/api/v1/media/${mediaId}`, { headers: auth(token) });
    expect(check.status).toBe(200);
  });

  test("delete own media → 204, then 404 on get and absent from list", async () => {
    const chunk = await makeChunk(1024);
    const media = await upload(token, [chunk], "to-delete.bin");
    const mediaId = recordId(media.id);

    const del = await fetch(`${BASE}/api/v1/media/${mediaId}`, { method: "DELETE", headers: auth(token) });
    expect(del.status).toBe(204);

    const get = await fetch(`${BASE}/api/v1/media/${mediaId}`, { headers: auth(token) });
    expect(get.status).toBe(404);

    const list = await fetch(`${BASE}/api/v1/media`, { headers: auth(token) });
    const items = await list.json();
    expect(items.find((m: any) => recordId(m.id) === mediaId)).toBeUndefined();
  });

  test("deleting media garbage collects its sole chunk", async () => {
    const chunk = await makeChunk(2048);
    const media = await upload(token, [chunk], "solo-chunk.bin");
    const mediaId = recordId(media.id);

    const before = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token) });
    expect(before.status).toBe(200);

    const del = await fetch(`${BASE}/api/v1/media/${mediaId}`, { method: "DELETE", headers: auth(token) });
    expect(del.status).toBe(204);

    const after = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token) });
    expect(after.status).toBe(404);
  });

  test("deleting one of two media sharing a chunk keeps it alive until the last reference is gone", async () => {
    const chunk = await makeChunk(4096);
    const mediaA = await upload(token, [chunk], "shared-a.bin");
    const mediaB = await upload(token, [chunk], "shared-b.bin");

    const delA = await fetch(`${BASE}/api/v1/media/${recordId(mediaA.id)}`, { method: "DELETE", headers: auth(token) });
    expect(delA.status).toBe(204);

    // still referenced by mediaB → not collected yet
    const stillThere = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token) });
    expect(stillThere.status).toBe(200);

    const delB = await fetch(`${BASE}/api/v1/media/${recordId(mediaB.id)}`, { method: "DELETE", headers: auth(token) });
    expect(delB.status).toBe(204);

    // last reference gone → garbage collected
    const gone = await fetch(`${BASE}/api/v1/media/chunks/${chunk.hash}`, { headers: auth(token) });
    expect(gone.status).toBe(404);
  });
});
