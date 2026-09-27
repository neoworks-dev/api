/**
 * The asset routes live in the api process but on their own listener, so their
 * own origin. An upload must be reachable only there, and nothing a browser
 * could execute may render there.
 *
 * Requires both servers up (see ../_helpers.ts). Skips cleanly when the API
 * server is unreachable.
 */

import { describe, test, expect, beforeAll } from 'bun:test'
import { API_BASE, ASSETS_BASE, signupAndGetToken } from '../_helpers.ts'

let serverUp = false
let token = ''

beforeAll(async () => {
	try {
		serverUp = (await fetch(`${API_BASE}/health`)).ok
	} catch {
		serverUp = false
	}
	if (serverUp) token = await signupAndGetToken()
})

async function upload(body: BlobPart, type: string): Promise<{ id: string; url: string }> {
	const form = new FormData()
	form.append('file', new Blob([body], { type }), 'upload')
	form.append('visibility', 'public')
	const res = await fetch(`${ASSETS_BASE}/assets`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${token}` },
		body: form,
	})
	expect(res.status).toBe(201)
	return res.json()
}

function fetchFromAssetOrigin(id: string): Promise<Response> {
	return fetch(`${ASSETS_BASE}/assets/${id}`)
}

describe('assets', () => {
	test('a public image renders inline on the asset origin', async () => {
		if (!serverUp) return
		const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
		const { id } = await upload(png, 'image/png')

		const res = await fetchFromAssetOrigin(id)
		expect(res.status).toBe(200)
		expect(res.headers.get('content-type')).toBe('image/png')
		expect(res.headers.get('x-content-type-options')).toBe('nosniff')
		expect(res.headers.get('content-disposition')).toBeNull()
	}, 30_000)

	test('an uploaded HTML page downloads inside a sandbox instead of rendering', async () => {
		if (!serverUp) return
		const { id } = await upload('<script>alert(1)</script>', 'text/html')

		const res = await fetchFromAssetOrigin(id)
		expect(res.status).toBe(200)
		expect(res.headers.get('content-disposition')).toBe('attachment')
		expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox")
		expect(res.headers.get('x-content-type-options')).toBe('nosniff')
	}, 30_000)

	test('the API origin never serves an asset', async () => {
		if (!serverUp) return
		const { id } = await upload('plain', 'text/plain')

		expect((await fetchFromAssetOrigin(id)).status).toBe(200)
		expect((await fetch(`${API_BASE}/assets/${id}`)).status).toBe(404)
	}, 30_000)
})
