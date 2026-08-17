/**
 * Two-user end-to-end test for E2EE spaces: real signup, real libsodium crypto
 * (the shipped space-keys.js module), real REST calls.
 *
 * A creates a shared space, encrypts a contact row, invites B with a sealed
 * space-key wrap; B accepts, pulls, verifies A's signature, and decrypts. Then
 * rotation locks a removed member out, OCC conflicts return the current row,
 * and no response ever contains plaintext contact fields.
 *
 * Requires both servers up (see ../_helpers.ts):
 *   go run ./cmd/oauth   (apps/oauth, :8080)
 *   go run ./cmd/api     (apps/api,  :8081)
 * Skips cleanly when the API server is unreachable.
 */

import { describe, test, expect, beforeAll } from 'bun:test'
import _sodium from 'libsodium-wrappers-sumo'
// The shipped Vault modules are the code under test.
// @ts-ignore plain JS module shared with the Vault iframe
import { createSpaceKeys } from '../../../../oauth/handlers/auth/static/space-keys.js'
// @ts-ignore plain JS module shared with the Vault iframe
import { createScopeKeys } from '../../../../oauth/handlers/auth/static/scope-keys.js'
import { API_BASE, signupAndGetToken } from '../_helpers.ts'

const SCOPES = ['openid', 'profile', 'email', 'contacts:read', 'contacts:write']
const COLLECTION = 'contacts'

let sodium: typeof _sodium
let spaceApi: ReturnType<typeof createSpaceKeys>
let scopeApi: ReturnType<typeof createScopeKeys>
let serverUp = false

function b64(bytes: Uint8Array): string {
	return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}
function fromB64(value: string): Uint8Array {
	return sodium.from_base64(value, sodium.base64_variants.ORIGINAL)
}

/** One test user: token + AMK-derived scope keypair and signing keypair. */
interface TestUser {
	token: string
	userId: string
	scopeKp: { publicKey: Uint8Array; privateKey: Uint8Array }
	signKp: { publicKey: Uint8Array; privateKey: Uint8Array }
	/** Kept so a test can derive another collection's scope keypair. */
	scopeMaster: Uint8Array
}

function jwtSub(token: string): string {
	const payload = JSON.parse(atob(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')))
	return String(payload.sub)
}

async function makeUser(): Promise<TestUser> {
	const token = await signupAndGetToken(SCOPES)
	const amk = crypto.getRandomValues(new Uint8Array(32))
	const scopeMaster = scopeApi.deriveScopeMaster(amk)
	const user: TestUser = {
		token,
		userId: jwtSub(token),
		scopeKp: scopeApi.scopeKeypair(scopeMaster, COLLECTION),
		signKp: spaceApi.deriveSigningKeypair(amk),
		scopeMaster,
	}
	// Publish directory keys the way the Vault does on unlock.
	await api(user, 'PUT', '/api/v1/keys/public', {
		public_key: b64(user.scopeKp.publicKey),
		fingerprint: 'fp',
		sign_public_key: b64(user.signKp.publicKey),
	})
	await api(user, 'PUT', '/api/v1/keys/scope-public', {
		scope: COLLECTION,
		public_key: b64(user.scopeKp.publicKey),
	})
	return user
}

async function api(user: TestUser, method: string, path: string, body?: unknown): Promise<Response> {
	const headers: Record<string, string> = { Authorization: `Bearer ${user.token}` }
	if (body !== undefined) headers['Content-Type'] = 'application/json'
	return fetch(`${API_BASE}${path}`, {
		method,
		headers,
		body: body === undefined ? undefined : JSON.stringify(body),
	})
}

/** Encrypts one row exactly like the Vault does. */
async function sealRow(
	user: TestUser,
	spaceKey: Uint8Array,
	spaceId: string,
	header: { itemId: string; keyEpoch: number; schemaVer: number; baseSeq: number; deleted: boolean },
	plaintext: Uint8Array,
	collection: string = COLLECTION,
): Promise<{ blob: string; sig: string }> {
	const aad = spaceApi.buildRowAad({ ...header, spaceId, collection })
	const rowKey = spaceApi.deriveRowKey(spaceKey, header.itemId)
	const key = await crypto.subtle.importKey('raw', rowKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
	const iv = crypto.getRandomValues(new Uint8Array(12))
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext))
	const blob = new Uint8Array(12 + ct.length)
	blob.set(iv, 0)
	blob.set(ct, 12)
	return {
		blob: b64(blob),
		sig: spaceApi.signEnvelope(aad, blob, user.signKp.privateKey),
	}
}

/**
 * The history entry a content write appends. Every accepted push carries at
 * least one: the server rejects a content write without versions, because a row
 * with no recoverable history is a row whose past the client silently dropped.
 */
async function sealVersion(
	user: TestUser,
	spaceKey: Uint8Array,
	spaceId: string,
	header: {
		itemId: string
		versionId: string
		keyEpoch: number
		schemaVer: number
		baseSeq: number
		deleted: boolean
	},
	plaintext: Uint8Array,
	collection: string = COLLECTION,
): Promise<{ version_id: string; blob: string; sig: string }> {
	const aad = spaceApi.buildVersionAad({ ...header, spaceId, collection })
	const versionKey = spaceApi.deriveVersionKey(spaceKey, header.versionId)
	const key = await crypto.subtle.importKey('raw', versionKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
	const iv = crypto.getRandomValues(new Uint8Array(12))
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext))
	const blob = new Uint8Array(12 + ct.length)
	blob.set(iv, 0)
	blob.set(ct, 12)
	return {
		version_id: header.versionId,
		blob: b64(blob),
		sig: spaceApi.signEnvelope(aad, blob, user.signKp.privateKey),
	}
}

async function openRow(
	spaceKey: Uint8Array,
	spaceId: string,
	envelope: {
		item_id: string
		key_epoch: number
		schema_ver: number
		base_seq: number
		deleted: boolean
		blob: string
		sig: string
	},
	signerPub: string,
	collection: string = COLLECTION,
): Promise<Uint8Array> {
	const aad = spaceApi.buildRowAad({
		itemId: envelope.item_id,
		spaceId,
		collection,
		keyEpoch: envelope.key_epoch,
		schemaVer: envelope.schema_ver,
		baseSeq: envelope.base_seq,
		deleted: envelope.deleted,
	})
	const blob = fromB64(envelope.blob)
	if (!spaceApi.verifyEnvelope(aad, blob, envelope.sig, signerPub)) {
		throw new Error('bad envelope signature')
	}
	const rowKey = spaceApi.deriveRowKey(spaceKey, envelope.item_id)
	const key = await crypto.subtle.importKey('raw', rowKey, 'AES-GCM', false, ['decrypt'])
	return new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: blob.slice(0, 12), additionalData: aad },
			key,
			blob.slice(12),
		),
	)
}

beforeAll(async () => {
	await _sodium.ready
	sodium = _sodium
	spaceApi = createSpaceKeys(sodium)
	scopeApi = createScopeKeys(sodium)
	try {
		const res = await fetch(`${API_BASE}/health`)
		serverUp = res.ok
	} catch {
		serverUp = false
	}
})

describe('spaces E2E', () => {
	test('two-user share: create, push, invite, accept, pull, decrypt, verify', async () => {
		if (!serverUp) {
			console.warn('skipping: api server not reachable at', API_BASE)
			return
		}
		const alice = await makeUser()
		const bob = await makeUser()

		// Alice creates a shared space with a freshly minted key.
		const spaceId = crypto.randomUUID()
		const spaceKey = spaceApi.mintSpaceKey()
		const selfWrap = spaceApi.wrapSpaceKey(spaceKey, b64(alice.scopeKp.publicKey))
		const selfSig = spaceApi.signWrap(spaceId, alice.userId, 1, spaceKey, alice.signKp.privateKey)
		const createRes = await api(alice, 'POST', '/api/v1/spaces', {
			space_id: spaceId,
			collection: COLLECTION,
			kind: 'shared',
			wrapped_key: selfWrap,
			signature: selfSig,
		})
		expect(createRes.ok).toBe(true)

		// Alice pushes an encrypted contact.
		const itemId = crypto.randomUUID()
		const secret = new TextEncoder().encode('{"formatted_name":"Shared Ada","phones":["+491701234567"]}')
		const sealed = await sealRow(
			alice,
			spaceKey,
			spaceId,
			{ itemId, keyEpoch: 1, schemaVer: 1, baseSeq: 0, deleted: false },
			secret,
		)
		const firstVersion = await sealVersion(
			alice,
			spaceKey,
			spaceId,
			{ itemId, versionId: crypto.randomUUID(), keyEpoch: 1, schemaVer: 1, baseSeq: 0, deleted: false },
			secret,
		)
		const pushRes = await api(alice, 'PUT', `/api/v1/spaces/${spaceId}/items/${itemId}`, {
			base_seq: 0,
			key_epoch: 1,
			schema_ver: 1,
			deleted: false,
			blob: sealed.blob,
			sig: sealed.sig,
			versions: [firstVersion],
		})
		expect(pushRes.ok).toBe(true)
		expect((await pushRes.json()).seq).toBe(1)

		// The server response and stored row never contain plaintext.
		const rawPull = await (await api(alice, 'GET', `/api/v1/spaces/${spaceId}/items?since=0`)).text()
		expect(rawPull).not.toContain('Shared Ada')
		expect(rawPull).not.toContain('491701234567')

		// Alice looks up Bob's scope key + sign key, seals the space key to him.
		const dir = await (await api(alice, 'GET', `/api/v1/keys/public?user=${bob.userId}&scope=${COLLECTION}`)).json()
		expect(dir.public_key).toBe(b64(bob.scopeKp.publicKey))
		expect(dir.sign_public_key).toBe(b64(bob.signKp.publicKey))
		const bobWrap = spaceApi.wrapSpaceKey(spaceKey, dir.public_key)
		const bobWrapSig = spaceApi.signWrap(spaceId, bob.userId, 1, spaceKey, alice.signKp.privateKey)
		const inviteRes = await api(alice, 'POST', `/api/v1/spaces/${spaceId}/members`, {
			user_id: bob.userId,
			role: 'writer',
			wrapped_keys: [{ epoch: 1, wrapped_key: bobWrap, signature: bobWrapSig }],
		})
		expect(inviteRes.ok).toBe(true)

		// Bob cannot pull before accepting.
		expect((await api(bob, 'GET', `/api/v1/spaces/${spaceId}/items?since=0`)).status).toBe(403)

		// Bob unseals the wrap, verifies Alice's signature, re-signs, accepts.
		const bobMemberships = await (await api(bob, 'GET', `/api/v1/spaces?collection=${COLLECTION}`)).json()
		const invite = bobMemberships.spaces.find((m: any) => m.space.space_id === spaceId)
		expect(invite.member.status).toBe('invited')
		const wrap = invite.member.wrapped_keys[0]
		const bobSpaceKey = spaceApi.unwrapSpaceKey(wrap.wrapped_key, bob.scopeKp)
		const aliceDir = await (await api(bob, 'GET', `/api/v1/keys/public?user=${alice.userId}&scope=${COLLECTION}`)).json()
		expect(
			spaceApi.verifyWrap(spaceId, bob.userId, wrap.epoch, bobSpaceKey, wrap.signature, aliceDir.sign_public_key),
		).toBe(true)
		const acceptSig = spaceApi.signWrap(spaceId, bob.userId, wrap.epoch, bobSpaceKey, bob.signKp.privateKey)
		expect((await api(bob, 'POST', `/api/v1/spaces/${spaceId}/accept`, { accept_signature: acceptSig })).ok).toBe(true)

		// Bob pulls, verifies Alice's envelope signature, decrypts.
		const page = await (await api(bob, 'GET', `/api/v1/spaces/${spaceId}/items?since=0`)).json()
		expect(page.items.length).toBe(1)
		const plain = await openRow(bobSpaceKey, spaceId, page.items[0], aliceDir.sign_public_key)
		expect(new TextDecoder().decode(plain)).toContain('Shared Ada')

		// Bob (writer) pushes an update; Alice pulls and decrypts it.
		const bobEdit = new TextEncoder().encode('{"formatted_name":"Shared Ada (edited by Bob)"}')
		const bobSealed = await sealRow(
			bob,
			bobSpaceKey,
			spaceId,
			{ itemId, keyEpoch: 1, schemaVer: 1, baseSeq: 1, deleted: false },
			bobEdit,
		)
		const bobVersion = await sealVersion(
			bob,
			bobSpaceKey,
			spaceId,
			{ itemId, versionId: crypto.randomUUID(), keyEpoch: 1, schemaVer: 1, baseSeq: 1, deleted: false },
			bobEdit,
		)
		const bobPush = await api(bob, 'PUT', `/api/v1/spaces/${spaceId}/items/${itemId}`, {
			base_seq: 1,
			key_epoch: 1,
			schema_ver: 1,
			deleted: false,
			blob: bobSealed.blob,
			sig: bobSealed.sig,
			versions: [bobVersion],
		})
		expect(bobPush.ok).toBe(true)

		// OCC: Alice pushing against the stale base gets 409 + the current row.
		const staleSealed = await sealRow(
			alice,
			spaceKey,
			spaceId,
			{ itemId, keyEpoch: 1, schemaVer: 1, baseSeq: 1, deleted: false },
			secret,
		)
		const staleVersion = await sealVersion(
			alice,
			spaceKey,
			spaceId,
			{ itemId, versionId: crypto.randomUUID(), keyEpoch: 1, schemaVer: 1, baseSeq: 1, deleted: false },
			secret,
		)
		const conflictRes = await api(alice, 'PUT', `/api/v1/spaces/${spaceId}/items/${itemId}`, {
			base_seq: 1,
			key_epoch: 1,
			schema_ver: 1,
			deleted: false,
			blob: staleSealed.blob,
			sig: staleSealed.sig,
			versions: [staleVersion],
		})
		expect(conflictRes.status).toBe(409)
		const conflictBody = await conflictRes.json()
		expect(conflictBody.error).toBe('conflict')
		expect(conflictBody.current.seq).toBe(2)

		// Removal + rotation: Bob is locked out; epoch-1 pushes are rejected.
		const removeRes = await api(alice, 'DELETE', `/api/v1/spaces/${spaceId}/members/${bob.userId}`)
		expect(removeRes.ok).toBe(true)
		const newKey = spaceApi.mintSpaceKey()
		const rotateRes = await api(alice, 'POST', `/api/v1/spaces/${spaceId}/rotate`, {
			expected_epoch: 1,
			rewrapped: [
				{
					user_id: alice.userId,
					wrapped_key: spaceApi.wrapSpaceKey(newKey, b64(alice.scopeKp.publicKey)),
					signature: spaceApi.signWrap(spaceId, alice.userId, 2, newKey, alice.signKp.privateKey),
				},
			],
		})
		expect(rotateRes.ok).toBe(true)
		expect((await rotateRes.json()).key_epoch).toBe(2)

		expect((await api(bob, 'GET', `/api/v1/spaces/${spaceId}/items?since=0`)).status).toBe(403)

		const oldEpochPush = await api(alice, 'PUT', `/api/v1/spaces/${spaceId}/items/${itemId}`, {
			base_seq: 2,
			key_epoch: 1,
			schema_ver: 1,
			deleted: false,
			blob: staleSealed.blob,
			sig: staleSealed.sig,
			versions: [staleVersion],
		})
		expect(oldEpochPush.status).toBe(409)
		expect((await oldEpochPush.json()).error).toBe('stale_epoch')
	}, 60_000)

	test('one table serves every collection, keyed by its space', async () => {
		if (!serverUp) return
		const user = await makeUser()

		// The same item uuid in a calendar space and a memories space. Under the
		// old flat ids these would have been one row fighting over one key; the
		// composite key makes them two rows that cannot see each other.
		const itemId = crypto.randomUUID()
		const written: Record<string, { spaceId: string; key: Uint8Array; text: string }> = {}

		for (const collection of ['calendar', 'memories'] as const) {
			const scopeKp = scopeApi.scopeKeypair(user.scopeMaster, collection)
			await api(user, 'PUT', '/api/v1/keys/scope-public', {
				scope: collection,
				public_key: b64(scopeKp.publicKey),
			})

			const spaceId = crypto.randomUUID()
			const key = spaceApi.mintSpaceKey()
			const createRes = await api(user, 'POST', '/api/v1/spaces', {
				space_id: spaceId,
				collection,
				kind: 'shared',
				wrapped_key: spaceApi.wrapSpaceKey(key, b64(scopeKp.publicKey)),
				signature: spaceApi.signWrap(spaceId, user.userId, 1, key, user.signKp.privateKey),
			})
			expect(createRes.ok).toBe(true)

			const text = collection === 'calendar' ? '{"title":"Standup"}' : '{"source_text":"a ramble"}'
			const plaintext = new TextEncoder().encode(text)
			const header = { itemId, keyEpoch: 1, schemaVer: 1, baseSeq: 0, deleted: false }
			const sealed = await sealRow(user, key, spaceId, header, plaintext, collection)
			const version = await sealVersion(
				user,
				key,
				spaceId,
				{ ...header, versionId: crypto.randomUUID() },
				plaintext,
				collection,
			)

			const pushRes = await api(user, 'PUT', `/api/v1/spaces/${spaceId}/items/${itemId}`, {
				base_seq: 0,
				key_epoch: 1,
				schema_ver: 1,
				deleted: false,
				blob: sealed.blob,
				sig: sealed.sig,
				versions: [version],
			})
			expect(pushRes.ok).toBe(true)
			// Each space counts its own sequence from 1, sharing a table or not.
			expect((await pushRes.json()).seq).toBe(1)
			written[collection] = { spaceId, key, text }
		}

		// Each space pulls back exactly its own row, decrypting under its own key.
		for (const collection of ['calendar', 'memories'] as const) {
			const { spaceId, key, text } = written[collection]!
			const page = await (await api(user, 'GET', `/api/v1/spaces/${spaceId}/items?since=0`)).json()
			expect(page.items.length).toBe(1)
			expect(page.items[0].item_id).toBe(itemId)

			const directory = await (
				await api(user, 'GET', `/api/v1/keys/public?user=${user.userId}&scope=${collection}`)
			).json()
			const plain = await openRow(key, spaceId, page.items[0], directory.sign_public_key, collection)
			expect(new TextDecoder().decode(plain)).toBe(text)
		}
	}, 60_000)

	test('personal space create is idempotent across devices', async () => {
		if (!serverUp) return
		const user = await makeUser()
		const makePersonal = async () => {
			const spaceId = crypto.randomUUID()
			const key = spaceApi.mintSpaceKey()
			return api(user, 'POST', '/api/v1/spaces', {
				space_id: spaceId,
				collection: COLLECTION,
				kind: 'personal',
				wrapped_key: spaceApi.wrapSpaceKey(key, b64(user.scopeKp.publicKey)),
				signature: spaceApi.signWrap(spaceId, user.userId, 1, key, user.signKp.privateKey),
			})
		}
		const first = await (await makePersonal()).json()
		const second = await (await makePersonal()).json()
		expect(first.space.space_id).toBe(second.space.space_id)
	}, 30_000)
})
