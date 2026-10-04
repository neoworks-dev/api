# NeoWorks API

Core backend for the NeoWorks platform: the REST API under `/api/v1` (encrypted
node tree and sync, access grants, key bundles, devices, app installs, presigned
blob URLs, link shares), storage (SurrealDB, S3-compatible object storage),
OAuth token primitives, scheduling, email, and push. Go module
`github.com/neoworks/auth`.

## License

Source-available under the **PolyForm Shield License 1.0.0** — see
[LICENSE.md](./LICENSE.md). You may use, modify, and self-host it for any
purpose **except** building a product or service that competes with NeoWorks.
No warranty.

## Role in the monorepo

This module is the shared foundation several sibling services depend on via a
`replace github.com/neoworks/auth => ../api` directive (e.g. `apps/oauth`).
It is consumed as a **git submodule** of the NeoWorks monorepo
and expects to sit at `apps/api` next to those siblings.

## Local development

Configuration is read from `.env` (see `.env.example`). The JWT signing key at
`keys/auth.pem` is local-only and is never committed. From the monorepo root the
dev stack brings this service up with air hot-reload against SurrealDB and Redis.
