package gql

import "fmt"

// openschemaTargets is the codegen target set every seeded schema advertises.
var openschemaTargets = []string{"SQL", "TypeScript", "Go", "JSON Schema", "GraphQL", "OpenAPI"}

type seedFile struct {
	path     string
	contents string
}

type seedSchema struct {
	scope       string
	name        string
	description string
	version     string
	downloads   int
	official    bool
	tags        []string
	readme      string
	files       []seedFile
}

// genReadme is the fallback readme for schemas without an authored one.
func genReadme(s seedSchema) string {
	return fmt.Sprintf(`## Overview

%s

## Install

`+"```"+`bash
openschema add @%s/%s
openschema gen %s.schema --target ts --out ./src/types
`+"```"+`

Write the model once and generate SQL, TypeScript, Go, JSON Schema, GraphQL, and
OpenAPI — all guaranteed to agree.`, s.description, s.scope, s.name, s.name)
}

// genFile is the fallback single source file for schemas without authored files.
func genFile(s seedSchema) seedFile {
	title := s.name
	if title != "" {
		title = string(title[0]-32) + title[1:]
	}
	return seedFile{
		path: s.name + ".schema",
		contents: fmt.Sprintf(`namespace %s

@table("%s")
model %s {
  @primaryKey @default(gen_uuid())
  1 id: uuid

  2 name: string
  3 createdAt: timestamp
}`, s.name, s.name, title),
	}
}

func openschemaSeedCatalog() []seedSchema {
	catalog := []seedSchema{
		{
			scope: "neoworks", name: "commerce",
			description: "Orders, carts, catalog, and payments — the canonical retail core schema.",
			version:     "2.4.1", downloads: 48200, official: true,
			tags: []string{"orders", "catalog", "payments"},
			readme: `## Overview

The canonical retail core schema: **orders, carts, catalog, and payments** in one
source of truth. Generate database tables, API types, and GraphQL from the same
definition — they can't drift because they all come from here.

## What's inside

- **Catalog** — products, variants, prices, and inventory.
- **Cart & checkout** — carts, line items, and discounts.
- **Orders** — orders, fulfilment, and returns with stable field ordinals.
- **Payments** — payment intents, captures, and refunds.

## Compatibility

Every release is gated by ` + "`openschema check`" + ` in CI, so upgrades within a major
version are guaranteed backward-compatible.`,
			files: []seedFile{
				{path: "commerce.schema", contents: `namespace commerce

import Product from "./catalog.schema"
import Order from "./orders.schema"

enum OrderStatus { 1 pending  2 paid  3 shipped  4 delivered  5 refunded }
enum Currency { 1 usd  2 eur  3 gbp }`},
				{path: "catalog.schema", contents: `namespace commerce

@table("products")
model Product {
  @primaryKey @default(gen_uuid())
  1 id: uuid

  2 sku: string
  3 title: string
  4 description: string?

  @minValue(0)
  5 priceCents: i64

  6 currency: Currency
  7 inStock: bool
}`},
				{path: "orders.schema", contents: `namespace commerce

@table("orders")
model Order {
  @primaryKey @default(gen_uuid())
  1 id: uuid

  2 status: OrderStatus

  @minValue(0)
  3 totalCents: i64

  4 currency: Currency
  5 placedAt: timestamp
  6 note: string?
  7 lines: [OrderLine]
}

model OrderLine {
  1 sku: string
  @minValue(1)
  2 quantity: i32
  @minValue(0)
  3 unitPriceCents: i64
}`},
			},
		},
		{
			scope: "neoworks", name: "identity",
			description: "Accounts, organizations, roles, and OAuth clients with stable field ordinals.",
			version:     "3.1.0", downloads: 41080, official: true,
			tags: []string{"accounts", "oauth", "rbac"},
			readme: `## Overview

Accounts, organizations, roles, and OAuth clients — the shared **identity** core
behind every NeoWorks service. Stable field ordinals keep tokens and stored rows
compatible across every release.

## What's inside

- **Accounts** — users, emails, and credentials.
- **Organizations** — orgs, memberships, and roles (RBAC).
- **OAuth** — clients, scopes, and grants.`,
			files: []seedFile{
				{path: "identity.schema", contents: `namespace identity

import Account from "./accounts.schema"

enum Role { 1 owner  2 admin  3 member  4 viewer }`},
				{path: "accounts.schema", contents: `namespace identity

@table("accounts")
model Account {
  @primaryKey @default(gen_uuid())
  1 id: uuid

  @format("email")
  2 email: string

  3 displayName: string?
  4 createdAt: timestamp
}

@table("memberships")
model Membership {
  1 account: uuid
  2 organization: uuid
  3 role: Role
}`},
			},
		},
		{
			scope: "neoworks", name: "geo",
			description: "Places, addresses, routes, and H3 cells shared across the maps stack.",
			version:     "1.9.2", downloads: 27640, official: true,
			tags: []string{"places", "routing", "h3"},
		},
		{
			scope: "acme", name: "billing",
			description: "Invoices, subscriptions, and tax lines overlaying the commerce core.",
			version:     "0.8.0", downloads: 12940, official: false,
			tags: []string{"invoices", "subscriptions", "overlay"},
		},
		{
			scope: "globex", name: "logistics",
			description: "Shipments, fulfilment, and carrier events with compatibility-checked releases.",
			version:     "1.2.5", downloads: 9870, official: false,
			tags: []string{"shipments", "fulfilment"},
		},
		{
			scope: "neoworks", name: "messaging",
			description: "Conversations, messages, and delivery receipts for the relay services.",
			version:     "1.0.4", downloads: 8120, official: true,
			tags: []string{"chat", "receipts"},
		},
		{
			scope: "neoworks", name: "analytics",
			description: "Events, sessions, and funnels with a privacy-first column visibility model.",
			version:     "0.6.0", downloads: 5230, official: true,
			tags: []string{"events", "funnels"},
		},
		{
			scope: "acme", name: "support",
			description: "Tickets, threads, and SLAs overlaying the messaging core schema.",
			version:     "0.3.1", downloads: 1840, official: false,
			tags: []string{"tickets", "sla", "overlay"},
		},
		{
			scope: "neoworks", name: "file",
			description: "Assets, encodings, and thumbnails for the encrypted file surface.",
			version:     "1.4.0", downloads: 6710, official: true,
			tags: []string{"assets", "thumbnails"},
		},
	}

	for i := range catalog {
		if catalog[i].readme == "" {
			catalog[i].readme = genReadme(catalog[i])
		}
		if len(catalog[i].files) == 0 {
			catalog[i].files = []seedFile{genFile(catalog[i])}
		}
	}
	return catalog
}
