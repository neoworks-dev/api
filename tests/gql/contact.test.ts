import { describe, test, expect, beforeEach } from "bun:test";
import { buildSchema, graphql as execute } from "graphql";
import { readFileSync } from "fs";
import { join } from "path";

const schema = buildSchema(
  readFileSync(join(import.meta.dir, "../../schema/Contacts.graphql"), "utf-8"),
);

// ── In-memory store ───────────────────────────────────────────────────────────

type Contact = {
  id: string;
  name: string;
  email: string;
  phone?: string;
  created_at: string;
  updated_at: string;
  version_id: string;
  user_id: string;
};

type ContactVersion = {
  id: string;
  contact_id: string;
  name: string;
  email: string;
  phone?: string;
  created_at: string;
};

let contacts: Map<string, Contact>;
let versions: Map<string, ContactVersion>;
let seq: number;
let currentUserId: string;

function nextId(prefix: string): string {
  return `${prefix}:${++seq}`;
}

function resetStore(userId = "user:test") {
  contacts = new Map();
  versions = new Map();
  seq = 0;
  currentUserId = userId;
}

// ── Resolvers ─────────────────────────────────────────────────────────────────

function makeRoot() {
  return {
    contacts({ limit = 50, offset = 0 }: { limit?: number; offset?: number }) {
      return [...contacts.values()]
        .filter((c) => c.user_id === currentUserId)
        .slice(offset, offset + limit)
        .map(toGqlContact);
    },

    contact({ id }: { id: string }) {
      const c = contacts.get(full("contact", id));
      if (!c || c.user_id !== currentUserId) return null;
      return toGqlContact(c);
    },

    contactHistory({
      id,
      filter,
    }: {
      id: string;
      filter?: {
        name?: string;
        email?: string;
        phone?: string;
        before?: string;
      };
    }) {
      const contactId = full("contact", id);
      return [...versions.values()]
        .filter((v) => {
          if (v.contact_id !== contactId) return false;
          if (filter?.name && v.name !== filter.name) return false;
          if (filter?.email && v.email !== filter.email) return false;
          if (filter?.phone && v.phone !== filter.phone) return false;
          if (filter?.before && v.created_at > filter.before) return false;
          return true;
        })
        .sort((a, b) => b.created_at.localeCompare(a.created_at))
        .map(toGqlVersion);
    },

    createContact({
      input,
    }: {
      input: { name: string; email: string; phone?: string };
    }) {
      const id = nextId("contact");
      const vId = nextId("contact_version");
      const ts = new Date().toISOString();

      versions.set(vId, {
        id: vId,
        contact_id: id,
        name: input.name,
        email: input.email,
        phone: input.phone,
        created_at: ts,
      });

      const contact: Contact = {
        id,
        name: input.name,
        email: input.email,
        phone: input.phone,
        created_at: ts,
        updated_at: ts,
        version_id: vId,
        user_id: currentUserId,
      };
      contacts.set(id, contact);
      return toGqlContact(contact);
    },

    updateContact({
      id,
      parentVersionIds: _parents,
      input,
    }: {
      id: string;
      parentVersionIds: string[];
      input: { name?: string; email?: string; phone?: string };
    }) {
      const contactId = full("contact", id);
      const current = contacts.get(contactId);
      if (!current) throw new Error("contact not found");

      const vId = nextId("contact_version");
      const ts = new Date().toISOString();

      const name = input.name ?? current.name;
      const email = input.email ?? current.email;
      const phone = input.phone ?? current.phone;

      versions.set(vId, {
        id: vId,
        contact_id: contactId,
        name,
        email,
        phone,
        created_at: ts,
      });

      const updated: Contact = {
        ...current,
        name,
        email,
        phone,
        updated_at: ts,
        version_id: vId,
      };
      contacts.set(contactId, updated);
      return toGqlContact(updated);
    },

    deleteContact({ id }: { id: string }) {
      const contactId = full("contact", id);
      const c = contacts.get(contactId);
      if (!c || c.user_id !== currentUserId) return false;
      contacts.delete(contactId);
      return true;
    },
  };
}

function full(table: string, id: string): string {
  return id.includes(":") ? id : `${table}:${id}`;
}

function stripTable(id: string): string {
  const idx = id.indexOf(":");
  return idx >= 0 ? id.slice(idx + 1) : id;
}

function toGqlContact(c: Contact) {
  return {
    id: c.id,
    name: c.name,
    email: c.email,
    phone: c.phone,
    createdAt: c.created_at,
    updatedAt: c.updated_at,
  };
}

function toGqlVersion(v: ContactVersion) {
  return {
    id: v.id,
    contactId: v.contact_id,
    name: v.name,
    email: v.email,
    phone: v.phone,
    createdAt: v.created_at,
  };
}

// ── GQL helper ────────────────────────────────────────────────────────────────

async function gql(query: string, variables?: Record<string, unknown>) {
  const result = await execute({
    schema,
    source: query,
    rootValue: makeRoot(),
    variableValues: variables,
  });
  if (result.errors?.length)
    throw new Error(result.errors.map((e) => e.message).join("; "));
  return result.data!;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("Contact GQL", () => {
  beforeEach(() => resetStore());

  test("createContact returns contact with timestamps", async () => {
    const data = await gql(`
      mutation {
        createContact(input: { name: "Alice Smith", email: "alice@example.com" }) {
          id name email createdAt updatedAt
        }
      }
    `);
    const c = (data as any).createContact;
    expect(c.name).toBe("Alice Smith");
    expect(c.email).toBe("alice@example.com");
    expect(c.createdAt).toBeTruthy();
    expect(c.updatedAt).toBeTruthy();
  });

  test("contact query returns created contact", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Bob", email: "bob@example.com" }) { id } }
    `);
    const id = stripTable((d as any).createContact.id);

    const data = await gql(
      `query($id: ID!) { contact(id: $id) { id name email } }`,
      { id },
    );
    expect((data as any).contact.email).toBe("bob@example.com");
  });

  test("createContact produces one version in history", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const id = stripTable((d as any).createContact.id);

    const data = await gql(
      `query($id: ID!) { contactHistory(id: $id) { id contactId name email createdAt } }`,
      { id },
    );
    const history = (data as any).contactHistory;
    expect(history).toHaveLength(1);
    expect(history[0].name).toBe("Alice Smith");
    expect(history[0].contactId).toBeTruthy();
  });

  test("updateContact creates new version and preserves unset fields", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const cId = stripTable((d as any).createContact.id);
    const v1Id = stripTable(
      (
        (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
          id: cId,
        })) as any
      ).contactHistory[0].id,
    );

    const u = await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id name email }
      }`,
      { id: cId, p: [v1Id], i: { name: "Alice Johnson" } },
    );
    expect((u as any).updateContact.name).toBe("Alice Johnson");
    expect((u as any).updateContact.email).toBe("alice@example.com");

    const h = await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
      id: cId,
    });
    expect((h as any).contactHistory).toHaveLength(2);
  });

  test("parallel branch + merge produces 4 versions", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const cId = stripTable((d as any).createContact.id);
    const v1Id = stripTable(
      (
        (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
          id: cId,
        })) as any
      ).contactHistory[0].id,
    );

    // branch A: rename
    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v1Id], i: { name: "Alice Johnson" } },
    );

    // branch B: new email, also parented from v1
    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v1Id], i: { email: "alice.new@example.com" } },
    );

    const h3 = (
      (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
        id: cId,
      })) as any
    ).contactHistory as { id: string }[];
    expect(h3).toHaveLength(3);

    const v2Id = stripTable(h3[0].id);
    const v3Id = stripTable(h3[1].id);

    // merge
    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v2Id, v3Id], i: {} },
    );

    const h4 = await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
      id: cId,
    });
    expect((h4 as any).contactHistory).toHaveLength(4);
  });

  test("filter by name returns only matching versions", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const cId = stripTable((d as any).createContact.id);
    const v1Id = stripTable(
      (
        (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
          id: cId,
        })) as any
      ).contactHistory[0].id,
    );
    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v1Id], i: { name: "Alice Johnson" } },
    );

    const data = await gql(
      `query($id: ID!, $f: ContactVersionFilter) { contactHistory(id: $id, filter: $f) { id name } }`,
      { id: cId, f: { name: "Alice Johnson" } },
    );
    const hist = (data as any).contactHistory;
    expect(hist.length).toBeGreaterThan(0);
    for (const v of hist) expect(v.name).toBe("Alice Johnson");
  });

  test("filter by email returns only matching versions", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const cId = stripTable((d as any).createContact.id);
    const v1Id = stripTable(
      (
        (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
          id: cId,
        })) as any
      ).contactHistory[0].id,
    );
    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v1Id], i: { email: "alice.new@example.com" } },
    );

    const data = await gql(
      `query($id: ID!, $f: ContactVersionFilter) { contactHistory(id: $id, filter: $f) { id email } }`,
      { id: cId, f: { email: "alice.new@example.com" } },
    );
    const hist = (data as any).contactHistory;
    expect(hist.length).toBeGreaterThan(0);
    for (const v of hist) expect(v.email).toBe("alice.new@example.com");
  });

  test("before filter returns only versions created before the cutoff", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "Alice Smith", email: "alice@example.com" }) { id } }
    `);
    const cId = stripTable((d as any).createContact.id);
    const v1Id = stripTable(
      (
        (await gql(`query($id: ID!) { contactHistory(id: $id) { id } }`, {
          id: cId,
        })) as any
      ).contactHistory[0].id,
    );

    await new Promise((r) => setTimeout(r, 20));
    const afterV1 = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 5));

    await gql(
      `mutation($id: ID!, $p: [ID!]!, $i: UpdateContactInput!) {
        updateContact(id: $id, parentVersionIds: $p, input: $i) { id }
      }`,
      { id: cId, p: [v1Id], i: { name: "Alice Johnson" } },
    );

    const data = await gql(
      `query($id: ID!, $f: ContactVersionFilter) { contactHistory(id: $id, filter: $f) { id name } }`,
      { id: cId, f: { before: afterV1 } },
    );
    const hist = (data as any).contactHistory;
    expect(hist).toHaveLength(1);
    expect(hist[0].name).toBe("Alice Smith");
  });

  test("deleteContact removes contact", async () => {
    const d = await gql(`
      mutation { createContact(input: { name: "To Delete", email: "del@example.com" }) { id } }
    `);
    const id = stripTable((d as any).createContact.id);

    const del = await gql(`mutation($id: ID!) { deleteContact(id: $id) }`, {
      id,
    });
    expect((del as any).deleteContact).toBe(true);

    const get = await gql(`query($id: ID!) { contact(id: $id) { id } }`, {
      id,
    });
    expect((get as any).contact).toBeNull();
  });

  test("contacts lists all contacts for current user", async () => {
    await gql(
      `mutation { createContact(input: { name: "A", email: "a@x.com" }) { id } }`,
    );
    await gql(
      `mutation { createContact(input: { name: "B", email: "b@x.com" }) { id } }`,
    );

    const data = await gql(`query { contacts { id name } }`);
    expect((data as any).contacts).toHaveLength(2);
  });

  test("contacts does not return other users contacts", async () => {
    await gql(
      `mutation { createContact(input: { name: "A", email: "a@x.com" }) { id } }`,
    );

    currentUserId = "user:other";
    const data = await gql(`query { contacts { id name } }`);
    expect((data as any).contacts).toHaveLength(0);
  });
});
