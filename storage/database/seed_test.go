package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/registrycompat"
	"github.com/neoworks/auth/storage/database"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func TestFirstPartyClientsAreSeeded(t *testing.T) {
	f := newFixture(t)
	wanted := map[string][]string{
		"neoworks-calendar":      {"@neoworks/calendar:read", "@neoworks/calendar:write", "@neoworks/calendar:share"},
		"neoworks-contacts":      {"@neoworks/contacts:read", "@neoworks/contacts:write", "@neoworks/contacts:share"},
		"neoworks-photos":        {"@neoworks/photos:read", "@neoworks/photos:write", "@neoworks/photos:share"},
		"neoworks-authenticator": {"openid"},
		"openschema":             {"openid", "schemas:publish"},
	}
	for clientID, scopes := range wanted {
		client, err := f.store.GetClient(context.Background(), clientID)
		if err != nil {
			t.Fatalf("client %s: %v", clientID, err)
		}
		if !client.Public || !client.FirstParty || len(client.RedirectURIs) == 0 {
			t.Errorf("client %s is not a usable public client: %+v", clientID, client)
		}
		for _, scope := range scopes {
			if !slices.Contains(client.Scopes, scope) {
				t.Errorf("client %s lacks scope %s", clientID, scope)
			}
		}
	}
}

func TestTheFilesClientIsNotSeeded(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.GetClient(context.Background(), "neoworks-files")
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("neoworks-files must not be seeded, got %v", err)
	}
}

func TestTheExampleSongsClientIsThirdParty(t *testing.T) {
	f := newFixture(t)
	client, err := f.store.GetClient(context.Background(), "example-songs")
	if err != nil {
		t.Fatal(err)
	}
	if client.FirstParty {
		t.Fatal("example-songs must be a third-party client")
	}
}

func TestFirstPartyCannotBeChangedAfterTheClientExists(t *testing.T) {
	f := newFixture(t)
	results, err := surrealdb.Query[any](context.Background(), f.store.DB,
		"UPDATE $id SET first_party = true", map[string]any{"id": models.NewRecordID("client", "example-songs")})
	if err == nil && len(*results) > 0 && (*results)[0].Error == nil {
		t.Fatal("updating first_party on an existing client must fail")
	}
	client, err := f.store.GetClient(context.Background(), "example-songs")
	if err != nil || client.FirstParty {
		t.Fatalf("example-songs must stay third-party: %+v %v", client, err)
	}
}

func TestTheNeoworksCollectionSchemasAreSeededWithTheirDescriptors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	owner, err := f.store.GetOwner(ctx, "neoworks")
	if err != nil || owner.Kind != database.OwnerKindOrganization {
		t.Fatalf("the neoworks scope belongs to the Neoworks organization: %+v %v", owner, err)
	}
	for _, name := range []string{"calendar", "contacts", "photos", "google"} {
		schema, err := f.store.GetRegistrySchema(ctx, "neoworks", name)
		if err != nil {
			t.Fatalf("@neoworks/%s is not seeded: %v", name, err)
		}
		version, err := f.store.GetRegistryVersion(ctx, "neoworks", name, schema.LatestVersion)
		if err != nil {
			t.Fatalf("@neoworks/%s %s: %v", name, schema.LatestVersion, err)
		}
		if len(version.Files) == 0 || version.DescriptorHash == "" {
			t.Fatalf("@neoworks/%s must carry its sources and descriptor: %+v", name, version)
		}
		descriptor, err := f.store.GetRegistryDescriptor(ctx, "neoworks", name, version.DescriptorHash)
		if err != nil {
			t.Fatalf("@neoworks/%s descriptor: %v", name, err)
		}
		if database.DescriptorHash([]byte(descriptor)) != version.DescriptorHash {
			t.Errorf("@neoworks/%s: the stored hash is not the hash of the stored descriptor", name)
		}
		if _, err := registrycompat.Parse(descriptor); err != nil {
			t.Errorf("@neoworks/%s: the seeded descriptor does not parse: %v", name, err)
		}
	}
}

func TestANewVersionOfASeededSchemaIsCheckedAgainstTheSeed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	staff := f.createUser()
	if err := f.store.AddMember(ctx, "neoworks", staff.UserID, []ownership.Grant{ownership.OrganizationWide(ownership.SchemasPublish)}); err != nil {
		t.Fatal(err)
	}
	schema, err := f.store.GetRegistrySchema(ctx, "neoworks", "photos")
	if err != nil {
		t.Fatal(err)
	}
	version, err := f.store.GetRegistryVersion(ctx, "neoworks", "photos", schema.LatestVersion)
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := f.store.GetRegistryDescriptor(ctx, "neoworks", "photos", version.DescriptorHash)
	if err != nil {
		t.Fatal(err)
	}
	input := database.RegistryPublishInput{
		Scope: "neoworks", Name: "photos", Version: "0.1.1", Title: "Photos", Description: "Photos",
		Files: []database.RegistryPublishFile{{Path: "photos.schema", Contents: "x"}}, Descriptor: seeded,
	}
	if _, err := f.store.PublishRegistryVersion(ctx, staff.UserID, input); err != nil {
		t.Fatalf("the seeded descriptor is compatible with itself: %v", err)
	}
	input.Version = "0.1.2"
	input.Descriptor = `{"descriptorVersion":1,"namespace":"neoworks.photos"}`
	var incompatible *database.IncompatibleSchemaError
	if _, err := f.store.PublishRegistryVersion(ctx, staff.UserID, input); !errors.As(err, &incompatible) {
		t.Fatalf("a version that drops the seeded models is refused: %v", err)
	}
}
