package registry_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/handlers/registry"
	"github.com/neoworks/auth/registrycompat"
	"github.com/neoworks/auth/storage/database"
)

const songsPath = "/api/v1/schemas/example/songs"

type publishesResponse struct {
	Publishes []database.RegistryPublishAttempt `json:"publishes"`
}

type refusal struct {
	Error      string                     `json:"error"`
	Violations []registrycompat.Violation `json:"violations"`
}

func songsDescriptor(t *testing.T) *registrycompat.Descriptor {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "registrycompat", "testdata", "example-songs.descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := registrycompat.Parse(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

// withoutPlaylist is @example/songs 0.1.0, before 0.2.0 added the playlist container.
func withoutPlaylist(descriptor *registrycompat.Descriptor) *registrycompat.Descriptor {
	descriptor.Models = slices.DeleteFunc(descriptor.Models, func(model registrycompat.Model) bool { return model.Name == "Playlist" })
	descriptor.Nodes = slices.DeleteFunc(descriptor.Nodes, func(node registrycompat.Node) bool { return node.Kind == "container" })
	return descriptor
}

func descriptorText(t *testing.T, descriptor *registrycompat.Descriptor) string {
	t.Helper()
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func songsBody(t *testing.T, version string, descriptor *registrycompat.Descriptor) map[string]any {
	body := publishBody(version)
	body["title"] = "Songs"
	body["descriptor"] = descriptorText(t, descriptor)
	return body
}

func TestTheSongsHistoryPublishesAndIsListed(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	first := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.1.0", withoutPlaylist(songsDescriptor(t))), nil)
	second := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.2.0", songsDescriptor(t)), nil)
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("publishing the history: %d %s / %d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}

	var listed publishesResponse
	handlertest.Decode(t, f.router.Do(t, owner, "GET", songsPath+"/publishes", nil, nil), &listed)
	if len(listed.Publishes) != 2 || listed.Publishes[0].Version != "0.2.0" || listed.Publishes[1].Version != "0.1.0" {
		t.Fatalf("publishes should be newest first: %+v", listed.Publishes)
	}
	for _, attempt := range listed.Publishes {
		if !attempt.Accepted || len(attempt.Violations) != 0 || attempt.Actor.Kind != "user" || attempt.At.IsZero() {
			t.Fatalf("unexpected attempt: %+v", attempt)
		}
	}
}

func TestAnIncompatibleVersionIsRefusedWithItsViolationsAndRecorded(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.1.0", songsDescriptor(t)), nil)

	broken := songsDescriptor(t)
	broken.Models[1].Fields[1].Name = "performer"
	broken.Models[1].Fields[4].Value.Scalar = "u32"
	refused := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.2.0", broken), nil)
	if refused.Code != http.StatusConflict {
		t.Fatalf("incompatible publish: got %d want 409: %s", refused.Code, refused.Body.String())
	}
	var body refusal
	handlertest.Decode(t, refused, &body)
	rules := []string{}
	for _, violation := range body.Violations {
		rules = append(rules, violation.Rule)
	}
	slices.Sort(rules)
	if body.Error != "incompatible_schema" || !slices.Equal(rules, []string{"field_ordinal_reused", "field_type_changed"}) {
		t.Fatalf("unexpected refusal: %s", refused.Body.String())
	}

	var detail struct {
		Schema   database.RegistrySchema    `json:"schema"`
		Versions []database.RegistryVersion `json:"versions"`
	}
	handlertest.Decode(t, f.router.DoAnonymous(t, "GET", songsPath), &detail)
	if detail.Schema.LatestVersion != "0.1.0" || len(detail.Versions) != 1 {
		t.Fatalf("a refused version must not be stored: %+v", detail)
	}
	var listed publishesResponse
	handlertest.Decode(t, f.router.Do(t, owner, "GET", songsPath+"/publishes", nil, nil), &listed)
	if len(listed.Publishes) != 2 || listed.Publishes[0].Accepted || listed.Publishes[0].Version != "0.2.0" || len(listed.Publishes[0].Violations) != 2 {
		t.Fatalf("the refusal must be recorded with its violations: %+v", listed.Publishes)
	}

	fixed := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.2.0", songsDescriptor(t)), nil)
	if fixed.Code != http.StatusCreated {
		t.Fatalf("the corrected version must be accepted: %d %s", fixed.Code, fixed.Body.String())
	}
}

func TestEveryPublishedVersionIsCheckedNotOnlyTheLatest(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	withLegacy := songsDescriptor(t)
	withLegacy.Models[1].Fields = append(withLegacy.Models[1].Fields, registrycompat.Field{
		Ordinal: 8, Name: "legacy", Container: registrycompat.Container{Kind: "singular", Nullable: true},
		Value: registrycompat.Shape{Kind: "scalar", Scalar: "string"},
	})
	f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "1.0.0", withLegacy), nil)
	f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "1.1.0", songsDescriptor(t)), nil)

	reused := songsDescriptor(t)
	reused.Models[1].Fields = append(reused.Models[1].Fields, registrycompat.Field{
		Ordinal: 8, Name: "dueDate", Container: registrycompat.Container{Kind: "singular", Nullable: true},
		Value: registrycompat.Shape{Kind: "scalar", Scalar: "timestamp"},
	})
	refused := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "1.2.0", reused), nil)
	if refused.Code != http.StatusConflict || !strings.Contains(refused.Body.String(), "conflicts with version 1.0.0") {
		t.Fatalf("the number of a removed field was reused: %d %s", refused.Code, refused.Body.String())
	}
}

func TestRepublishingAVersionIsRecordedAsRefused(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.1.0", songsDescriptor(t)), nil)
	if again := f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.1.0", songsDescriptor(t)), nil); again.Code != http.StatusConflict {
		t.Fatalf("republish: got %d want 409", again.Code)
	}
	var listed publishesResponse
	handlertest.Decode(t, f.router.Do(t, owner, "GET", songsPath+"/publishes", nil, nil), &listed)
	if len(listed.Publishes) != 2 || listed.Publishes[0].Accepted || listed.Publishes[0].Violations[0].Rule != "version_exists" {
		t.Fatalf("unexpected publishes: %+v", listed.Publishes)
	}
}

func TestOnlyTheOwnerReadsThePublishesAndIntrudersLeaveNoTrace(t *testing.T) {
	f := newFixture(t)
	owner := handlertest.CreateUser(t, f.store, registry.PublishScope)
	intruder := handlertest.CreateUser(t, f.store, registry.PublishScope)
	f.router.Do(t, owner, "POST", songsPath+"/versions", songsBody(t, "0.1.0", songsDescriptor(t)), nil)

	if response := f.router.Do(t, intruder, "POST", songsPath+"/versions", songsBody(t, "0.2.0", songsDescriptor(t)), nil); response.Code != http.StatusForbidden {
		t.Fatalf("intruder publishing: got %d want 403", response.Code)
	}
	if response := f.router.Do(t, intruder, "GET", songsPath+"/publishes", nil, nil); response.Code != http.StatusForbidden {
		t.Fatalf("intruder reading the publishes: got %d want 403", response.Code)
	}
	if response := f.router.DoAnonymous(t, "GET", songsPath+"/publishes"); response.Code != http.StatusForbidden {
		t.Fatalf("anonymous reading the publishes: got %d want 403", response.Code)
	}
	if response := f.router.Do(t, owner, "GET", "/api/v1/schemas/example/missing/publishes", nil, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unknown schema: got %d want 404", response.Code)
	}
	var listed publishesResponse
	handlertest.Decode(t, f.router.Do(t, owner, "GET", songsPath+"/publishes", nil, nil), &listed)
	if len(listed.Publishes) != 1 {
		t.Fatalf("the intruder's attempt must not be recorded: %+v", listed.Publishes)
	}
}
