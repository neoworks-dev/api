package database

import (
	"strings"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func TestMediaListConditionsScope(t *testing.T) {
	user := models.NewRecordID("user", "u1")

	owned, ownedParams, err := mediaListConditions(user, false, nil)
	if err != nil {
		t.Fatalf("owned: %v", err)
	}
	// Owned scope is ownership + the thumbnail exclusion.
	if len(owned) != 2 || owned[0] != "user = $user" || owned[1] != "purpose != 'thumbnail'" {
		t.Fatalf("owned scope = %v, want [user = $user, purpose != 'thumbnail']", owned)
	}
	if ownedParams["user"] == nil {
		t.Fatalf("owned params missing $user")
	}

	shared, _, err := mediaListConditions(user, true, nil)
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	if len(shared) != 2 || !strings.Contains(shared[0], "media_grant WHERE recipient = $user") {
		t.Fatalf("shared scope = %v, want a media_grant subquery + thumbnail exclusion", shared)
	}
}

func TestMediaListConditionsFilter(t *testing.T) {
	user := models.NewRecordID("user", "u1")
	filter := &gql_model.MediaFilter{
		MimeType: &gql_model.StringFilter{StartsWith: strptr("image/")},
	}

	conditions, params, err := mediaListConditions(user, false, filter)
	if err != nil {
		t.Fatalf("filter compile: %v", err)
	}
	// ownership + thumbnail exclusion + the compiled filter expr.
	if len(conditions) != 3 {
		t.Fatalf("conditions = %v, want scope + thumbnail exclusion + filter", conditions)
	}
	if !strings.Contains(conditions[2], "mime_type") {
		t.Fatalf("filter expr %q does not reference mime_type", conditions[2])
	}
	if !hasValue(params, "image/") {
		t.Fatalf("params %v missing bound filter value", params)
	}
}

func TestMediaOrderByClause(t *testing.T) {
	def, err := mediaOrderByClause(nil)
	if err != nil || def != "ORDER BY created_at DESC" {
		t.Fatalf("default order = %q (err %v)", def, err)
	}

	desc := gql_model.SortDirectionDesc
	clause, err := mediaOrderByClause([]*gql_model.MediaSort{
		{Field: gql_model.MediaSortFieldFilename},
		{Field: gql_model.MediaSortFieldSize, Direction: &desc},
	})
	if err != nil {
		t.Fatalf("sort: %v", err)
	}
	if clause != "ORDER BY filename, size DESC" {
		t.Fatalf("order = %q", clause)
	}

	if _, err := mediaOrderByClause([]*gql_model.MediaSort{{Field: gql_model.MediaSortField("BOGUS")}}); err == nil {
		t.Fatalf("expected error for unsortable field")
	}
}

func hasValue(params map[string]any, want string) bool {
	for _, v := range params {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
