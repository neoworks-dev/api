package database

import (
	"context"
	"testing"

	gql_model "github.com/neoworks/auth/gql/model"
	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// TestContactLifecycle covers create → list → update → trash/restore → history
// against the vCard schema, guarding the id round-trip and version lineage.
func TestContactLifecycle(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()

	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")

	suffix := randSuffix()
	uID := "contact_owner_" + suffix
	owner := models.NewRecordID("user", uID)

	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name = 'Owner', last_name = 'O', email = $e, password_hash = 'x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})

	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user = $u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	uid := "uid-" + suffix
	fn := "Ada Lovelace"
	created, err := store.Contacts.Create(ctx, &CreateContactParams{
		UserID: owner,
		Fields: ContactFields{
			UID:           &uid,
			FormattedName: &fn,
			Emails:        []FieldData{{Value: "ada@analytical.engine", Types: []string{"work"}}},
			Phones:        []FieldData{{Value: "+44 20 0000"}},
		},
	})
	if err != nil {
		t.Fatalf("create contact: %v", err)
	}
	if created.ID == "" || created.FormattedName != fn || created.UID != uid {
		t.Fatalf("unexpected created contact: %+v", created)
	}
	if len(created.Emails) != 1 || created.Emails[0].Value != "ada@analytical.engine" {
		t.Fatalf("emails did not round-trip: %+v", created.Emails)
	}
	if created.Favorite || created.Deleted || created.Kind != "individual" {
		t.Fatalf("unexpected defaults: %+v", created)
	}

	list, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 50, 0)
	if err != nil || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("active list mismatch: %+v (err %v)", list, err)
	}

	// Update derives from the current head version.
	versions, err := store.Contacts.ListVersions(ctx, &ListVersionsParams{ContactID: models.NewRecordID("contact", created.ID)})
	if err != nil || len(versions) != 1 {
		t.Fatalf("expected one version, got %+v (err %v)", versions, err)
	}
	parent := models.NewRecordID("contact_version", versions[0].ID)
	newName := "Ada King"
	updated, err := store.Contacts.Update(ctx, &UpdateContactParams{
		ID:               models.NewRecordID("contact", created.ID),
		UserID:           owner,
		ParentVersionIDs: []models.RecordID{parent},
		Fields:           ContactFields{FormattedName: &newName},
	})
	if err != nil {
		t.Fatalf("update contact: %v", err)
	}
	if updated.FormattedName != "Ada King" || len(updated.Emails) != 1 {
		t.Fatalf("update should change name and keep emails: %+v", updated)
	}

	// Trash removes it from the active scope and shows it in trashed.
	if _, err := store.Contacts.Trash(ctx, models.NewRecordID("contact", created.ID), owner); err != nil {
		t.Fatalf("trash: %v", err)
	}
	active, _ := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 50, 0)
	if len(active) != 0 {
		t.Fatalf("trashed contact should not be active, got %d", len(active))
	}
	trashed, _ := store.Contacts.List(ctx, owner, gql_model.ContactScopeTrashed, nil, nil, nil, nil, 50, 0)
	if len(trashed) != 1 {
		t.Fatalf("expected one trashed contact, got %d", len(trashed))
	}

	if _, err := store.Contacts.Restore(ctx, models.NewRecordID("contact", created.ID), owner); err != nil {
		t.Fatalf("restore: %v", err)
	}
	active, _ = store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 50, 0)
	if len(active) != 1 {
		t.Fatalf("restored contact should be active again, got %d", len(active))
	}

	history, err := store.Contacts.ListVersions(ctx, &ListVersionsParams{ContactID: models.NewRecordID("contact", created.ID)})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	// create + rename + trash + restore = 4 versions, newest first.
	if len(history) != 4 || history[0].Deleted {
		t.Fatalf("expected 4 versions newest-first (restored), got %d: %+v", len(history), history)
	}
}

// TestContactVersionBranching covers restoring (forking from) an old version:
// parent_ids must be populated and the source version must gain a second child.
func TestContactVersionBranching(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "branch_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE derived_from", map[string]any{})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	uid := "branch-" + suffix
	v1Name := "Name One"
	created, err := store.Contacts.Create(ctx, &CreateContactParams{
		UserID: owner,
		Fields: ContactFields{UID: &uid, FormattedName: &v1Name},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	contactID := models.NewRecordID("contact", created.ID)

	head := func() models.RecordID {
		vs, err := store.Contacts.ListVersions(ctx, &ListVersionsParams{ContactID: contactID})
		if err != nil || len(vs) == 0 {
			t.Fatalf("list versions: %+v err=%v", vs, err)
		}
		return models.NewRecordID("contact_version", vs[0].ID)
	}

	v1 := head()
	name2 := "Name Two"
	if _, err := store.Contacts.Update(ctx, &UpdateContactParams{ID: contactID, UserID: owner, ParentVersionIDs: []models.RecordID{v1}, Fields: ContactFields{FormattedName: &name2}}); err != nil {
		t.Fatalf("update 2: %v", err)
	}
	name3 := "Name Three"
	if _, err := store.Contacts.Update(ctx, &UpdateContactParams{ID: contactID, UserID: owner, ParentVersionIDs: []models.RecordID{head()}, Fields: ContactFields{FormattedName: &name3}}); err != nil {
		t.Fatalf("update 3: %v", err)
	}

	// Fork from v1: a new head copying its content, parent = v1.
	forked, err := store.Contacts.RestoreVersion(ctx, contactID, v1, owner)
	if err != nil {
		t.Fatalf("restore version: %v", err)
	}
	if forked.FormattedName != v1Name {
		t.Fatalf("fork should copy v1 name %q, got %q", v1Name, forked.FormattedName)
	}

	versions, err := store.Contacts.ListVersions(ctx, &ListVersionsParams{ContactID: contactID})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(versions) != 4 {
		t.Fatalf("expected 4 versions, got %d", len(versions))
	}
	if versions[0].FormattedName != v1Name {
		t.Fatalf("newest version should be the fork (%q), got %q", v1Name, versions[0].FormattedName)
	}

	// v1 must now have two children (the linear v2 and the fork) → a real branch.
	childrenOfV1 := 0
	parentsSeen := false
	for _, v := range versions {
		if len(v.ParentIds) > 0 {
			parentsSeen = true
		}
		for _, pid := range v.ParentIds {
			if pid == v1.ID.(string) {
				childrenOfV1++
			}
		}
	}
	if !parentsSeen {
		t.Fatalf("parent_ids never populated: %+v", versions)
	}
	if childrenOfV1 != 2 {
		t.Fatalf("v1 should have 2 children after fork, got %d", childrenOfV1)
	}
}

// TestContactSearchAndPaging covers server-side search (name/email/phone) and
// the offset/limit window used by the infinite-scroll list.
func TestContactSearchAndPaging(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "search_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	mk := func(name, email, phone string) {
		fn, e, p := name, email, phone
		uid := name + "-" + suffix
		_, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: ContactFields{
			UID: &uid, FormattedName: &fn,
			Emails: []FieldData{{Value: e}}, Phones: []FieldData{{Value: p}},
		}})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("Ada Lovelace", "ada@analytical.engine", "+44 20 1111")
	mk("Bob Jones", "bob@example.com", "+1 555 2222")
	mk("Charlie Brown", "charlie@peanuts.test", "+1 555 3333")

	strptr := func(s string) *string { return &s }

	cases := []struct {
		needle string
		want   int
	}{
		{"lovelace", 1},   // by name
		{"bob@example", 1}, // by email
		{"555", 2},         // phone substring shared by Bob and Charlie
		{"a", 3},           // every name contains 'a' (Ada, Charlie, ... ) — broad match
		{"zzznope", 0},     // no match
	}
	for _, tc := range cases {
		got, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, strptr(tc.needle), nil, nil, 50, 0)
		if err != nil {
			t.Fatalf("search %q: %v", tc.needle, err)
		}
		if len(got) != tc.want {
			names := make([]string, len(got))
			for i, c := range got {
				names[i] = c.FormattedName
			}
			t.Fatalf("search %q: want %d, got %d (%v)", tc.needle, tc.want, len(got), names)
		}
	}

	// Pagination window: 3 contacts, batches of 2 → page0=2, page1=1, page2=0.
	page0, _ := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 2, 0)
	page1, _ := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 2, 2)
	page2, _ := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, nil, 2, 4)
	if len(page0) != 2 || len(page1) != 1 || len(page2) != 0 {
		t.Fatalf("paging window wrong: %d/%d/%d", len(page0), len(page1), len(page2))
	}
	// Ordered by formatted_name, so the pages are disjoint and sequential.
	if page0[0].FormattedName != "Ada Lovelace" || page1[0].FormattedName != "Charlie Brown" {
		t.Fatalf("unexpected page order: %q … %q", page0[0].FormattedName, page1[0].FormattedName)
	}
}

// TestContactFilter exercises the ContactFilter → SurrealQL compiler: scalar
// string ops, repeatable-field any/isEmpty matches, bool equality and and/or/not.
func TestContactFilter(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "filter_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	mk := func(name, email, phone string, fav bool) {
		fn, f := name, fav
		uid := name + "-" + suffix
		fields := ContactFields{UID: &uid, FormattedName: &fn, Favorite: &f}
		if email != "" {
			fields.Emails = []FieldData{{Value: email, Types: []string{"work"}}}
		}
		if phone != "" {
			fields.Phones = []FieldData{{Value: phone}}
		}
		if _, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: fields}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("Ada Lovelace", "ada@analytical.engine", "+44 20 1111", true)
	mk("Bob Jones", "bob@example.com", "", false)        // no phone
	mk("Charlie Brown", "charlie@example.com", "+1 555 3", true)

	str := func(s string) *string { return &s }
	bl := func(b bool) *bool { return &b }

	run := func(name string, f *gql_model.ContactFilter, want int) {
		got, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, f, nil, 50, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != want {
			names := make([]string, len(got))
			for i, c := range got {
				names[i] = c.FormattedName
			}
			t.Fatalf("%s: want %d, got %d (%v)", name, want, len(got), names)
		}
	}

	// Email substring on any element.
	run("email contains example", &gql_model.ContactFilter{
		Emails: &gql_model.FieldListFilter{Any: &gql_model.ContactFieldFilter{Value: &gql_model.StringFilter{Contains: str("example")}}},
	}, 2)

	// Has no phone (isEmpty true) → only Bob.
	run("no phone", &gql_model.ContactFilter{
		Phones: &gql_model.FieldListFilter{IsEmpty: bl(true)},
	}, 1)

	// Has a phone (isEmpty false) → Ada + Charlie.
	run("has phone", &gql_model.ContactFilter{
		Phones: &gql_model.FieldListFilter{IsEmpty: bl(false)},
	}, 2)

	// favorite = true AND has a phone → Ada + Charlie.
	run("favorite and phone", &gql_model.ContactFilter{
		Favorite: &gql_model.BoolFilter{Eq: bl(true)},
		Phones:   &gql_model.FieldListFilter{IsEmpty: bl(false)},
	}, 2)

	// name startsWith "ada" OR favorite=false → Ada, Bob.
	run("name or not-favorite", &gql_model.ContactFilter{
		Or: []*gql_model.ContactFilter{
			{FormattedName: &gql_model.StringFilter{StartsWith: str("ada")}},
			{Favorite: &gql_model.BoolFilter{Eq: bl(false)}},
		},
	}, 2)

	// NOT (favorite = true) → only Bob.
	run("not favorite", &gql_model.ContactFilter{
		Not: &gql_model.ContactFilter{Favorite: &gql_model.BoolFilter{Eq: bl(true)}},
	}, 1)

	// email type membership.
	run("email type work", &gql_model.ContactFilter{
		Emails: &gql_model.FieldListFilter{Any: &gql_model.ContactFieldFilter{Type: str("work")}},
	}, 3)
}

// TestContactSort covers the sort argument: ascending/descending and the default
// (formatted_name asc) plus multi-key ordering.
func TestContactSort(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "filter_sort_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	mk := func(name, birthday string) {
		fn, bd := name, birthday
		uid := name + "-" + suffix
		fields := ContactFields{UID: &uid, FormattedName: &fn, Birthday: &bd}
		if _, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: fields}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("Charlie", "1990-01-01")
	mk("Ada", "1815-12-10")
	mk("Bob", "1970-05-05")

	names := func(sort []*gql_model.ContactSort) []string {
		got, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil, sort, 50, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		out := make([]string, len(got))
		for i, c := range got {
			out[i] = c.FormattedName
		}
		return out
	}
	equal := func(label string, got, want []string) {
		if len(got) != len(want) {
			t.Fatalf("%s: want %v, got %v", label, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: want %v, got %v", label, want, got)
			}
		}
	}

	desc := gql_model.SortDirectionDesc

	// Default (no sort) → formatted_name ascending.
	equal("default", names(nil), []string{"Ada", "Bob", "Charlie"})

	// Birthday ascending → Ada (1815), Bob (1970), Charlie (1990).
	equal("birthday asc", names([]*gql_model.ContactSort{
		{Field: gql_model.ContactSortFieldBirthday},
	}), []string{"Ada", "Bob", "Charlie"})

	// formatted_name descending.
	equal("name desc", names([]*gql_model.ContactSort{
		{Field: gql_model.ContactSortFieldFormattedName, Direction: &desc},
	}), []string{"Charlie", "Bob", "Ada"})
}

// TestContactGeoFilter covers GeoFilter: near (radius), within (GeoJSON polygon)
// and isNull, against contacts whose GEO point is stored as {lat, lng}.
func TestContactGeoFilter(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "filter_geo_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	mk := func(name string, geo *GeoData) {
		fn := name
		uid := name + "-" + suffix
		fields := ContactFields{UID: &uid, FormattedName: &fn, Geo: geo}
		if _, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: fields}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("Berlin Bob", &GeoData{Lat: 52.52, Lng: 13.405})  // Berlin
	mk("Munich Mary", &GeoData{Lat: 48.137, Lng: 11.575}) // ~500 km away
	mk("Nowhere Ned", nil)                                // no geo

	run := func(name string, f *gql_model.ContactFilter, want int) {
		got, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, f, nil, 50, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != want {
			names := make([]string, len(got))
			for i, c := range got {
				names[i] = c.FormattedName
			}
			t.Fatalf("%s: want %d, got %d (%v)", name, want, len(got), names)
		}
	}

	// Within 50 km of Berlin → only Berlin Bob.
	run("near Berlin 50km", &gql_model.ContactFilter{
		Geo: &gql_model.GeoFilter{Near: &gql_model.NearInput{Lat: 52.52, Lng: 13.405, RadiusMeters: 50000}},
	}, 1)

	// A wide radius covers both points (but not the geo-less contact).
	run("near Berlin 1000km", &gql_model.ContactFilter{
		Geo: &gql_model.GeoFilter{Near: &gql_model.NearInput{Lat: 52.52, Lng: 13.405, RadiusMeters: 1_000_000}},
	}, 2)

	// Inside a polygon around Berlin → only Berlin Bob. Coordinates are [lng, lat].
	berlinBox := map[string]any{
		"type": "Polygon",
		"coordinates": []any{[]any{
			[]any{13.0, 52.0}, []any{14.0, 52.0}, []any{14.0, 53.0}, []any{13.0, 53.0}, []any{13.0, 52.0},
		}},
	}
	run("within Berlin box", &gql_model.ContactFilter{
		Geo: &gql_model.GeoFilter{Within: berlinBox},
	}, 1)

	// isNull true → only the geo-less contact.
	tru := true
	run("geo isNull", &gql_model.ContactFilter{Geo: &gql_model.GeoFilter{IsNull: &tru}}, 1)

	// isNull false → both contacts that have a point.
	fls := false
	run("geo not null", &gql_model.ContactFilter{Geo: &gql_model.GeoFilter{IsNull: &fls}}, 2)
}

// TestContactFilterExtended covers the increment-1 operators: endsWith, matches,
// StringListFilter (categories), DateFilter (withinLast), scalar title, and Count.
func TestContactFilterExtended(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "filter_ext_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})

	mk := func(name, email, title string, categories []string) {
		fn, tt := name, title
		uid := name + "-" + suffix
		fields := ContactFields{UID: &uid, FormattedName: &fn, Title: &tt, Categories: categories}
		if email != "" {
			fields.Emails = []FieldData{{Value: email, Types: []string{"work"}}}
		}
		if _, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: fields}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("Ada Lovelace", "ada@analytical.engine", "Engineer", []string{"friend", "vip"})
	mk("Bob Jones", "bob@example.com", "Engineer", []string{"work"})
	mk("Charlie Brown", "charlie@example.org", "Manager", []string{"friend"})

	str := func(s string) *string { return &s }

	run := func(name string, f *gql_model.ContactFilter, want int) {
		got, err := store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil, f, nil, 50, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != want {
			names := make([]string, len(got))
			for i, c := range got {
				names[i] = c.FormattedName
			}
			t.Fatalf("%s: want %d, got %d (%v)", name, want, len(got), names)
		}
	}

	// endsWith on an email element.
	run("email endsWith .com", &gql_model.ContactFilter{
		Emails: &gql_model.FieldListFilter{Any: &gql_model.ContactFieldFilter{Value: &gql_model.StringFilter{EndsWith: str(".com")}}},
	}, 1)

	// matches regex on formatted_name (starts with A or C).
	run("name matches ^[AC]", &gql_model.ContactFilter{
		FormattedName: &gql_model.StringFilter{Matches: str("^[AC]")},
	}, 2)

	// scalar title eq.
	run("title Engineer", &gql_model.ContactFilter{
		Title: &gql_model.StringFilter{Eq: str("Engineer")},
	}, 2)

	// full-text search on formatted_name (snowball-stemmed) → Ada.
	run("search lovelace", &gql_model.ContactFilter{
		FormattedName: &gql_model.StringFilter{Search: str("lovelace")},
	}, 1)

	// fuzzy match tolerates the typo "lovlace" → Ada.
	run("fuzzy lovlace", &gql_model.ContactFilter{
		FormattedName: &gql_model.StringFilter{Fuzzy: str("ada lovlace")},
	}, 1)

	// categories hasAll → only Ada has both.
	run("categories hasAll friend+vip", &gql_model.ContactFilter{
		Categories: &gql_model.StringListFilter{HasAll: []string{"friend", "vip"}},
	}, 1)

	// categories hasAny friend → Ada + Charlie.
	run("categories hasAny friend", &gql_model.ContactFilter{
		Categories: &gql_model.StringListFilter{HasAny: []string{"friend"}},
	}, 2)

	// categories contains substring "frien" → Ada + Charlie.
	run("categories contains frien", &gql_model.ContactFilter{
		Categories: &gql_model.StringListFilter{Contains: str("frien")},
	}, 2)

	// categories size = 2 → only Ada.
	run("categories size 2", &gql_model.ContactFilter{
		Categories: &gql_model.StringListFilter{Size: &gql_model.IntFilter{Eq: intptr(2)}},
	}, 1)

	// created_at withinLast covers everything just created.
	run("created withinLast 1h", &gql_model.ContactFilter{
		CreatedAt: &gql_model.DateFilter{WithinLast: str("1h")},
	}, 3)

	// Count mirrors List under the same filter.
	count, err := store.Contacts.Count(ctx, owner, gql_model.ContactScopeActive, nil, nil,
		&gql_model.ContactFilter{Title: &gql_model.StringFilter{Eq: str("Engineer")}})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("count title Engineer: want 2, got %d", count)
	}

	// Count with no filter = all 3 active.
	allCount, err := store.Contacts.Count(ctx, owner, gql_model.ContactScopeActive, nil, nil, nil)
	if err != nil {
		t.Fatalf("count all: %v", err)
	}
	if allCount != 3 {
		t.Fatalf("count all: want 3, got %d", allCount)
	}

	// Invalid duration is rejected by the compiler.
	_, err = store.Contacts.List(ctx, owner, gql_model.ContactScopeActive, nil, nil,
		&gql_model.ContactFilter{CreatedAt: &gql_model.DateFilter{WithinLast: str("30 days")}}, nil, 50, 0)
	if err == nil {
		t.Fatalf("expected error for invalid withinLast duration")
	}
}

func TestContactRelations(t *testing.T) {
	url, user, pass, ns := testEnv()
	ctx := context.Background()
	store, err := NewSurrealStore(url, user, pass, ns, "auth")
	if err != nil {
		t.Skipf("surreal not reachable: %v", err)
	}
	root := rootConn(t, url, user, pass, ns, "auth")
	suffix := randSuffix()
	uID := "rel_owner_" + suffix
	owner := models.NewRecordID("user", uID)
	mustQuery(t, root, "CREATE type::record('user', $id) SET first_name='O', last_name='O', email=$e, password_hash='x'",
		map[string]any{"id": uID, "e": uID + "@test.local"})
	t.Cleanup(func() {
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE related WHERE in.user=$u OR out.user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE contact_version WHERE user=$u", map[string]any{"u": owner})
		_, _ = surrealdb.Query[[]any](ctx, root, "DELETE $u", map[string]any{"u": owner})
	})
	mk := func(name string) string {
		fn := name
		uid := name + "-" + suffix
		c, err := store.Contacts.Create(ctx, &CreateContactParams{UserID: owner, Fields: ContactFields{UID: &uid, FormattedName: &fn}})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return c.ID
	}
	a, b := mk("Alice"), mk("Bob")
	ar := models.NewRecordID("contact", a)
	br := models.NewRecordID("contact", b)

	ok, err := store.Contacts.Relate(ctx, owner, ar, br, []string{"friend"}, nil)
	if err != nil || !ok {
		t.Fatalf("relate: ok=%v err=%v", ok, err)
	}
	full, err := store.Contacts.Get(ctx, ar, owner)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(full.Related) != 1 || full.Related[0].ContactID != b || full.Related[0].Types[0] != "friend" {
		t.Fatalf("expected one friend relation to %s, got %+v", b, full.Related)
	}
	if _, err := store.Contacts.Unrelate(ctx, owner, ar, br); err != nil {
		t.Fatalf("unrelate: %v", err)
	}
	full, _ = store.Contacts.Get(ctx, ar, owner)
	if len(full.Related) != 0 {
		t.Fatalf("expected no relations after unrelate, got %+v", full.Related)
	}
}
