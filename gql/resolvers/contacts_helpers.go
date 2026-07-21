package gql

import (
	"crypto/rand"
	"encoding/hex"

	gql_model "github.com/neoworks/auth/gql/model"
	"github.com/neoworks/auth/storage/database"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Conversion helpers between the generated GraphQL inputs and the database layer.
// Kept out of Contacts.resolvers.go, which gqlgen regenerates.

func newContactUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func fileRef(id *string) *models.RecordID {
	if id == nil {
		return nil
	}
	r := models.NewRecordID("file", *id)
	return &r
}

func fieldsIn(in []*gql_model.ContactFieldInput) []database.FieldData {
	if in == nil {
		return nil
	}
	out := make([]database.FieldData, len(in))
	for i, f := range in {
		out[i] = database.FieldData{Value: f.Value, Types: f.Types, Pref: f.Pref, Label: f.Label}
	}
	return out
}

func nameIn(in *gql_model.NameInput) *database.NameData {
	if in == nil {
		return nil
	}
	return &database.NameData{Family: in.Family, Given: in.Given, Additional: in.Additional, Prefixes: in.Prefixes, Suffixes: in.Suffixes}
}

func genderIn(in *gql_model.GenderInput) *database.GenderData {
	if in == nil {
		return nil
	}
	return &database.GenderData{Sex: in.Sex, Identity: in.Identity}
}

func geoIn(in *gql_model.GeoInput) *database.GeoData {
	if in == nil {
		return nil
	}
	return &database.GeoData{Lat: in.Lat, Lng: in.Lng}
}

func addressesIn(in []*gql_model.AddressInput) []database.AddressData {
	if in == nil {
		return nil
	}
	out := make([]database.AddressData, len(in))
	for i, a := range in {
		out[i] = database.AddressData{
			Types: a.Types, Pref: a.Pref, Label: a.Label, PoBox: a.PoBox, Ext: a.Ext,
			Street: a.Street, Locality: a.Locality, Region: a.Region, PostalCode: a.PostalCode, Country: a.Country,
		}
	}
	return out
}

func orgsIn(in []*gql_model.ContactOrganizationInput) []database.OrgData {
	if in == nil {
		return nil
	}
	out := make([]database.OrgData, len(in))
	for i, o := range in {
		out[i] = database.OrgData{Name: o.Name, Units: o.Units}
	}
	return out
}

func customFieldsIn(in []*gql_model.CustomFieldInput) []database.CustomFieldData {
	if in == nil {
		return nil
	}
	out := make([]database.CustomFieldData, len(in))
	for i, c := range in {
		out[i] = database.CustomFieldData{Label: c.Label, Value: c.Value}
	}
	return out
}
