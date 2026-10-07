package database_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func facetContent(tags ...int) string {
	content := []byte{}
	for _, tag := range tags {
		content = append(content, dbtest.FacetField(tag, []byte("ciphertext"))...)
	}
	return base64.RawURLEncoding.EncodeToString(content)
}

func repeatedFacetContent() string {
	return facetContent(1, 1)
}

func validItem(author access.Principal) database.Node {
	parent := uuid.NewString()
	return newNode(author, author.UserID, "@neoworks/calendar", database.KindItem, &parent)
}

func TestValidateNodeInputRejectsMalformedNodes(t *testing.T) {
	owner := userPrincipal(uuid.NewString(), "@neoworks/calendar:write")
	installer := installPrincipal(owner.UserID, uuid.NewString(), "@neoworks/calendar:write")
	empty := ""
	selfParent := ""

	cases := map[string]func(node *database.Node) access.Principal{
		"bad id":              func(node *database.Node) access.Principal { node.ID = "not-a-uuid"; return owner },
		"bad collection":      func(node *database.Node) access.Principal { node.Collection = "mail"; return owner },
		"root with parent":    func(node *database.Node) access.Principal { node.Kind = database.KindRoot; return owner },
		"item without parent": func(node *database.Node) access.Principal { node.ParentID = nil; return owner },
		"own parent": func(node *database.Node) access.Principal {
			selfParent = node.ID
			node.ParentID = &selfParent
			return owner
		},
		"zero epoch":       func(node *database.Node) access.Principal { node.Epoch = 0; return owner },
		"negative baseSeq": func(node *database.Node) access.Principal { node.BaseSeq = -1; return owner },
		"no signature":     func(node *database.Node) access.Principal { node.Signature = ""; return owner },
		"missing key":      func(node *database.Node) access.Principal { node.WrappedKey = nil; return owner },
		"empty key":        func(node *database.Node) access.Principal { node.WrappedKey = &empty; return owner },
		"repeated facet": func(node *database.Node) access.Principal {
			node.Content = repeatedFacetContent()
			return owner
		},
		"unframed content": func(node *database.Node) access.Principal { node.Content = "AAEC"; return owner },
		"padded content":   func(node *database.Node) access.Principal { node.Content += "="; return owner },
		"facet tag zero":   func(node *database.Node) access.Principal { node.Content = facetContent(0); return owner },
		"root content": func(node *database.Node) access.Principal {
			node.Kind, node.ParentID, node.WrappedKey = database.KindRoot, nil, nil
			return owner
		},
		"shortcut with content": func(node *database.Node) access.Principal {
			target, role := uuid.NewString(), "read"
			node.TargetID, node.TargetRole = &target, &role
			return owner
		},
		"shortcut without role": func(node *database.Node) access.Principal {
			target := uuid.NewString()
			node.TargetID, node.Content = &target, ""
			return owner
		},
		"role without target": func(node *database.Node) access.Principal {
			role := "read"
			node.TargetRole = &role
			return owner
		},
		"foreign author":    func(node *database.Node) access.Principal { node.AuthorID = uuid.NewString(); return owner },
		"wrong author type": func(node *database.Node) access.Principal { node.AuthorType = "install"; return owner },
		"user with cert": func(node *database.Node) access.Principal {
			cert := uuid.NewString()
			node.CertID = &cert
			return owner
		},
		"install no cert": func(node *database.Node) access.Principal {
			node.AuthorType, node.AuthorID = "install", installer.InstallID
			return installer
		},
		"bad blob": func(node *database.Node) access.Principal {
			node.Blob = []byte(`{"objectId":"x","chunks":1,"size":1}`)
			return owner
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			node := validItem(owner)
			principal := mutate(&node)
			if _, err := database.ValidateNodeInput(node, principal); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestValidateNodeInputAcceptsBlobAndKeepsItCompact(t *testing.T) {
	owner := userPrincipal(uuid.NewString(), "@neoworks/files:write")
	node := validItem(owner)
	node.Collection = "@neoworks/files"
	objectID, variantID := uuid.NewString(), uuid.NewString()
	node.Blob = []byte(`{ "objectId": "` + objectID + `", "chunks": 2, "size": 100,
		"variants": [{"name": "thumb", "objectId": "` + variantID + `", "chunks": 1, "size": 10}] }`)

	validated, err := database.ValidateNodeInput(node, owner)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validated.BlobSize != 110 || len(validated.BlobObjects) != 2 {
		t.Fatalf("blob facts wrong: size %d objects %v", validated.BlobSize, validated.BlobObjects)
	}
	if strings.ContainsAny(*validated.BlobJSON, " \n\t") {
		t.Fatalf("stored blob JSON is not compact: %q", *validated.BlobJSON)
	}
}

func TestValidateNodeInputInstallAuthorNeedsCertificate(t *testing.T) {
	userID := uuid.NewString()
	installer := installPrincipal(userID, uuid.NewString(), "@neoworks/calendar:write")
	node := validItem(installer)
	cert := uuid.NewString()
	node.CertID = &cert
	if _, err := database.ValidateNodeInput(node, installer); err != nil {
		t.Fatalf("install author with cert should validate: %v", err)
	}
}

func TestValidateNodeInputAcceptsFramedContentShortcutsAndEmptyRoots(t *testing.T) {
	owner := userPrincipal(uuid.NewString(), "@neoworks/calendar:write")
	facets := validItem(owner)
	facets.Content = facetContent(1, 488337835)
	if _, err := database.ValidateNodeInput(facets, owner); err != nil {
		t.Fatalf("content with two facets should validate: %v", err)
	}

	shortcut := validItem(owner)
	target, role := uuid.NewString(), "write"
	shortcut.TargetID, shortcut.TargetRole, shortcut.Content = &target, &role, ""
	if _, err := database.ValidateNodeInput(shortcut, owner); err != nil {
		t.Fatalf("shortcut should validate: %v", err)
	}

	root := newNode(owner, owner.UserID, "@neoworks/calendar", database.KindRoot, nil)
	if _, err := database.ValidateNodeInput(root, owner); err != nil {
		t.Fatalf("root without content should validate: %v", err)
	}
}

func TestContentFacetTagsRejectsOverflowingVarints(t *testing.T) {
	overflowing := base64.RawURLEncoding.EncodeToString([]byte{0x8a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x01, 0x00})
	if _, err := database.ContentFacetTags(overflowing); err == nil {
		t.Fatal("a key varint wider than 64 bits must be rejected")
	}
	descending := base64.RawURLEncoding.EncodeToString(append(dbtest.FacetField(3, []byte("b")), dbtest.FacetField(2, []byte("a"))...))
	if _, err := database.ContentFacetTags(descending); err == nil {
		t.Fatal("facets out of tag order must be rejected")
	}
}
