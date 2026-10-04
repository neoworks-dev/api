package database_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/storage/database"
)

func validItem(author access.Principal) database.Node {
	parent := uuid.NewString()
	return newNode(author, author.UserID, "calendar", database.KindItem, &parent)
}

func TestValidateNodeInputRejectsMalformedNodes(t *testing.T) {
	owner := userPrincipal(uuid.NewString(), "calendar:write")
	installer := installPrincipal(owner.UserID, uuid.NewString(), "calendar:write")
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
		"duplicate facets": func(node *database.Node) access.Principal {
			node.Content = append(node.Content, node.Content[0])
			return owner
		},
		"empty ciphertext":  func(node *database.Node) access.Principal { node.Content[0].Ciphertext = ""; return owner },
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
	owner := userPrincipal(uuid.NewString(), "files:write")
	node := validItem(owner)
	node.Collection = "files"
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
	installer := installPrincipal(userID, uuid.NewString(), "calendar:write")
	node := validItem(installer)
	cert := uuid.NewString()
	node.CertID = &cert
	if _, err := database.ValidateNodeInput(node, installer); err != nil {
		t.Fatalf("install author with cert should validate: %v", err)
	}
}
