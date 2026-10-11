package apps_test

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"

	"github.com/neoworks/auth/access"
	"github.com/neoworks/auth/applogo"
	"github.com/neoworks/auth/handlers/apps"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

// memoryObjects is the object storage logos go to.
type memoryObjects map[string][]byte

func (objects memoryObjects) PutObject(_ context.Context, key string, data []byte, _ string) error {
	objects[key] = data
	return nil
}

func (objects memoryObjects) RemovePrefix(_ context.Context, prefix string) error {
	delete(objects, prefix)
	return nil
}

func quarterPNG(t *testing.T, leftColumns int) []byte {
	t.Helper()
	picture := image.NewRGBA(image.Rect(0, 0, 128, 128))
	for y := 0; y < 128; y++ {
		for x := 0; x < 128; x++ {
			if x < leftColumns {
				picture.Set(x, y, color.Black)
			} else {
				picture.Set(x, y, color.White)
			}
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, picture); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func newLogoFixture(t *testing.T) (*fixture, memoryObjects) {
	objects := memoryObjects{}
	return newFixtureWith(t, func(handler *apps.Handler) { handler.WithLogoStorage(objects) }), objects
}

func (f *fixture) putLogo(principal access.Principal, clientID string, body []byte, status int) map[string]any {
	f.t.Helper()
	response := f.router.DoBytes(f.t, principal, "PUT", "/api/v1/apps/"+clientID+"/logo", body, "application/octet-stream")
	if response.Code != status {
		f.t.Fatalf("put logo: got %d want %d: %s", response.Code, status, response.Body.String())
	}
	decoded := map[string]any{}
	if response.Body.Len() > 0 {
		handlertest.Decode(f.t, response, &decoded)
	}
	return decoded
}

func TestALogoIsStoredAsAnAssetAndReplacedOnReupload(t *testing.T) {
	f, objects := newLogoFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)

	first := f.putLogo(owner, clientID, quarterPNG(t, 32), http.StatusOK)
	url, _ := first["logoUrl"].(string)
	if !strings.Contains(url, "/assets/") || first["held"] != false || len(objects) != 1 {
		t.Fatalf("first upload: %v, %d objects", first, len(objects))
	}
	app := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	if app["logoUrl"] != url {
		t.Fatalf("app logoUrl %v want %s", app["logoUrl"], url)
	}

	f.putLogo(owner, clientID, quarterPNG(t, 96), http.StatusOK)
	if len(objects) != 1 {
		t.Fatalf("the replaced logo is deleted: %d objects", len(objects))
	}
	f.expect(owner, "DELETE", "/api/v1/apps/"+clientID+"/logo", nil, http.StatusNoContent, "")
	app = f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	if app["logoUrl"] != nil || len(objects) != 0 {
		t.Fatalf("after delete: %v, %d objects", app["logoUrl"], len(objects))
	}
}

func TestLogosAreSanitizedOrRefused(t *testing.T) {
	f, objects := newLogoFixture(t)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)

	hostile := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><script>alert(1)</script></svg>`
	response := f.putLogo(owner, clientID, []byte(hostile), http.StatusBadRequest)
	if response["error"] != "invalid_request" || response["field"] != "logo" {
		t.Fatalf("hostile svg: %v", response)
	}
	f.putLogo(owner, clientID, []byte("not an image"), http.StatusBadRequest)
	f.putLogo(owner, clientID, nil, http.StatusBadRequest)
	if len(objects) != 0 {
		t.Fatalf("nothing stored for refused logos: %d", len(objects))
	}

	clean := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)"><circle r="4" onclick="x()"/></svg>`
	f.putLogo(owner, clientID, []byte(clean), http.StatusOK)
	for _, stored := range objects {
		if strings.Contains(string(stored), "onload") || strings.Contains(string(stored), "onclick") {
			t.Fatalf("stored svg kept a handler: %s", stored)
		}
	}
}

func TestUploadingALogoNeedsAppsEdit(t *testing.T) {
	f, _ := newLogoFixture(t)
	leader := f.userWithHandle("founder")
	f.organization("acme", leader)
	clientID := appOf(f.createApp(leader, "acme", nil))["id"].(string)
	viewer := f.member("acme", ownership.OrganizationWide(ownership.UsageView))
	f.putLogo(viewer, clientID, quarterPNG(t, 32), http.StatusForbidden)
	f.expect(viewer, "DELETE", "/api/v1/apps/"+clientID+"/logo", nil, http.StatusForbidden, "missing_permission")
}

func (f *fixture) giveFirstPartyALogo(clientID string, logo []byte) {
	f.t.Helper()
	checked, err := applogo.Validate(logo)
	if err != nil {
		f.t.Fatal(err)
	}
	err = f.store.SetAppLogo(context.Background(), database.AppLogo{
		ClientID: clientID, AssetID: "official", LogoFingerprint: database.LogoFingerprint{SHA256: checked.SHA256, AHash: checked.AHash},
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestALogoResemblingAFirstPartyLogoIsHeldUntilTheAppIsApproved(t *testing.T) {
	f, _ := newLogoFixture(t)
	official := quarterPNG(t, 32)
	f.giveFirstPartyALogo("neoworks-calendar", official)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)

	copied := f.putLogo(owner, clientID, official, http.StatusOK)
	if copied["held"] != true {
		t.Fatalf("a copy of the official logo is held: %v", copied)
	}
	app := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	if app["logoHeld"] != true || app["logoUrl"] == nil {
		t.Fatalf("the developer still sees the held logo: %v", app)
	}
	public, err := f.store.GetPublicApp(context.Background(), clientID)
	if err != nil || public.LogoAssetID != nil {
		t.Fatalf("users do not see a held logo: %+v %v", public, err)
	}

	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	f.decide(clientID, database.DecisionApprove, "")
	public, err = f.store.GetPublicApp(context.Background(), clientID)
	if err != nil || public.LogoAssetID == nil {
		t.Fatalf("an approved app shows its logo: %+v %v", public, err)
	}
	different := f.putLogo(owner, clientID, quarterPNG(t, 100), http.StatusOK)
	if different["held"] != false {
		t.Fatalf("a different picture is not held: %v", different)
	}
}

func TestAnApprovedAppUploadingALookalikeLogoGoesBackToReview(t *testing.T) {
	f, _ := newLogoFixture(t)
	official := quarterPNG(t, 32)
	f.giveFirstPartyALogo("neoworks-calendar", official)
	owner := f.userWithHandle("moritz")
	clientID := appOf(f.createApp(owner, "moritz", nil))["id"].(string)
	f.expect(owner, "POST", "/api/v1/apps/"+clientID+"/review", reviewBody(), http.StatusOK, "")
	f.decide(clientID, database.DecisionApprove, "")

	f.putLogo(owner, clientID, official, http.StatusOK)
	app := f.expect(owner, "GET", "/api/v1/apps/"+clientID, nil, http.StatusOK, "")
	review := app["review"].(map[string]any)
	if review["status"] != "pending" || review["reason"] != database.LogoResemblanceReason {
		t.Fatalf("review after a lookalike logo: %v", review)
	}
}
