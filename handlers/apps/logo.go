package apps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/neoworks/auth/applogo"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

// LogoStorage keeps the bytes of logos.
type LogoStorage interface {
	PutObject(ctx context.Context, key string, data []byte, contentType string) error
	RemovePrefix(ctx context.Context, prefix string) error
}

// putLogo stores the uploaded PNG or SVG, sanitized, as the app's logo.
func (h *Handler) putLogo(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsEdit) {
		return
	}
	logo, err := readLogo(w, r)
	if err != nil {
		writeFieldError(w, "readLogo", err)
		return
	}
	held, err := h.resemblesProtectedLogo(r.Context(), a.app, logo)
	if err != nil {
		respond.StoreError(w, "protectedLogos", err)
		return
	}
	assetID, err := h.storeLogoAsset(r.Context(), a.userID, logo)
	if err != nil {
		respond.StoreError(w, "storeLogoAsset", err)
		return
	}
	updated, err := h.attachLogo(r.Context(), a.app, assetID, logo, held)
	if err != nil {
		respond.StoreError(w, "attachLogo", err)
		return
	}
	h.auditLogo(r, a, updated, held)
	respond.JSON(w, http.StatusOK, map[string]any{"logoUrl": logoURL(updated), "held": held})
}

func readLogo(w http.ResponseWriter, r *http.Request) (*applogo.Logo, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, applogo.MaxPNGBytes+1))
	if err != nil {
		return nil, invalidField("logo", "the logo is larger than the limit")
	}
	logo, err := applogo.Validate(body)
	if err != nil {
		return nil, invalidField("logo", err.Error())
	}
	return logo, nil
}

// resemblesProtectedLogo reports whether the logo looks like the logo of a first
// party app or of an approved app of someone else. Such a logo is held until the
// app is approved.
func (h *Handler) resemblesProtectedLogo(ctx context.Context, app *database.App, logo *applogo.Logo) (bool, error) {
	if app.FirstParty {
		return false, nil
	}
	protected, err := h.store.ProtectedLogos(ctx, app)
	if err != nil {
		return false, err
	}
	for _, other := range protected {
		if applogo.Resembles(logo.SHA256, logo.AHash, other.SHA256, other.AHash) {
			return true, nil
		}
	}
	return false, nil
}

func (h *Handler) storeLogoAsset(ctx context.Context, userID string, logo *applogo.Logo) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	storageKey := "assets/" + hex.EncodeToString(random)
	if err := h.logos.PutObject(ctx, storageKey, logo.Data, logo.ContentType); err != nil {
		return "", err
	}
	asset, err := h.store.CreateAsset(ctx, database.CreateAssetParams{
		StorageKey: storageKey, Mime: logo.ContentType, Size: len(logo.Data), Visibility: "public", UserID: userID,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", asset.ID.ID), nil
}

// attachLogo points the app at the new asset and removes the one it had.
func (h *Handler) attachLogo(ctx context.Context, app *database.App, assetID string, logo *applogo.Logo, held bool) (*database.App, error) {
	attached := database.AppLogo{
		ClientID: app.ID, AssetID: assetID, Held: held,
		LogoFingerprint: database.LogoFingerprint{SHA256: logo.SHA256, AHash: logo.AHash},
	}
	if err := h.store.SetAppLogo(ctx, attached); err != nil {
		return nil, err
	}
	h.discardLogoAsset(ctx, app.LogoAssetID)
	return h.store.GetApp(ctx, app.ID)
}

// discardLogoAsset deletes an asset the app no longer uses. A failure is
// logged: the logo was already replaced.
func (h *Handler) discardLogoAsset(ctx context.Context, assetID *string) {
	if assetID == nil {
		return
	}
	storageKey, err := h.store.DeleteAsset(ctx, *assetID)
	if errors.Is(err, database.ErrNotFound) {
		return
	}
	if err == nil {
		err = h.logos.RemovePrefix(ctx, storageKey)
	}
	if err != nil {
		slog.Error("discard logo asset", "asset", *assetID, "error", err)
	}
}

func (h *Handler) auditLogo(r *http.Request, a *acting, updated *database.App, held bool) {
	h.auditApp(r, a, updated, database.AuditAppLogoChanged, map[string]any{"held": held})
	if held && a.app.Review.Status == database.ReviewStatusApproved {
		h.auditApp(r, a, updated, database.AuditAppReviewReset, map[string]any{"reason": database.LogoResemblanceReason})
	}
}

func (h *Handler) deleteLogo(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsEdit) {
		return
	}
	if err := h.store.ClearAppLogo(r.Context(), a.app.ID); err != nil {
		respond.StoreError(w, "clearAppLogo", err)
		return
	}
	h.discardLogoAsset(r.Context(), a.app.LogoAssetID)
	h.auditApp(r, a, a.app, database.AuditAppLogoRemoved, nil)
	w.WriteHeader(http.StatusNoContent)
}
