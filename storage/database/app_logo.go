package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// LogoFingerprint identifies the picture of a stored logo; AHash is empty for
// logos without a perceptual hash (SVG).
type LogoFingerprint struct {
	SHA256 string
	AHash  string
}

type dbLogoFingerprint struct {
	SHA256 string  `json:"logo_sha256"`
	AHash  *string `json:"logo_ahash"`
}

// AppLogo is a logo stored as an asset, to attach to an app.
type AppLogo struct {
	ClientID string
	AssetID  string
	LogoFingerprint
	// Held keeps the logo from users until the app is approved.
	Held bool
}

func assetRecord(assetID string) models.RecordID {
	return models.NewRecordID("asset", assetID)
}

// LogoResemblanceReason is the reason shown when a lookalike logo sends an
// approved app back to review.
const LogoResemblanceReason = "The logo resembles the logo of another app and needs a second look."

// setLogoStatement attaches a logo. A held logo sends an approved app back to
// review; the reason is assigned before the status because the assignments run
// in order.
func setLogoStatement(logo AppLogo) (string, map[string]any) {
	assignments := []string{"logo = $asset", "logo_sha256 = $sha256", "logo_held = $held", "logo_ahash = NONE"}
	params := map[string]any{
		"client": clientRecord(logo.ClientID), "asset": assetRecord(logo.AssetID),
		"sha256": logo.SHA256, "held": logo.Held,
	}
	if logo.AHash != "" {
		assignments[3] = "logo_ahash = $ahash"
		params["ahash"] = logo.AHash
	}
	if logo.Held {
		assignments = append(assignments,
			"review_reason = IF review_status = 'approved' { $resemblance_reason } ELSE { review_reason }",
			"review_updated_at = IF review_status = 'approved' { time::now() } ELSE { review_updated_at }",
			"review_status = IF review_status = 'approved' { 'pending' } ELSE { review_status }")
		params["resemblance_reason"] = LogoResemblanceReason
	}
	return "UPDATE $client SET " + strings.Join(assignments, ", "), params
}

// SetAppLogo attaches the logo to the app in place of the one it had.
func (s *SurrealStore) SetAppLogo(ctx context.Context, logo AppLogo) error {
	statement, params := setLogoStatement(logo)
	if err := queryExec(ctx, s.DB, statement, params); err != nil {
		return fmt.Errorf("set app logo: %w", err)
	}
	return nil
}

// ClearAppLogo detaches the app's logo.
func (s *SurrealStore) ClearAppLogo(ctx context.Context, clientID string) error {
	err := queryExec(ctx, s.DB,
		"UPDATE $client SET logo = NONE, logo_sha256 = NONE, logo_ahash = NONE, logo_held = false",
		map[string]any{"client": clientRecord(clientID)})
	if err != nil {
		return fmt.Errorf("clear app logo: %w", err)
	}
	return nil
}

// ProtectedLogos returns the logos the app must not resemble: those of first
// party apps and of approved apps of other owners.
func (s *SurrealStore) ProtectedLogos(ctx context.Context, app *App) ([]LogoFingerprint, error) {
	owner, err := s.ownerRecord(ctx, app.Owner.Handle)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[dbLogoFingerprint](ctx, s.DB,
		`SELECT logo_sha256, logo_ahash FROM client
		WHERE logo_sha256 != NONE AND id != $client AND owner != $owner
			AND (first_party = true OR review_status = 'approved')`,
		map[string]any{"client": clientRecord(app.ID), "owner": owner})
	if err != nil {
		return nil, fmt.Errorf("protected logos: %w", err)
	}
	logos := make([]LogoFingerprint, 0, len(rows))
	for _, row := range rows {
		logos = append(logos, LogoFingerprint{SHA256: row.SHA256, AHash: textOrEmpty(row.AHash)})
	}
	return logos, nil
}

// DeleteAsset removes the asset row and returns its storage key, so the caller
// can delete the object.
func (s *SurrealStore) DeleteAsset(ctx context.Context, assetID string) (string, error) {
	row, err := queryFirst[Asset](ctx, s.DB, "SELECT * FROM $asset", map[string]any{"asset": assetRecord(assetID)})
	if err != nil {
		return "", err
	}
	if err := queryExec(ctx, s.DB, "DELETE $asset", map[string]any{"asset": assetRecord(assetID)}); err != nil {
		return "", fmt.Errorf("delete asset: %w", err)
	}
	return row.StorageKey, nil
}
