package apps

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

const maxSupportContactRunes = 200

type reviewRequest struct {
	PrivacyPolicyURL string `json:"privacyPolicyUrl"`
	SupportContact   string `json:"supportContact"`
}

// submitReview asks Neoworks to review the app. The app must say what it is:
// a description, a homepage, and a reason for each requested scope.
func (h *Handler) submitReview(w http.ResponseWriter, r *http.Request) {
	a, ok := h.appOf(w, r)
	if !ok || !h.allowed(w, r, a, ownership.AppsReview) {
		return
	}
	var request reviewRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	submission, err := reviewSubmission(a.app, request)
	if err != nil {
		writeFieldError(w, "reviewSubmission", err)
		return
	}
	updated, err := h.store.SubmitReview(r.Context(), a.app.ID, submission)
	if errors.Is(err, database.ErrReviewState) {
		respond.Error(w, http.StatusConflict, "review_state", "the app is already in review, approved or suspended")
		return
	}
	if err != nil {
		respond.StoreError(w, "submitReview", err)
		return
	}
	h.auditApp(r, a, updated, database.AuditAppReviewSubmitted, nil)
	respond.JSON(w, http.StatusOK, updated.Review)
}

func reviewSubmission(app *database.App, request reviewRequest) (database.ReviewSubmission, error) {
	if app.Description == "" {
		return database.ReviewSubmission{}, invalidField("description", "describe the app before asking for review")
	}
	if app.Homepage == "" {
		return database.ReviewSubmission{}, invalidField("homepage", "add a homepage before asking for review")
	}
	privacyPolicyURL := strings.TrimSpace(request.PrivacyPolicyURL)
	if len(privacyPolicyURL) > maxHomepageRunes || !isHTTPSURL(privacyPolicyURL) {
		return database.ReviewSubmission{}, invalidField("privacyPolicyUrl", "the privacy policy must be an https:// URL")
	}
	supportContact, err := parseText("supportContact", request.SupportContact, 3, maxSupportContactRunes)
	if err != nil {
		return database.ReviewSubmission{}, err
	}
	if !isEmail(supportContact) && !isHTTPSURL(supportContact) {
		return database.ReviewSubmission{}, invalidField("supportContact", "the support contact must be an email address or an https:// URL")
	}
	return database.ReviewSubmission{PrivacyPolicyURL: privacyPolicyURL, SupportContact: supportContact}, nil
}

func isEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}
