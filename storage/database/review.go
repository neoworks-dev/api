package database

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ErrReviewState means the review cannot move from the app's current status to
// the requested one.
var ErrReviewState = errors.New("review state does not allow this")

// ReviewSubmission is what a developer files when asking for review. The scopes
// and their reasons are the app's own.
type ReviewSubmission struct {
	PrivacyPolicyURL string `json:"privacyPolicyUrl"`
	SupportContact   string `json:"supportContact"`
}

// ReviewDecision is what a Neoworks administrator decides.
type ReviewDecision string

const (
	DecisionApprove ReviewDecision = "approve"
	DecisionReject  ReviewDecision = "reject"
	DecisionSuspend ReviewDecision = "suspend"
)

// decisionOutcome is the status a decision leads to, and the statuses it can be
// made from. An approval also covers lifting a suspension.
var decisionOutcome = map[ReviewDecision]struct {
	status string
	from   []string
}{
	DecisionApprove: {ReviewStatusApproved, []string{ReviewStatusPending, ReviewStatusSuspended}},
	DecisionReject:  {ReviewStatusRejected, []string{ReviewStatusPending}},
	DecisionSuspend: {ReviewStatusSuspended, []string{ReviewStatusNone, ReviewStatusPending, ReviewStatusApproved, ReviewStatusRejected}},
}

// IsKnown reports whether the decision exists.
func (decision ReviewDecision) IsKnown() bool {
	_, known := decisionOutcome[decision]
	return known
}

// NeedsReason reports whether the decision must come with a reason for the developer.
func (decision ReviewDecision) NeedsReason() bool {
	return decision == DecisionReject || decision == DecisionSuspend
}

// needsReReview reports whether the patch asks for a scope the reviewer did not
// approve on an approved app.
func needsReReview(current *App, patch AppPatch) bool {
	if patch.Scopes == nil || current.Review.Status != ReviewStatusApproved {
		return false
	}
	for _, name := range ScopeNames(*patch.Scopes) {
		if !slices.Contains(current.ReviewedScopes, name) {
			return true
		}
	}
	return false
}

const submitReviewStatement = `UPDATE $client SET review_status = 'pending', review_reason = NONE,
	review_updated_at = time::now(), privacy_policy_url = $privacy_policy_url, support_contact = $support_contact,
	reviewed_scopes = NONE
	WHERE review_status IN ['none', 'rejected'] AND first_party = false`

// SubmitReview files the app for review; ErrReviewState unless it has none or
// was rejected.
func (s *SurrealStore) SubmitReview(ctx context.Context, clientID string, submission ReviewSubmission) (*App, error) {
	rows, err := queryRows[dbApp](ctx, s.DB, submitReviewStatement, map[string]any{
		"client": clientRecord(clientID), "privacy_policy_url": submission.PrivacyPolicyURL,
		"support_contact": submission.SupportContact,
	})
	if err != nil {
		return nil, fmt.Errorf("submit review: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrReviewState
	}
	return s.GetApp(ctx, clientID)
}

// DecideReview records a decision about an app. ErrReviewState when the app is
// not in a status the decision can be made from.
func (s *SurrealStore) DecideReview(ctx context.Context, clientID string, decision ReviewDecision, reason string) (*App, error) {
	outcome, known := decisionOutcome[decision]
	if !known {
		return nil, fmt.Errorf("%w: unknown decision %q", ErrInvalidInput, decision)
	}
	assignments := "review_status = $status, review_updated_at = time::now()"
	params := map[string]any{"client": clientRecord(clientID), "status": outcome.status, "from": outcome.from}
	if reason == "" {
		assignments += ", review_reason = NONE"
	} else {
		assignments += ", review_reason = $reason"
		params["reason"] = reason
	}
	if decision == DecisionApprove {
		assignments += ", reviewed_scopes = scopes"
	}
	rows, err := queryRows[dbApp](ctx, s.DB,
		"UPDATE $client SET "+assignments+" WHERE review_status IN $from AND first_party = false", params)
	if err != nil {
		return nil, fmt.Errorf("decide review: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrReviewState
	}
	return s.GetApp(ctx, clientID)
}

// ReviewQueueItem is an app waiting for or having had a decision, with what the
// reviewer needs to judge it.
type ReviewQueueItem struct {
	App              *App             `json:"app"`
	PrivacyPolicyURL string           `json:"privacyPolicyUrl"`
	SupportContact   string           `json:"supportContact"`
	Scopes           []RequestedScope `json:"scopes"`
}

// ListReviewQueue returns the apps in the review status, oldest request first.
func (s *SurrealStore) ListReviewQueue(ctx context.Context, status string) ([]ReviewQueueItem, error) {
	rows, err := queryRows[dbApp](ctx, s.DB,
		"SELECT * FROM client WHERE review_status = $status AND first_party = false ORDER BY review_updated_at, created_at",
		map[string]any{"status": status})
	if err != nil {
		return nil, fmt.Errorf("list review queue: %w", err)
	}
	items := make([]ReviewQueueItem, 0, len(rows))
	for _, row := range rows {
		item, err := s.queueItem(ctx, row)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, nil
}

func (s *SurrealStore) queueItem(ctx context.Context, row dbApp) (*ReviewQueueItem, error) {
	owner, err := s.appOwner(ctx, row.Owner)
	if err != nil {
		return nil, err
	}
	app := row.toApp(*owner)
	return &ReviewQueueItem{
		App: app, PrivacyPolicyURL: textOrEmpty(row.PrivacyURL), SupportContact: textOrEmpty(row.Support), Scopes: app.Scopes,
	}, nil
}
