// Package mollie is a thin client for the Mollie payments API. It covers the
// slice the billing flow needs: creating a customer for an organization and
// starting a "first" payment that captures a reusable mandate, plus reading a
// payment back when Mollie calls our webhook.
//
// Like the email and push packages it is env-gated: when MOLLIE_API_KEY is
// absent NewClient returns a disabled client whose calls fail with
// ErrNotConfigured, so dev works without a Mollie account.
package mollie

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ErrNotConfigured is returned by every call on a disabled client (no API key).
var ErrNotConfigured = errors.New("mollie: not configured")

const defaultBaseURL = "https://api.mollie.com/v2"

// Money is a Mollie amount: a currency code plus a string value like "0.01".
type Money struct {
	Currency string `json:"currency"`
	Value    string `json:"value"`
}

// FirstPaymentInput starts a sequenceType=first payment against an existing
// customer. Paying it authorizes a mandate reusable for later usage charges.
type FirstPaymentInput struct {
	CustomerID     string
	Amount         Money
	Description    string
	RedirectURL    string
	WebhookURL     string
	OrganizationID string
}

// Payment is the subset of a Mollie payment resource the billing flow reads.
type Payment struct {
	ID             string
	Status         string // open, paid, failed, canceled, expired, pending
	MandateID      string
	CustomerID     string
	CheckoutURL    string
	OrganizationID string // lifted from metadata.organization_id
}

type Client interface {
	// Enabled reports whether a real Mollie API key is configured.
	Enabled() bool
	CreateCustomer(ctx context.Context, name, email string) (customerID string, err error)
	CreateFirstPayment(ctx context.Context, in FirstPaymentInput) (Payment, error)
	GetPayment(ctx context.Context, id string) (Payment, error)
}

type Config struct {
	APIKey  string
	BaseURL string
}

func ConfigFromEnv() Config {
	return Config{
		APIKey:  os.Getenv("MOLLIE_API_KEY"),
		BaseURL: os.Getenv("MOLLIE_API_BASE"),
	}
}

// NewClient returns a live client when an API key is set, otherwise a disabled
// client whose methods return ErrNotConfigured.
func NewClient(cfg Config) Client {
	if cfg.APIKey == "" {
		return disabledClient{}
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &httpClient{
		apiKey:  cfg.APIKey,
		baseURL: baseURL,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// ── HTTP client ─────────────────────────────────────────────────────────────

type httpClient struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

func (c *httpClient) Enabled() bool { return true }

type customerResponse struct {
	ID string `json:"id"`
}

func (c *httpClient) CreateCustomer(ctx context.Context, name, email string) (string, error) {
	body := map[string]any{"name": name, "email": email}
	var out customerResponse
	if err := c.do(ctx, http.MethodPost, "/customers", body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("mollie: customer response missing id")
	}
	return out.ID, nil
}

// paymentResponse mirrors the fields of a Mollie payment we consume.
type paymentResponse struct {
	ID         string            `json:"id"`
	Status     string            `json:"status"`
	MandateID  string            `json:"mandateId"`
	CustomerID string            `json:"customerId"`
	Metadata   map[string]string `json:"metadata"`
	Links      struct {
		Checkout struct {
			Href string `json:"href"`
		} `json:"checkout"`
	} `json:"_links"`
}

func (p paymentResponse) toPayment() Payment {
	return Payment{
		ID:             p.ID,
		Status:         p.Status,
		MandateID:      p.MandateID,
		CustomerID:     p.CustomerID,
		CheckoutURL:    p.Links.Checkout.Href,
		OrganizationID: p.Metadata["organization_id"],
	}
}

func (c *httpClient) CreateFirstPayment(ctx context.Context, in FirstPaymentInput) (Payment, error) {
	body := map[string]any{
		"amount":       in.Amount,
		"customerId":   in.CustomerID,
		"sequenceType": "first",
		"description":  in.Description,
		"redirectUrl":  in.RedirectURL,
		"metadata":     map[string]string{"organization_id": in.OrganizationID},
	}
	// A webhook URL Mollie cannot reach (e.g. localhost) is rejected, so only
	// send it when one is configured. Without it we poll status on redirect.
	if in.WebhookURL != "" {
		body["webhookUrl"] = in.WebhookURL
	}

	var out paymentResponse
	if err := c.do(ctx, http.MethodPost, "/payments", body, &out); err != nil {
		return Payment{}, err
	}
	payment := out.toPayment()
	if payment.CheckoutURL == "" {
		return Payment{}, fmt.Errorf("mollie: payment response missing checkout url")
	}
	return payment, nil
}

func (c *httpClient) GetPayment(ctx context.Context, id string) (Payment, error) {
	var out paymentResponse
	if err := c.do(ctx, http.MethodGet, "/payments/"+id, nil, &out); err != nil {
		return Payment{}, err
	}
	return out.toPayment(), nil
}

// do issues a request against the Mollie API and decodes a JSON response into
// out. It returns an error carrying Mollie's detail message on non-2xx.
func (c *httpClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mollie: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("mollie: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mollie: request: %w", err)
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("mollie: read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("mollie: %s %s: %s", method, path, mollieError(payload, res.StatusCode))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("mollie: decode response: %w", err)
	}
	return nil
}

// mollieError extracts the human-readable detail from a Mollie error body,
// falling back to the status code.
func mollieError(payload []byte, status int) string {
	var parsed struct {
		Detail string `json:"detail"`
		Title  string `json:"title"`
	}
	if json.Unmarshal(payload, &parsed) == nil && parsed.Detail != "" {
		return parsed.Detail
	}
	return fmt.Sprintf("status %d", status)
}

// ── Disabled client ─────────────────────────────────────────────────────────

type disabledClient struct{}

func (disabledClient) Enabled() bool { return false }

func (disabledClient) CreateCustomer(context.Context, string, string) (string, error) {
	return "", ErrNotConfigured
}

func (disabledClient) CreateFirstPayment(context.Context, FirstPaymentInput) (Payment, error) {
	return Payment{}, ErrNotConfigured
}

func (disabledClient) GetPayment(context.Context, string) (Payment, error) {
	return Payment{}, ErrNotConfigured
}
