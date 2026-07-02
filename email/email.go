// Package email sends transactional email on behalf of Neoworks and its clients.
// Delivery is env-gated: when SMTP credentials are absent it degrades to a no-op
// that logs the message, so dev works out of the box without a mail account.
package email

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"strings"
)

// Message is a single outbound email. HTML is optional; when empty Text is sent.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func ConfigFromEnv() Config {
	return Config{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
	}
}

// NewSender returns an SMTP sender when host + credentials are configured,
// otherwise a no-op sender that logs each message.
func NewSender(cfg Config) Sender {
	if cfg.Host == "" || cfg.Username == "" || cfg.From == "" {
		return noopSender{}
	}
	port := cfg.Port
	if port == "" {
		port = "587"
	}
	return &smtpSender{cfg: cfg, port: port}
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

type smtpSender struct {
	cfg  Config
	port string
}

func (s *smtpSender) Send(_ context.Context, msg Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("email: no recipients")
	}
	addr := s.cfg.Host + ":" + s.port
	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	if err := smtp.SendMail(addr, auth, s.cfg.From, msg.To, buildMIME(s.cfg.From, msg)); err != nil {
		return fmt.Errorf("email: send: %w", err)
	}
	return nil
}

// buildMIME renders RFC 5322 headers + body. HTML wins when present.
func buildMIME(from string, msg Message) []byte {
	contentType := "text/plain; charset=\"UTF-8\""
	body := msg.Text
	if msg.HTML != "" {
		contentType = "text/html; charset=\"UTF-8\""
		body = msg.HTML
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(msg.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// ── No-op ─────────────────────────────────────────────────────────────────────

type noopSender struct{}

func (noopSender) Send(_ context.Context, msg Message) error {
	slog.Info("email noop (SMTP not configured)", "to", msg.To, "subject", msg.Subject)
	return nil
}
