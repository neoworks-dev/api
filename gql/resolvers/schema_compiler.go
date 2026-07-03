package gql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	gql_model "github.com/neoworks/auth/gql/model"
)

// The OpenSchema DSL is the canonical authoring format for client databases. The
// Go API does not parse it; it delegates to the schema-compiler sidecar (a Bun
// service running the OpenSchema compiler), which returns the DatabaseSchemaInput
// the existing rewrite consumes. The Go rewrite remains the security authority and
// re-validates everything the compiler produced.

func schemaCompilerURL() string {
	if value := os.Getenv("SCHEMA_COMPILER_URL"); value != "" {
		return value
	}
	return "http://127.0.0.1:8086"
}

type compileFile struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type compileDiagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Line    *int   `json:"line"`
	Col     *int   `json:"col"`
}

type compileResponse struct {
	OK          bool                           `json:"ok"`
	Schema      *gql_model.DatabaseSchemaInput `json:"schema"`
	DDL         []string                       `json:"ddl"`
	Source      string                         `json:"source"`
	Diagnostics []compileDiagnostic            `json:"diagnostics"`
}

// compileSchemaSource compiles OpenSchema DSL text via the sidecar, returning both
// the DatabaseSchemaInput (validated + recorded for the data plane) and the
// SurrealQL DDL the compiler emits (applied verbatim to the org instance — the
// compiler, not the Go API, owns codegen). Returns nil for empty input (a database
// may be created with no schema). Diagnostics surface as a Public error.
func compileSchemaSource(ctx context.Context, source string) (*gql_model.DatabaseSchemaInput, []string, error) {
	if strings.TrimSpace(source) == "" {
		return nil, nil, nil
	}

	body, err := json.Marshal(map[string]any{
		"files": []compileFile{{Path: "schema.schema", Contents: source}},
	})
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, schemaCompilerURL()+"/compile", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("schema compiler unreachable: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var out compileResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("schema compiler bad response: %w", err)
	}
	if !out.OK {
		return nil, nil, Public("schema error: " + formatDiagnostics(out.Diagnostics))
	}
	if out.Schema == nil {
		return nil, nil, fmt.Errorf("schema compiler returned no schema")
	}
	return out.Schema, out.DDL, nil
}

func formatDiagnostics(diagnostics []compileDiagnostic) string {
	if len(diagnostics) == 0 {
		return "invalid schema"
	}
	parts := make([]string, 0, len(diagnostics))
	for _, d := range diagnostics {
		if d.Line != nil {
			parts = append(parts, fmt.Sprintf("%s (line %d)", d.Message, *d.Line))
			continue
		}
		parts = append(parts, d.Message)
	}
	return strings.Join(parts, "; ")
}
