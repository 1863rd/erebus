package modules

import (
	"context"

	"github.com/erebus/scanner/internal/crawler"
)

// ScanMode controls how aggressively modules probe targets.
type ScanMode int

const (
	ModeNormal ScanMode = iota // Default: balanced speed vs. coverage
	ModeDeep                   // Extended payloads, more vectors, slower
)

type modeKey struct{}

// WithMode embeds a ScanMode into the context so all modules can read it.
func WithMode(ctx context.Context, m ScanMode) context.Context {
	return context.WithValue(ctx, modeKey{}, m)
}

// GetMode retrieves the ScanMode from context; defaults to ModeNormal.
func GetMode(ctx context.Context) ScanMode {
	if m, ok := ctx.Value(modeKey{}).(ScanMode); ok {
		return m
	}
	return ModeNormal
}

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Likely    Confidence = "likely"
	Potential Confidence = "potential"
)

// AccessCell holds one cell of the access control matrix:
// the HTTP response an identity received for a given endpoint.
type AccessCell struct {
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Sig    string `json:"sig,omitempty"` // normalized body signature (sha256 prefix)
}

type Finding struct {
	// Core identity
	Module   string   `json:"module"`
	Severity Severity `json:"severity"`

	// Location
	URL    string `json:"url"`
	Method string `json:"method,omitempty"`
	Param  string `json:"param,omitempty"`

	// HTTP context
	StatusCode   int `json:"status_code,omitempty"`
	ResponseSize int `json:"response_size,omitempty"`

	// Attack
	Payload  string `json:"payload,omitempty"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`

	// Classification
	CWE            string   `json:"cwe,omitempty"`
	CVSS           float64  `json:"cvss,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	AttackCategory string   `json:"attack_category,omitempty"` // e.g. "A01:Broken Access Control"
	References     []string `json:"references,omitempty"`

	// Quality
	Confidence Confidence `json:"confidence,omitempty"`

	// Remediation
	Remediation     string `json:"remediation,omitempty"`
	RemPriority     string `json:"remediation_priority,omitempty"` // immediate / high / medium / low

	// Data context
	Extracted   string `json:"extracted,omitempty"`
	DataExposed string `json:"data_exposed,omitempty"` // "credentials", "PII", "internal config", etc.

	// Tags & session
	Tags    []string `json:"tags,omitempty"`
	Session string   `json:"session,omitempty"`

	// Exploit chain
	ChainOf    string   `json:"chain_of,omitempty"`
	ChainSteps []string `json:"chain_steps,omitempty"` // ordered exploit steps

	// HTTP capture
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`

	// Access control matrix — populated by the accessmatrix engine
	// Key = identity name, value = what that identity received for this endpoint
	MatrixRow map[string]AccessCell `json:"matrix_row,omitempty"`
}

type Module interface {
	Name() string
	Run(ctx context.Context, page crawler.Page) ([]Finding, error)
}
