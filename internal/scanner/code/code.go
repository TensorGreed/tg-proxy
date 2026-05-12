// Package code detects source-code snippets embedded in HTTP bodies. The
// primary motivation is AI workflows: catching proprietary code being
// pasted into LLM prompts. The detectors target syntactic signatures that
// are unambiguous in prose — `def foo(...):`, `package main`, `#include`
// — rather than counting individual keywords.
//
// A short paragraph that quotes one line of code will produce one
// finding. A 500-line script will produce many. The pipeline's redactor
// can then mask, audit, or block as configured.
package code

import (
	"context"
	"regexp"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "code"

type detector struct {
	typ        string
	pattern    *regexp.Regexp
	severity   api.Severity
	confidence float32
}

var detectors = []detector{
	// --- Python ---------------------------------------------------------
	{
		typ:        "code.python_def",
		pattern:    regexp.MustCompile(`\bdef\s+[A-Za-z_][A-Za-z0-9_]*\s*\(`),
		severity:   api.SeverityMedium,
		confidence: 0.85,
	},
	{
		typ:        "code.python_class",
		pattern:    regexp.MustCompile(`\bclass\s+[A-Z][A-Za-z0-9_]*\s*[(:]`),
		severity:   api.SeverityMedium,
		confidence: 0.80,
	},
	{
		typ:        "code.python_import",
		pattern:    regexp.MustCompile(`(?m)^\s*(?:from\s+[\w.]+\s+)?import\s+[A-Za-z_][\w,\s]*$`),
		severity:   api.SeverityMedium,
		confidence: 0.75,
	},
	// --- JavaScript / TypeScript ---------------------------------------
	{
		typ:        "code.javascript_function",
		pattern:    regexp.MustCompile(`\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(`),
		severity:   api.SeverityMedium,
		confidence: 0.85,
	},
	{
		typ:        "code.javascript_arrow",
		pattern:    regexp.MustCompile(`=>\s*[{(]`),
		severity:   api.SeverityLow,
		confidence: 0.55,
	},
	{
		typ:        "code.javascript_require",
		pattern:    regexp.MustCompile(`\brequire\s*\(\s*['"][^'"]+['"]\s*\)`),
		severity:   api.SeverityMedium,
		confidence: 0.90,
	},
	{
		typ:        "code.javascript_console",
		pattern:    regexp.MustCompile(`\bconsole\.(?:log|error|warn|info)\s*\(`),
		severity:   api.SeverityLow,
		confidence: 0.80,
	},
	// --- Go ------------------------------------------------------------
	{
		typ:        "code.go_func",
		pattern:    regexp.MustCompile(`\bfunc\s+(?:\([^)]*\)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\(`),
		severity:   api.SeverityMedium,
		confidence: 0.85,
	},
	{
		typ:        "code.go_package",
		pattern:    regexp.MustCompile(`(?m)^package\s+[a-z][a-z0-9_]*\s*$`),
		severity:   api.SeverityMedium,
		confidence: 0.95,
	},
	// --- C / C++ -------------------------------------------------------
	{
		typ:        "code.c_include",
		pattern:    regexp.MustCompile(`(?m)^\s*#\s*include\s*[<"][^>"]+[>"]`),
		severity:   api.SeverityMedium,
		confidence: 0.95,
	},
	// --- Java / C# -----------------------------------------------------
	{
		typ:        "code.java_class_decl",
		pattern:    regexp.MustCompile(`\b(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?class\s+[A-Z][A-Za-z0-9_]*\b`),
		severity:   api.SeverityMedium,
		confidence: 0.90,
	},
	// --- Shell ---------------------------------------------------------
	{
		typ:        "code.shebang",
		pattern:    regexp.MustCompile(`(?m)^#!\s*(?:/usr)?/(?:bin|local/bin)/(?:env\s+)?[A-Za-z][A-Za-z0-9_/-]*`),
		severity:   api.SeverityMedium,
		confidence: 0.95,
	},
	// --- SQL -----------------------------------------------------------
	// Only the safe, declarative DDL form. SQLi-shaped SELECTs are the
	// sqli scanner's job.
	{
		typ:        "code.sql_create",
		pattern:    regexp.MustCompile(`(?i)\bcreate\s+(?:temporary\s+)?(?:table|view|index|schema|procedure|function)\s+[A-Za-z_]`),
		severity:   api.SeverityMedium,
		confidence: 0.85,
	},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (*Scanner) Name() string { return Name }

func (*Scanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var findings []api.Finding
	for _, d := range detectors {
		for _, idx := range d.pattern.FindAllIndex(data, -1) {
			findings = append(findings, api.Finding{
				Type:       d.typ,
				Severity:   d.severity,
				Start:      idx[0],
				End:        idx[1],
				Confidence: d.confidence,
				Scanner:    Name,
			})
		}
	}
	return findings, nil
}
