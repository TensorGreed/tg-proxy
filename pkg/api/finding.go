package api

import "fmt"

type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return fmt.Sprintf("severity(%d)", uint8(s))
	}
}

// ParseSeverity is the inverse of Severity.String for the named levels.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q", s)
	}
}

// Finding describes a single match inside a scanned byte slice. Start and End
// are byte offsets into the slice that was passed to Scanner.Scan; End is
// exclusive. Redactors rely on these offsets to rewrite the body in place, so
// scanners must populate them correctly (Start >= 0, End > Start, End <= len).
type Finding struct {
	Type       string
	Severity   Severity
	Start      int
	End        int
	Confidence float32
	Scanner    string
	Metadata   map[string]any
}

// Len returns the byte length of the match.
func (f Finding) Len() int { return f.End - f.Start }
