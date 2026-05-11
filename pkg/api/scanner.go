package api

import "context"

// Direction tells a scanner whether the body it is being asked to inspect
// came from the client (request) or the upstream server (response). Some
// scanners adjust heuristics or thresholds based on direction.
type Direction uint8

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

func (d Direction) String() string {
	switch d {
	case DirectionRequest:
		return "request"
	case DirectionResponse:
		return "response"
	default:
		return "unknown"
	}
}

// Hints carries metadata about the HTTP exchange the body belongs to. Hints
// are advisory; scanners must still operate correctly on data alone.
type Hints struct {
	ContentType string
	URL         string
	Method      string
	Direction   Direction
}

// Scanner inspects a byte slice and reports any sensitive substrings it
// finds, with byte-precise offsets so a redactor can rewrite them.
//
// Implementations must be safe for concurrent use: the pipeline fans bodies
// out to every registered scanner in parallel.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, data []byte, hints Hints) ([]Finding, error)
}
