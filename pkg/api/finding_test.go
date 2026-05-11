package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "severity(99)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.sev.String())
	}
}

func TestParseSeverity(t *testing.T) {
	for _, name := range []string{"info", "low", "medium", "high", "critical"} {
		s, err := ParseSeverity(name)
		require.NoError(t, err)
		assert.Equal(t, name, s.String())
	}

	_, err := ParseSeverity("nope")
	assert.Error(t, err)
}

func TestFindingLen(t *testing.T) {
	f := Finding{Start: 3, End: 10}
	assert.Equal(t, 7, f.Len())
}

func TestDirectionString(t *testing.T) {
	assert.Equal(t, "request", DirectionRequest.String())
	assert.Equal(t, "response", DirectionResponse.String())
	assert.Equal(t, "unknown", Direction(9).String())
}
