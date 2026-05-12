package sqli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func findingsOf(t *testing.T, typ, input string) []api.Finding {
	t.Helper()
	all, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	var out []api.Finding
	for _, f := range all {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestScanner_Name(t *testing.T) { assert.Equal(t, "sqli", New().Name()) }

func TestScan_Empty(t *testing.T) {
	f, err := New().Scan(context.Background(), nil, api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, f)
}

func TestScan_UnionSelect(t *testing.T) {
	for _, input := range []string{
		"id=1 UNION SELECT username,password FROM users",
		"id=1 union  select 1,2",
		"q=' UNION ALL SELECT NULL,NULL--",
	} {
		fs := findingsOf(t, "sqli.union_select", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_Tautology(t *testing.T) {
	for _, input := range []string{
		"name=admin' OR 1=1--",
		"name=admin' or '1'='1",
		"AND 1 = 1",
	} {
		fs := findingsOf(t, "sqli.tautology", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_StatementChain(t *testing.T) {
	for _, input := range []string{
		"name=foo'; DROP TABLE users;--",
		"id=1; delete from sessions",
		"q=ok ; truncate audit",
	} {
		fs := findingsOf(t, "sqli.statement_chain", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_TimeBased(t *testing.T) {
	for _, input := range []string{
		"id=1 AND SLEEP(5)",
		"q=' OR BENCHMARK(1000000, MD5('x'))",
		"WAITFOR DELAY '00:00:05'",
		"pg_sleep(3)",
	} {
		fs := findingsOf(t, "sqli.time_based", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_XPCmdshell(t *testing.T) {
	fs := findingsOf(t, "sqli.xp_cmdshell", "'; EXEC xp_cmdshell 'whoami'--")
	require.Len(t, fs, 1)
	assert.Equal(t, api.SeverityCritical, fs[0].Severity)
}

func TestScan_SchemaRecon(t *testing.T) {
	for _, input := range []string{
		"SELECT * FROM information_schema.tables",
		"FROM sys.databases",
	} {
		fs := findingsOf(t, "sqli.schema_recon", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_BenignTextNotFlagged(t *testing.T) {
	// Plain prose with words that LOOK like SQL but aren't an injection.
	// The "or" tautology pattern requires "=" so "this or that" doesn't
	// trip it.
	input := "Should we choose this option or that one for the report?"
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScan_UnicodeWhitespace(t *testing.T) {
	// Each input replaces the ASCII space between keywords with a
	// different Unicode space-separator character. All variants must
	// still fire — otherwise an attacker can evade by literally typing
	// a non-breaking space.
	const (
		nbsp        = " " // NO-BREAK SPACE
		ideographic = "　" // IDEOGRAPHIC SPACE
		narrowNBSP  = " " // NARROW NO-BREAK SPACE
	)
	cases := []struct {
		name    string
		input   string
		wantTyp string
	}{
		{"nbsp UNION SELECT", "id=1 UNION" + nbsp + "SELECT 1,2", "sqli.union_select"},
		{"ideographic UNION SELECT", "id=1 UNION" + ideographic + "SELECT 1,2", "sqli.union_select"},
		{"narrow nbsp tautology", "name=admin' OR" + narrowNBSP + "1=1", "sqli.tautology"},
		{"nbsp ; DROP", "id=1;" + nbsp + "DROP TABLE users", "sqli.statement_chain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := findingsOf(t, c.wantTyp, c.input)
			assert.NotEmpty(t, fs, "expected %s to fire on %q", c.wantTyp, c.input)
		})
	}
}

func TestScan_OffsetsArePrecise(t *testing.T) {
	input := "name=admin' OR 1=1-- and id=2; DROP TABLE users"
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Greater(t, f.End, f.Start)
		assert.LessOrEqual(t, f.End, len(input))
		assert.Equal(t, "sqli", f.Scanner)
	}
}
