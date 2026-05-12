// echoplugin is a minimal external scanner used to drive the plugin host's
// integration tests. It flags every occurrence of the literal substring
// "TOKEN" in the scanned data and supplements that with a Luhn-validated
// credit-card detector so we can prove non-trivial behavior travels over
// the wire too.
package main

import (
	"bytes"
	"context"

	"github.com/TensorGreed/tg-proxy/pkg/api"
	tgplug "github.com/TensorGreed/tg-proxy/pkg/plugin"
)

type echoScanner struct{}

func (echoScanner) Name() string { return "echo" }

func (echoScanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	var findings []api.Finding
	needle := []byte("TOKEN")
	start := 0
	for {
		i := bytes.Index(data[start:], needle)
		if i < 0 {
			break
		}
		findings = append(findings, api.Finding{
			Type:       "echo.token",
			Severity:   api.SeverityHigh,
			Start:      start + i,
			End:        start + i + len(needle),
			Confidence: 1.0,
			Scanner:    "echo",
		})
		start += i + len(needle)
	}
	return findings, nil
}

func main() {
	tgplug.ServeScanner(echoScanner{})
}
