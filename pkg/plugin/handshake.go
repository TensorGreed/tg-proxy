// Package plugin is the public SDK for writing tg-proxy plugins in Go and
// for the host to load them. External scanners and redactors run as
// subprocesses spawned by tg-proxy via hashicorp/go-plugin and communicate
// over gRPC using the protocol in pkg/plugin/proto.
//
// Plugin authors:
//   - import this package and pkg/api
//   - implement api.Scanner or api.Redactor
//   - call plugin.ServeScanner / plugin.ServeRedactor from main
//
// The host imports github.com/TensorGreed/tg-proxy/internal/plugin to load
// plugins by config — that package is private because the loading logic is
// not part of the SDK contract.
package plugin

import (
	hcplug "github.com/hashicorp/go-plugin"
)

// Handshake is the magic-cookie envelope every tg-proxy plugin uses. The
// cookie key/value lets hashicorp/go-plugin notice when a misconfigured
// command — say, a shell that prints "hello" — is masquerading as a plugin.
//
// Bumping ProtocolVersion is the way to make a breaking change to the
// gRPC contract in pkg/plugin/proto; old plugins will refuse to start.
var Handshake = hcplug.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "TG_PROXY_PLUGIN",
	MagicCookieValue: "tg-proxy.plugin.v1",
}

const (
	// ScannerPluginName is the well-known dispense name for scanner
	// plugins. Plugin authors register their implementation under this key.
	ScannerPluginName = "scanner"
	// RedactorPluginName is the well-known dispense name for redactor
	// plugins.
	RedactorPluginName = "redactor"
)
