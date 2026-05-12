package plugin

import (
	hcplug "github.com/hashicorp/go-plugin"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// ServeScanner is the entry point Go plugin authors call from their main()
// to expose a scanner. It blocks until the host kills the process.
//
//	func main() {
//	    plugin.ServeScanner(&myScanner{})
//	}
func ServeScanner(impl api.Scanner) {
	hcplug.Serve(&hcplug.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]hcplug.Plugin{
			ScannerPluginName: &ScannerPlugin{Impl: impl},
		},
		GRPCServer: hcplug.DefaultGRPCServer,
	})
}

// ServeRedactor is the redactor counterpart of ServeScanner.
func ServeRedactor(impl api.Redactor) {
	hcplug.Serve(&hcplug.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]hcplug.Plugin{
			RedactorPluginName: &RedactorPlugin{Impl: impl},
		},
		GRPCServer: hcplug.DefaultGRPCServer,
	})
}

// HostPluginMap is the plugin map used by the host side when calling
// hcplug.NewClient. It declares the protocol but contains no Impl, since
// the host doesn't serve.
func HostPluginMap() map[string]hcplug.Plugin {
	return map[string]hcplug.Plugin{
		ScannerPluginName:  &ScannerPlugin{},
		RedactorPluginName: &RedactorPlugin{},
	}
}
