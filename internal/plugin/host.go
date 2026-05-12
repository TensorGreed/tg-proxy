// Package plugin loads external scanner and redactor plugins for tg-proxy.
//
// Plugins are subprocesses managed by hashicorp/go-plugin; they communicate
// with the host over gRPC using the protocol in pkg/plugin/proto. The
// public-facing SDK lives in pkg/plugin so plugin authors can import it;
// this package is private because plugin _loading_ is an implementation
// detail of the host.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	hcplug "github.com/hashicorp/go-plugin"

	"github.com/TensorGreed/tg-proxy/pkg/api"
	tgplug "github.com/TensorGreed/tg-proxy/pkg/plugin"
	pb "github.com/TensorGreed/tg-proxy/pkg/plugin/proto"
)

// PluginConfig describes a single external plugin entry: what to exec and
// which dispense key to ask for.
type PluginConfig struct {
	// Name is how the plugin is referred to in tg-proxy config. It is
	// also used as a fallback display name if the plugin's Info() RPC
	// reports an empty name.
	Name string

	// Command is the subprocess command line. First element is the
	// binary, the rest are arguments.
	Command []string

	// Env is the environment override; if empty, the host inherits its
	// own environment.
	Env []string

	// Kind is "scanner" or "redactor".
	Kind string

	// HandshakeTimeout caps how long we'll wait for the plugin to
	// announce itself. 10 seconds by default.
	HandshakeTimeout time.Duration
}

const (
	KindScanner  = tgplug.ScannerPluginName
	KindRedactor = tgplug.RedactorPluginName
)

// Host owns the lifecycle of all loaded plugin subprocesses. Plugins live
// until Shutdown is called.
type Host struct {
	logger *slog.Logger
	mu     sync.Mutex
	procs  []*hcplug.Client
}

func NewHost(logger *slog.Logger) *Host {
	if logger == nil {
		logger = slog.Default()
	}
	return &Host{logger: logger}
}

// LoadScanner spawns the plugin described by cfg and returns it as an
// api.Scanner whose Name() is the plugin's self-reported name (falling back
// to cfg.Name on lookup failure).
func (h *Host) LoadScanner(ctx context.Context, cfg PluginConfig) (api.Scanner, error) {
	raw, err := h.dispense(cfg, KindScanner)
	if err != nil {
		return nil, err
	}
	scanner, ok := raw.(api.Scanner)
	if !ok {
		return nil, fmt.Errorf("plugin %q did not return an api.Scanner (got %T)", cfg.Name, raw)
	}
	// Fetch info so the grpc client caches the plugin's self-reported
	// name; subsequent Name() calls return it.
	if i, ok := raw.(infoer); ok {
		_, _ = i.Info(ctx)
	}
	if scanner.Name() == "" {
		scanner = namedScanner{Scanner: scanner, name: cfg.Name}
	}
	return scanner, nil
}

// infoer is satisfied by the grpcScannerClient / grpcRedactorClient types
// defined in pkg/plugin. We use it to trigger an Info() round-trip so the
// adapter caches the plugin's self-reported name.
type infoer interface {
	Info(context.Context) (*pb.PluginInfo, error)
}

// LoadRedactor is the redactor counterpart of LoadScanner.
func (h *Host) LoadRedactor(ctx context.Context, cfg PluginConfig) (api.Redactor, error) {
	raw, err := h.dispense(cfg, KindRedactor)
	if err != nil {
		return nil, err
	}
	red, ok := raw.(api.Redactor)
	if !ok {
		return nil, fmt.Errorf("plugin %q did not return an api.Redactor (got %T)", cfg.Name, raw)
	}
	if i, ok := raw.(interface {
		Info(context.Context) (any, error)
	}); ok {
		_, _ = i.Info(ctx)
	}
	if red.Name() == "" {
		red = namedRedactor{Redactor: red, name: cfg.Name}
	}
	return red, nil
}

// Shutdown kills every plugin subprocess. Safe to call from a defer.
func (h *Host) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.procs {
		c.Kill()
	}
	h.procs = nil
}

func (h *Host) dispense(cfg PluginConfig, kind string) (interface{}, error) {
	if len(cfg.Command) == 0 {
		return nil, errors.New("plugin: command is required")
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...) //nolint:gosec // user-supplied; same trust level as the proxy itself
	if len(cfg.Env) > 0 {
		cmd.Env = cfg.Env
	}

	client := hcplug.NewClient(&hcplug.ClientConfig{
		HandshakeConfig:  tgplug.Handshake,
		Plugins:          tgplug.HostPluginMap(),
		Cmd:              cmd,
		AllowedProtocols: []hcplug.Protocol{hcplug.ProtocolGRPC},
		Logger:           hclogFromSlog(h.logger),
		StartTimeout:     timeout,
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("plugin %q: connect: %w", cfg.Name, err)
	}

	raw, err := rpcClient.Dispense(kind)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("plugin %q: dispense %s: %w", cfg.Name, kind, err)
	}

	h.mu.Lock()
	h.procs = append(h.procs, client)
	h.mu.Unlock()

	return raw, nil
}

// namedScanner overrides Name() when the plugin didn't report one.
type namedScanner struct {
	api.Scanner
	name string
}

func (n namedScanner) Name() string { return n.name }

type namedRedactor struct {
	api.Redactor
	name string
}

func (n namedRedactor) Name() string { return n.name }

// hclogFromSlog adapts a *slog.Logger so hashicorp/go-plugin's internal
// hclog interface can drive it. We only need a minimal mapping; finer
// levels collapse to debug.
func hclogFromSlog(logger *slog.Logger) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:   "tg-proxy.plugin",
		Output: slogWriter{logger: logger},
		Level:  hclog.Info,
	})
}

type slogWriter struct{ logger *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	if w.logger != nil {
		w.logger.Debug("plugin-host", "msg", string(p))
	}
	return len(p), nil
}
