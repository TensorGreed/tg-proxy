// tg-proxy is an explicit HTTP(S) network proxy that streams request and
// response bodies through pluggable scanners (PII, secrets, code, …) and a
// pluggable redactor before forwarding traffic. See config.example.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/TensorGreed/tg-proxy/internal/ca"
	"github.com/TensorGreed/tg-proxy/internal/config"
	"github.com/TensorGreed/tg-proxy/internal/pipeline"
	"github.com/TensorGreed/tg-proxy/internal/proxy"
	"github.com/TensorGreed/tg-proxy/internal/redactor"
	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// version is set at build time via -ldflags "-X main.version=...". For users
// who install via `go install`, ldflags aren't set; resolvedVersion falls
// back to the module version embedded by the Go toolchain.
var version = "dev"

func resolvedVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return version
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		if err := runCA(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "tg-proxy: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tg-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "", "path to YAML config file (uses defaults if empty)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("tg-proxy", resolvedVersion())
		return nil
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	logger, err := buildLogger(cfg.Log)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	scanners, err := buildScanners(cfg)
	if err != nil {
		return err
	}
	red, err := buildRedactor(cfg)
	if err != nil {
		return err
	}

	certStore, err := buildCertStore(cfg)
	if err != nil {
		return err
	}

	pl := pipeline.New(scanners, red)
	srv := proxy.New(proxy.Options{
		Addr:             cfg.Listen,
		Pipeline:         pl,
		MaxBody:          cfg.Limits.MaxBodySize,
		Logger:           logger,
		ReadTimeout:      cfg.Limits.ReadTimeout(),
		WriteTimeout:     cfg.Limits.WriteTimeout(),
		IdleTimeout:      cfg.Limits.IdleTimeout(),
		CertStore:        certStore,
		UpstreamInsecure: cfg.TLS.UpstreamInsecure,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting tg-proxy",
		"version", resolvedVersion(),
		"listen", cfg.Listen,
		"scanners", cfg.EnabledScanners(),
		"redactor", cfg.Redactor.Name,
		"mitm", cfg.TLS.MITM,
	)
	return srv.Start(ctx)
}

// buildCertStore returns a *ca.Store when MITM is enabled in config; nil
// otherwise. It refuses to start if MITM is on but the CA files are missing,
// pointing the operator at `tg-proxy ca generate`.
func buildCertStore(cfg *config.Config) (*ca.Store, error) {
	if !cfg.TLS.MITM {
		return nil, nil
	}
	certPath, keyPath, err := resolvePaths(cfg.TLS.CA.CertPath, cfg.TLS.CA.KeyPath)
	if err != nil {
		return nil, err
	}
	root, err := ca.LoadRoot(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w\nhint: run `tg-proxy ca generate` to create one", err)
	}
	cacheSize := cfg.TLS.LeafCacheSize
	if cacheSize <= 0 {
		cacheSize = 1024
	}
	return ca.NewStore(root, cacheSize, cfg.TLS.CA.Organization)
}

func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.Default(), nil
	}
	return config.Load(path)
}

func buildLogger(c config.LogConfig) (*slog.Logger, error) {
	level, err := config.ParseLogLevel(c.Level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch c.Format {
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h), nil
}

func buildScanners(cfg *config.Config) ([]api.Scanner, error) {
	reg := scanner.NewRegistry()
	if err := reg.Register(pii.New()); err != nil {
		return nil, err
	}

	out := make([]api.Scanner, 0, len(cfg.Scanners))
	for _, sc := range cfg.Scanners {
		if !sc.Enabled {
			continue
		}
		s, ok := reg.Get(sc.Name)
		if !ok {
			return nil, fmt.Errorf("scanner %q is not registered", sc.Name)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scanners enabled")
	}
	return out, nil
}

func buildRedactor(cfg *config.Config) (api.Redactor, error) {
	reg := redactor.NewRegistry()

	placeholder, _ := cfg.Redactor.Config["placeholder"].(string)
	if err := reg.Register(mask.New(placeholder)); err != nil {
		return nil, err
	}

	r, ok := reg.Get(cfg.Redactor.Name)
	if !ok {
		return nil, fmt.Errorf("redactor %q is not registered", cfg.Redactor.Name)
	}
	return r, nil
}
