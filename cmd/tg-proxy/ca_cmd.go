package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/TensorGreed/tg-proxy/internal/ca"
	"github.com/TensorGreed/tg-proxy/internal/config"
)

// installerFactory is the seam through which CA install/uninstall subcommands
// reach the OS trust store. Tests override it with a fake.
var installerFactory = ca.DefaultInstaller

// caCmdOutput is where ca subcommand output goes. Tests redirect it.
var caCmdOutput io.Writer = os.Stdout

// runCA dispatches "tg-proxy ca <sub>" subcommands.
func runCA(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tg-proxy ca <generate|install|uninstall|path> [flags]")
	}
	switch args[0] {
	case "generate":
		return runCAGenerate(args[1:])
	case "install":
		return runCAInstall(args[1:])
	case "uninstall":
		return runCAUninstall(args[1:])
	case "path":
		return runCAPath(args[1:])
	default:
		return fmt.Errorf("unknown 'ca' subcommand %q", args[0])
	}
}

func runCAGenerate(args []string) error {
	fs := flag.NewFlagSet("tg-proxy ca generate", flag.ContinueOnError)
	fs.SetOutput(caCmdOutput)
	certPath := fs.String("cert-path", "", "where to write the CA certificate (default: OS user config dir)")
	keyPath := fs.String("key-path", "", "where to write the CA private key (default: OS user config dir)")
	org := fs.String("org", "tg-proxy CA", "Subject Organization for the generated certificate")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cp, kp, err := resolvePaths(*certPath, *keyPath)
	if err != nil {
		return err
	}

	if !*force {
		if exists(cp) || exists(kp) {
			return fmt.Errorf("ca: %s or %s already exists; pass -force to overwrite", cp, kp)
		}
	}

	root, err := ca.NewRoot(*org)
	if err != nil {
		return err
	}
	if err := ca.SaveRoot(root, cp, kp); err != nil {
		return err
	}
	fmt.Fprintf(caCmdOutput, "wrote CA cert: %s\nwrote CA key:  %s\n", cp, kp)
	fmt.Fprintf(caCmdOutput, "next: run `tg-proxy ca install -cert-path %s` (requires admin) to trust this CA OS-wide\n", cp)
	return nil
}

func runCAInstall(args []string) error {
	fs := flag.NewFlagSet("tg-proxy ca install", flag.ContinueOnError)
	fs.SetOutput(caCmdOutput)
	certPath := fs.String("cert-path", "", "CA certificate to install (default: OS user config dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cp, _, err := resolvePaths(*certPath, "")
	if err != nil {
		return err
	}
	inst := installerFactory()
	fmt.Fprintln(caCmdOutput, inst.Describe())
	if err := inst.Install(cp); err != nil {
		return err
	}
	fmt.Fprintf(caCmdOutput, "installed %s into the OS trust store\n", cp)
	return nil
}

func runCAUninstall(args []string) error {
	fs := flag.NewFlagSet("tg-proxy ca uninstall", flag.ContinueOnError)
	fs.SetOutput(caCmdOutput)
	certPath := fs.String("cert-path", "", "CA certificate to uninstall (default: OS user config dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cp, _, err := resolvePaths(*certPath, "")
	if err != nil {
		return err
	}
	inst := installerFactory()
	fmt.Fprintln(caCmdOutput, inst.Describe())
	if err := inst.Uninstall(cp); err != nil {
		return err
	}
	fmt.Fprintf(caCmdOutput, "uninstalled %s from the OS trust store\n", cp)
	return nil
}

func runCAPath(args []string) error {
	fs := flag.NewFlagSet("tg-proxy ca path", flag.ContinueOnError)
	fs.SetOutput(caCmdOutput)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cp, kp, err := resolvePaths("", "")
	if err != nil {
		return err
	}
	fmt.Fprintf(caCmdOutput, "cert: %s\nkey:  %s\n", cp, kp)
	return nil
}

// resolvePaths fills in defaults from config.DefaultCAPaths when either input
// is empty. Both must end up populated.
func resolvePaths(certPath, keyPath string) (string, string, error) {
	if certPath != "" && keyPath != "" {
		return certPath, keyPath, nil
	}
	defCert, defKey, err := config.DefaultCAPaths()
	if err != nil {
		return "", "", err
	}
	if certPath == "" {
		certPath = defCert
	}
	if keyPath == "" {
		keyPath = defKey
	}
	return certPath, keyPath, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
