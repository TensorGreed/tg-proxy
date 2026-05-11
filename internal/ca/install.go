package ca

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// Installer adds and removes the tg-proxy root CA in the host operating
// system's trust store. Implementations exist for Linux, macOS and Windows;
// DefaultInstaller returns the right one for the current GOOS.
//
// All implementations require administrator privileges to take effect.
type Installer interface {
	// Install registers the certificate at certPath as a trusted root.
	Install(certPath string) error
	// Uninstall removes a previously-installed CA. On platforms that key
	// the trust entry by CommonName, certPath is read to recover it.
	Uninstall(certPath string) error
	// Describe returns a short human-readable summary of where the CA will
	// be placed and which command will be invoked.
	Describe() string
}

// runner is the seam through which installers shell out. Tests replace it
// with a fake to assert command-line arguments without actually mutating the
// host trust store.
type runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() //nolint:gosec // arguments come from internal config, not user input.
}

// --- Linux -----------------------------------------------------------------

const linuxDefaultDest = "/usr/local/share/ca-certificates/tg-proxy.crt"

type linuxInstaller struct {
	runner runner
	dest   string
}

func newLinuxInstaller() *linuxInstaller {
	return &linuxInstaller{runner: execRunner{}, dest: linuxDefaultDest}
}

func (i *linuxInstaller) Describe() string {
	return fmt.Sprintf("linux: copy CA to %s and run update-ca-certificates", i.dest)
}

func (i *linuxInstaller) Install(certPath string) error {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("ca: read source cert: %w", err)
	}
	if err := os.WriteFile(i.dest, data, 0o644); err != nil { //nolint:gosec // CA certs are public.
		return fmt.Errorf("ca: write %s: %w", i.dest, err)
	}
	out, err := i.runner.Run("update-ca-certificates")
	if err != nil {
		return fmt.Errorf("ca: update-ca-certificates: %w (%s)", err, string(out))
	}
	return nil
}

func (i *linuxInstaller) Uninstall(_ string) error {
	if err := os.Remove(i.dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ca: remove %s: %w", i.dest, err)
	}
	out, err := i.runner.Run("update-ca-certificates", "--fresh")
	if err != nil {
		return fmt.Errorf("ca: update-ca-certificates --fresh: %w (%s)", err, string(out))
	}
	return nil
}

// --- macOS -----------------------------------------------------------------

const darwinSystemKeychain = "/Library/Keychains/System.keychain"

type darwinInstaller struct {
	runner   runner
	keychain string
}

func newDarwinInstaller() *darwinInstaller {
	return &darwinInstaller{runner: execRunner{}, keychain: darwinSystemKeychain}
}

func (i *darwinInstaller) Describe() string {
	return "darwin: security add-trusted-cert -d -r trustRoot -k " + i.keychain
}

func (i *darwinInstaller) Install(certPath string) error {
	out, err := i.runner.Run("security", "add-trusted-cert",
		"-d", "-r", "trustRoot", "-k", i.keychain, certPath)
	if err != nil {
		return fmt.Errorf("ca: security add-trusted-cert: %w (%s)", err, string(out))
	}
	return nil
}

func (i *darwinInstaller) Uninstall(certPath string) error {
	cert, err := loadCertPEM(certPath)
	if err != nil {
		return err
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		return errors.New("ca: certificate has no CommonName; cannot remove from keychain")
	}
	out, err := i.runner.Run("security", "delete-certificate", "-c", cn, i.keychain)
	if err != nil {
		return fmt.Errorf("ca: security delete-certificate: %w (%s)", err, string(out))
	}
	return nil
}

// --- Windows ---------------------------------------------------------------

type windowsInstaller struct {
	runner runner
	store  string
}

func newWindowsInstaller() *windowsInstaller {
	return &windowsInstaller{runner: execRunner{}, store: "Root"}
}

func (i *windowsInstaller) Describe() string {
	return "windows: certutil -addstore -f " + i.store
}

func (i *windowsInstaller) Install(certPath string) error {
	out, err := i.runner.Run("certutil", "-addstore", "-f", i.store, certPath)
	if err != nil {
		return fmt.Errorf("ca: certutil -addstore: %w (%s)", err, string(out))
	}
	return nil
}

func (i *windowsInstaller) Uninstall(certPath string) error {
	cert, err := loadCertPEM(certPath)
	if err != nil {
		return err
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		return errors.New("ca: certificate has no CommonName; cannot remove from store")
	}
	out, err := i.runner.Run("certutil", "-delstore", i.store, cn)
	if err != nil {
		return fmt.Errorf("ca: certutil -delstore: %w (%s)", err, string(out))
	}
	return nil
}

// --- Unsupported -----------------------------------------------------------

type unsupportedInstaller struct{ os string }

func (u unsupportedInstaller) Describe() string {
	return "trust-store install is not supported on " + u.os
}

func (u unsupportedInstaller) Install(string) error {
	return fmt.Errorf("ca: trust-store install not supported on %s", u.os)
}

func (u unsupportedInstaller) Uninstall(string) error {
	return fmt.Errorf("ca: trust-store uninstall not supported on %s", u.os)
}
