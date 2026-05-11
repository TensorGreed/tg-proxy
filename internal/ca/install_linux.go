//go:build linux

package ca

// DefaultInstaller returns the Linux trust-store installer, which writes the
// CA to /usr/local/share/ca-certificates/ and invokes update-ca-certificates.
// Requires root or sudo.
func DefaultInstaller() Installer { return newLinuxInstaller() }
