//go:build darwin

package ca

// DefaultInstaller returns the macOS trust-store installer, which calls
// `security add-trusted-cert` against /Library/Keychains/System.keychain.
// Requires sudo.
func DefaultInstaller() Installer { return newDarwinInstaller() }
