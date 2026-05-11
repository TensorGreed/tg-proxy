//go:build windows

package ca

// DefaultInstaller returns the Windows trust-store installer, which calls
// `certutil -addstore Root`. Must be run from an Administrator command
// prompt or PowerShell.
func DefaultInstaller() Installer { return newWindowsInstaller() }
