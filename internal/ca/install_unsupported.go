//go:build !linux && !darwin && !windows

package ca

import "runtime"

// DefaultInstaller returns a stub that reports "unsupported OS" for every
// operation. The real installers live in install_{linux,darwin,windows}.go.
func DefaultInstaller() Installer {
	return unsupportedInstaller{os: runtime.GOOS}
}
