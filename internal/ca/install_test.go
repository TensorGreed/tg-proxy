package ca

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRunner records every shell-out and returns canned results.
type fakeRunner struct {
	calls   [][]string
	failOn  string  // command name that should error
	failMsg string
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	c := append([]string{name}, args...)
	f.calls = append(f.calls, c)
	if f.failOn == name {
		return []byte(f.failMsg), errors.New(f.failMsg)
	}
	return nil, nil
}

func writeFakeCert(t *testing.T) string {
	t.Helper()
	r, err := NewRoot("Install Test CA")
	require.NoError(t, err)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, SaveRoot(r, certPath, keyPath))
	return certPath
}

func TestLinuxInstaller_Install(t *testing.T) {
	certPath := writeFakeCert(t)

	dest := filepath.Join(t.TempDir(), "linux-ca.crt")
	runner := &fakeRunner{}
	inst := &linuxInstaller{runner: runner, dest: dest}

	require.NoError(t, inst.Install(certPath))

	// File should have been copied.
	assert.FileExists(t, dest)
	// update-ca-certificates should have been invoked.
	require.Len(t, runner.calls, 1)
	assert.Equal(t, "update-ca-certificates", runner.calls[0][0])
}

func TestLinuxInstaller_InstallReportsRunnerError(t *testing.T) {
	certPath := writeFakeCert(t)
	dest := filepath.Join(t.TempDir(), "linux-ca.crt")
	runner := &fakeRunner{failOn: "update-ca-certificates", failMsg: "boom"}
	inst := &linuxInstaller{runner: runner, dest: dest}

	err := inst.Install(certPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update-ca-certificates")
}

func TestLinuxInstaller_Uninstall(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "linux-ca.crt")
	// Create the file so removal is exercised.
	require.NoError(t, os.WriteFile(dest, []byte("x"), 0o644))

	runner := &fakeRunner{}
	inst := &linuxInstaller{runner: runner, dest: dest}
	require.NoError(t, inst.Uninstall(""))

	assert.NoFileExists(t, dest)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{"update-ca-certificates", "--fresh"}, runner.calls[0])
}

func TestLinuxInstaller_UninstallMissingFileOK(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "never-existed.crt")
	runner := &fakeRunner{}
	inst := &linuxInstaller{runner: runner, dest: dest}
	require.NoError(t, inst.Uninstall(""))
	require.Len(t, runner.calls, 1)
}

func TestLinuxInstaller_Describe(t *testing.T) {
	i := newLinuxInstaller()
	assert.Contains(t, i.Describe(), linuxDefaultDest)
}

func TestDarwinInstaller_Install(t *testing.T) {
	certPath := writeFakeCert(t)

	runner := &fakeRunner{}
	inst := &darwinInstaller{runner: runner, keychain: darwinSystemKeychain}
	require.NoError(t, inst.Install(certPath))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, "security", runner.calls[0][0])
	assert.Contains(t, runner.calls[0], "add-trusted-cert")
	assert.Contains(t, runner.calls[0], certPath)
}

func TestDarwinInstaller_Uninstall(t *testing.T) {
	certPath := writeFakeCert(t)
	runner := &fakeRunner{}
	inst := &darwinInstaller{runner: runner, keychain: darwinSystemKeychain}
	require.NoError(t, inst.Uninstall(certPath))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, "security", runner.calls[0][0])
	assert.Contains(t, runner.calls[0], "delete-certificate")
	assert.Contains(t, runner.calls[0], "Install Test CA")
}

func TestDarwinInstaller_UninstallMissingCertFails(t *testing.T) {
	runner := &fakeRunner{}
	inst := &darwinInstaller{runner: runner, keychain: darwinSystemKeychain}
	err := inst.Uninstall(filepath.Join(t.TempDir(), "nope.crt"))
	assert.Error(t, err)
	assert.Empty(t, runner.calls, "must not shell out if we could not read the cert")
}

func TestDarwinInstaller_Describe(t *testing.T) {
	assert.Contains(t, newDarwinInstaller().Describe(), darwinSystemKeychain)
}

func TestWindowsInstaller_Install(t *testing.T) {
	certPath := writeFakeCert(t)
	runner := &fakeRunner{}
	inst := &windowsInstaller{runner: runner, store: "Root"}
	require.NoError(t, inst.Install(certPath))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{"certutil", "-addstore", "-f", "Root", certPath}, runner.calls[0])
}

func TestWindowsInstaller_Uninstall(t *testing.T) {
	certPath := writeFakeCert(t)
	runner := &fakeRunner{}
	inst := &windowsInstaller{runner: runner, store: "Root"}
	require.NoError(t, inst.Uninstall(certPath))

	require.Len(t, runner.calls, 1)
	assert.Equal(t, []string{"certutil", "-delstore", "Root", "Install Test CA"}, runner.calls[0])
}

func TestWindowsInstaller_Describe(t *testing.T) {
	assert.Contains(t, newWindowsInstaller().Describe(), "certutil")
}

func TestUnsupportedInstaller_AllOpsError(t *testing.T) {
	u := unsupportedInstaller{os: "plan9"}
	assert.Contains(t, u.Describe(), "plan9")
	assert.Error(t, u.Install(""))
	assert.Error(t, u.Uninstall(""))
}

func TestDefaultInstaller_ReturnsNonNil(t *testing.T) {
	assert.NotNil(t, DefaultInstaller())
}

