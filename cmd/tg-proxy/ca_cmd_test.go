package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/ca"
)

type fakeInstaller struct {
	installArg, uninstallArg string
	installErr, uninstallErr error
	describeOut              string
}

func (f *fakeInstaller) Install(p string) error   { f.installArg = p; return f.installErr }
func (f *fakeInstaller) Uninstall(p string) error { f.uninstallArg = p; return f.uninstallErr }
func (f *fakeInstaller) Describe() string {
	if f.describeOut == "" {
		return "fake installer"
	}
	return f.describeOut
}

func withInstaller(t *testing.T, fi ca.Installer) {
	t.Helper()
	orig := installerFactory
	installerFactory = func() ca.Installer { return fi }
	t.Cleanup(func() { installerFactory = orig })
}

func captureCAOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := caCmdOutput
	caCmdOutput = buf
	t.Cleanup(func() { caCmdOutput = orig })
	return buf
}

func TestRunCA_NoArgs(t *testing.T) {
	assert.Error(t, runCA(nil))
}

func TestRunCA_UnknownSubcommand(t *testing.T) {
	err := runCA([]string{"nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nope")
}

func TestRunCAGenerate_WritesFiles(t *testing.T) {
	buf := captureCAOutput(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	require.NoError(t, runCAGenerate([]string{
		"-cert-path", certPath, "-key-path", keyPath, "-org", "Test CA",
	}))

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)
	assert.Contains(t, buf.String(), certPath)

	// Round-trip via LoadRoot to confirm the files are well-formed.
	root, err := ca.LoadRoot(certPath, keyPath)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", root.Cert.Subject.CommonName)
}

func TestRunCAGenerate_RefusesToOverwriteWithoutForce(t *testing.T) {
	captureCAOutput(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, []byte("exists"), 0o644))

	err := runCAGenerate([]string{"-cert-path", certPath, "-key-path", keyPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestRunCAGenerate_ForceOverwrites(t *testing.T) {
	captureCAOutput(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, []byte("exists"), 0o644))

	require.NoError(t, runCAGenerate([]string{
		"-cert-path", certPath, "-key-path", keyPath, "-force",
	}))
	root, err := ca.LoadRoot(certPath, keyPath)
	require.NoError(t, err)
	assert.NotEmpty(t, root.Cert.Subject.CommonName)
}

func TestRunCAInstall_DelegatesToInstaller(t *testing.T) {
	captureCAOutput(t)
	fi := &fakeInstaller{}
	withInstaller(t, fi)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, []byte("placeholder"), 0o644))

	require.NoError(t, runCAInstall([]string{"-cert-path", certPath}))
	assert.Equal(t, certPath, fi.installArg)
}

func TestRunCAInstall_PropagatesError(t *testing.T) {
	captureCAOutput(t)
	fi := &fakeInstaller{installErr: errors.New("permission denied")}
	withInstaller(t, fi)

	certPath := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(certPath, []byte("x"), 0o644))

	err := runCAInstall([]string{"-cert-path", certPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestRunCAUninstall_DelegatesToInstaller(t *testing.T) {
	captureCAOutput(t)
	fi := &fakeInstaller{}
	withInstaller(t, fi)

	certPath := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(certPath, []byte("x"), 0o644))

	require.NoError(t, runCAUninstall([]string{"-cert-path", certPath}))
	assert.Equal(t, certPath, fi.uninstallArg)
}

func TestRunCAPath_PrintsResolvedPaths(t *testing.T) {
	buf := captureCAOutput(t)
	require.NoError(t, runCAPath(nil))
	out := buf.String()
	assert.Contains(t, out, "cert:")
	assert.Contains(t, out, "key:")
}

func TestResolvePaths_ExplicitWins(t *testing.T) {
	cp, kp, err := resolvePaths("/a/b.crt", "/a/b.key")
	require.NoError(t, err)
	assert.Equal(t, "/a/b.crt", cp)
	assert.Equal(t, "/a/b.key", kp)
}

func TestResolvePaths_DefaultsFillIn(t *testing.T) {
	cp, kp, err := resolvePaths("", "")
	require.NoError(t, err)
	assert.NotEmpty(t, cp)
	assert.NotEmpty(t, kp)
}
