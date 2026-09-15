package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
)

// runCLI runs the root command with the given args,
// capturing stdout and discarding the framework's stderr output.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := rootCommand()
	cmd.Writer = &stdout
	cmd.ErrWriter = io.Discard
	err := cmd.Run(context.Background(), append([]string{"sbomscannerdb"}, args...))
	return stdout.String(), err
}

func TestCLI_BareInvocationShowsHelp(t *testing.T) {
	stdout, err := runCLI(t)
	require.NoError(t, err)
	assert.Contains(t, stdout, "USAGE:")
}

func TestCLI_UnknownCommand(t *testing.T) {
	stdout, err := runCLI(t, "frobnicate")

	var exitCoder cli.ExitCoder
	require.ErrorAs(t, err, &exitCoder)
	assert.Equal(t, 2, exitCoder.ExitCode())
	assert.Contains(t, err.Error(), `unknown command "frobnicate"`)
	assert.Contains(t, stdout, "USAGE:")
}

func TestCLI_ListRejectsArguments(t *testing.T) {
	_, err := runCLI(t, "list", "extra")

	var exitCoder cli.ExitCoder
	require.ErrorAs(t, err, &exitCoder)
	assert.Equal(t, 2, exitCoder.ExitCode())
	assert.Contains(t, err.Error(), "unexpected arguments")
}

func TestCLI_BuildFailsOnMissingDataFile(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	_, err := runCLI(t, "build", "--data-dir", t.TempDir(), "registry.example.com/db:latest")

	var exitCoder cli.ExitCoder
	require.ErrorAs(t, err, &exitCoder)
	assert.Equal(t, 1, exitCoder.ExitCode())
	assert.Contains(t, err.Error(), "validate KEV")
}

func TestCLI_BuildFailsOnMalformedDataFile(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, datafeed.KEVSourceFileName), []byte("not json"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, datafeed.EPSSSourceFileName), []byte("not csv"), 0o600))

	_, err := runCLI(t, "build", "--data-dir", dataDir, "registry.example.com/db:latest")

	var exitCoder cli.ExitCoder
	require.ErrorAs(t, err, &exitCoder)
	assert.Equal(t, 1, exitCoder.ExitCode())
	assert.Contains(t, err.Error(), "validate KEV")
}

func TestCLI_BuildFromDataDir(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	_, err := runCLI(t, "build", "--data-dir", filepath.Join("..", "..", "test", "fixtures", "sbomscannerdb"), "registry.example.com/db:latest")

	require.NoError(t, err)
	// The fixture directory is read, never written.
	assert.NoFileExists(t, filepath.Join("..", "..", "test", "fixtures", "sbomscannerdb", datafeed.KEVDBFileName))
}

func TestCLI_ExportRequiresReference(t *testing.T) {
	_, err := runCLI(t, "export", "-o", t.TempDir())

	require.Error(t, err)
}

func TestCLI_ExportFailsForUnknownRef(t *testing.T) {
	// An empty XDG cache dir means an empty local store.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	_, err := runCLI(t, "export", "-o", t.TempDir(), "registry.example.com/nope:missing")

	var exitCoder cli.ExitCoder
	require.ErrorAs(t, err, &exitCoder)
	assert.Equal(t, 1, exitCoder.ExitCode())
	assert.Contains(t, err.Error(), "not found in local store")
}

func TestCLI_UnknownFlagIsPlainError(t *testing.T) {
	_, err := runCLI(t, "--nonsense")

	require.Error(t, err)
	var exitCoder cli.ExitCoder
	assert.NotErrorAs(t, err, &exitCoder, "parse errors should not carry an exit code")
}
