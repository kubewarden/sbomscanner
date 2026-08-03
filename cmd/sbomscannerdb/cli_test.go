package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
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

func TestCLI_UnknownFlagIsPlainError(t *testing.T) {
	_, err := runCLI(t, "--nonsense")

	require.Error(t, err)
	var exitCoder cli.ExitCoder
	assert.NotErrorAs(t, err, &exitCoder, "parse errors should not carry an exit code")
}
