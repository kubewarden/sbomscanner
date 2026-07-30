package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"
)

func main() {
	os.Exit(run())
}

// run executes the CLI and maps its errors to exit codes:
// 0 = success, 1 = runtime error, 2 = usage error.
// The root command's no-op ExitErrHandler guarantees every error
// returns here instead of exiting inside Run.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := rootCommand().Run(ctx, os.Args)
	if err == nil {
		return 0
	}

	var exitCoder cli.ExitCoder
	if errors.As(err, &exitCoder) {
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return exitCoder.ExitCode()
	}

	// Parse errors are already printed by the framework with the usage text.
	return 2
}
