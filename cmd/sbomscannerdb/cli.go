package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// refArgsUsage documents the reference argument shared by build/push/pull.
const refArgsUsage = "<registry>/<repo>:<tag>"

// rootCommand builds the CLI command tree.
// All flag/argument parsing lives here; the internal packages are plain libraries.
func rootCommand() *cli.Command {
	return &cli.Command{
		Name:  "sbomscannerdb",
		Usage: "Build and distribute the sbomscanner DB as an OCI artifact",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "debug", Usage: "enable debug logging"},
		},
		// No-op: errors flow back to run() in main.go instead of os.Exit-ing inside Run.
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Commands: []*cli.Command{
			buildCommand(),
			listCommand(),
			pushCommand(),
			pullCommand(),
		},
		// Reached for a bare invocation (help, exit 0)
		// or an unknown top-level command (help + error, exit 2).
		Action: func(_ context.Context, cmd *cli.Command) error {
			if !cmd.Args().Present() {
				return cli.ShowAppHelp(cmd)
			}
			if err := cli.ShowAppHelp(cmd); err != nil {
				return fmt.Errorf("show help: %w", err)
			}
			return cli.Exit(fmt.Sprintf("unknown command %q", cmd.Args().First()), 2)
		},
	}
}

func buildCommand() *cli.Command {
	return &cli.Command{
		Name:      "build",
		Usage:     "Download KEV/EPSS and build the DB artifact into the local store",
		ArgsUsage: refArgsUsage,
		Arguments: referenceArguments(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.StringArgs("reference")[0]
			if err := runBuild(ctx, ref, newLogger(cmd)); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

func listCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List DB artifacts in the local store",
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return cli.Exit(fmt.Sprintf("list: unexpected arguments: %v", cmd.Args().Slice()), 2)
			}
			if err := runList(newLogger(cmd)); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

func pushCommand() *cli.Command {
	return &cli.Command{
		Name:      "push",
		Usage:     "Push a built artifact from the local store to a registry",
		ArgsUsage: refArgsUsage,
		Arguments: referenceArguments(),
		Flags:     registryFlags(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.StringArgs("reference")[0]
			if err := runPush(ctx, ref, registryConfig(cmd), newLogger(cmd)); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

func pullCommand() *cli.Command {
	return &cli.Command{
		Name:      "pull",
		Usage:     "Pull the artifact from a registry and write the KEV/EPSS data files to the current directory",
		ArgsUsage: refArgsUsage,
		Arguments: referenceArguments(),
		Flags:     registryFlags(),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ref := cmd.StringArgs("reference")[0]
			if err := runPull(ctx, ref, registryConfig(cmd), newLogger(cmd)); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

// newLogger builds the stderr text logger, honoring the global --debug flag.
func newLogger(cmd *cli.Command) *slog.Logger {
	level := slog.LevelInfo
	if cmd.Bool("debug") {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// registryFlags returns the flags shared by pull and push.
func registryFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "skip-tls-verify", Usage: "skip TLS certificate verification"},
		&cli.BoolFlag{Name: "plain-http", Usage: "use HTTP instead of HTTPS"},
	}
}

// registryConfig maps the shared flags into an oci.Config.
func registryConfig(cmd *cli.Command) oci.Config {
	return oci.Config{
		SkipTLSVerify: cmd.Bool("skip-tls-verify"),
		PlainHTTP:     cmd.Bool("plain-http"),
	}
}

// referenceArguments declares the single required reference argument shared by build/push/pull.
// Presence is enforced by the framework (Min: 1).
func referenceArguments() []cli.Argument {
	return []cli.Argument{
		&cli.StringArgs{Name: "reference", UsageText: refArgsUsage, Min: 1, Max: 1},
	}
}
