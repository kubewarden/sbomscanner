package cmdutil

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// WaitForStorageTypes waits until the storage types resources are available in the cluster.
func WaitForStorageTypes(ctx context.Context, config *rest.Config, logger *slog.Logger) error {
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return fmt.Errorf("failed to create http client: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(config, httpClient)
	if err != nil {
		return fmt.Errorf("failed to create discovery client: %w", err)
	}

	gv := storagev1alpha1.SchemeGroupVersion.String()
	err = retry.Do(
		func() error {
			logger.Info("Checking for storage types availability", "groupVersion", gv)
			_, err := discoveryClient.ServerResourcesForGroupVersion(gv)
			if err != nil {
				return fmt.Errorf("group version not available: %s: %w", gv, err)
			}
			return nil
		},
		retryOptions(ctx, func(n uint, err error) {
			logger.InfoContext(ctx, "Checking for storage types failed, retrying", "attempt", n+1, "error", err)
		})...,
	)
	if err != nil {
		return fmt.Errorf("timeout while waiting for storage types: %w", err)
	}

	logger.InfoContext(ctx, "Storage types are available, continuing.")
	return nil
}

// WaitForNATS waits until NATS is available.
func WaitForNATS(ctx context.Context, url string, opts []nats.Option, logger *slog.Logger) error {
	err := retry.Do(
		func() error {
			logger.InfoContext(ctx, "Checking for NATS availability")
			nc, err := nats.Connect(url, opts...)
			if err != nil {
				return fmt.Errorf("failed to connect to NATS: %w", err)
			}
			nc.Close()
			return nil
		},
		retryOptions(ctx, func(n uint, err error) {
			logger.InfoContext(ctx, "Checking for NATS failed, retrying", "attempt", n+1, "error", err)
		})...,
	)
	if err != nil {
		return fmt.Errorf("timeout while waiting for NATS: %w", err)
	}

	logger.InfoContext(ctx, "NATS is available, continuing.")
	return nil
}

// WaitForJetStream waits until JetStream is available on the NATS server.
func WaitForJetStream(ctx context.Context, url string, opts []nats.Option, logger *slog.Logger) error {
	err := retry.Do(
		func() error {
			logger.InfoContext(ctx, "Checking for JetStream availability")
			nc, err := nats.Connect(url, opts...)
			if err != nil {
				return fmt.Errorf("failed to connect to NATS: %w", err)
			}
			defer nc.Close()

			js, err := nc.JetStream()
			if err != nil {
				return fmt.Errorf("JetStream not available: %w", err)
			}

			_, err = js.AccountInfo()
			if err != nil {
				return fmt.Errorf("failed to get JetStream account info: %w", err)
			}

			return nil
		},
		retryOptions(ctx, func(n uint, err error) {
			logger.InfoContext(ctx, "Checking for JetStream failed, retrying", "attempt", n+1, "error", err)
		})...,
	)
	if err != nil {
		return fmt.Errorf("timeout while waiting for JetStream: %w", err)
	}

	logger.InfoContext(ctx, "JetStream is available, continuing.")
	return nil
}

func WaitForPostgres(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	err := retry.Do(
		func() error {
			logger.InfoContext(ctx, "Checking for Postgres availability")
			err := db.Ping(ctx)
			if err != nil {
				return fmt.Errorf("failed to ping database: %w", err)
			}
			return nil
		},
		retryOptions(ctx, func(n uint, err error) {
			logger.Info("Checking for Postgres failed, retrying", "attempt", n+1, "error", err)
		})...,
	)
	if err != nil {
		return fmt.Errorf("timeout while waiting for Postgres: %w", err)
	}

	logger.InfoContext(ctx, "Postgres is available, continuing.")
	return nil
}

func retryOptions(ctx context.Context, onRetry retry.OnRetryFunc) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.Attempts(20),
		retry.Delay(2 * time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(10 * time.Second),
		retry.LastErrorOnly(true),
		retry.OnRetry(onRetry),
	}
}
