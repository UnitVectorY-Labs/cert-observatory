package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/cmd"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/spf13/cobra"
)

// Version is the application version, injected at build time via ldflags
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "cert-observatory",
		Short:   "TLS certificate chain observatory",
		Long:    "Fetches and stores TLS certificate chains presented by domains.",
		Version: Version,
	}

	root.AddCommand(crawlDomainCmd())
	root.AddCommand(migrateCmd())

	return root
}

func crawlDomainCmd() *cobra.Command {
	cfg := cmd.DefaultCrawlDomainConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "crawl-domain",
		Short: "Crawl a single domain and store its certificate chain",
		Long: `Performs a TLS handshake to the specified domain on port 443,
captures the peer-provided certificate chain, and stores the results in the database.

The certificate chain is output to stdout in PEM format.
All logging and errors are output to stderr.`,
		RunE: func(c *cobra.Command, args []string) error {
			if cfg.URL == "" {
				return fmt.Errorf("--url is required")
			}

			// Apply environment variable defaults for database config
			applyDBEnvDefaults(cfg.DBConfig)

			return cmd.CrawlDomain(context.Background(), cfg)
		},
	}

	// Domain crawl flags
	c.Flags().StringVar(&cfg.URL, "url", "", "Domain to crawl (required, hostname only, no scheme or port)")
	c.Flags().DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout for connection and handshake")
	c.Flags().BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose/debug logging")

	// Database connection flags
	c.Flags().StringVar(&cfg.DBConfig.Host, "db-host", "", "Database host (env: DB_HOST)")
	c.Flags().IntVar(&cfg.DBConfig.Port, "db-port", 0, "Database port (env: DB_PORT)")
	c.Flags().StringVar(&cfg.DBConfig.User, "db-user", "", "Database user (env: DB_USER)")
	c.Flags().StringVar(&cfg.DBConfig.Password, "db-password", "", "Database password (env: DB_PASSWORD)")
	c.Flags().StringVar(&cfg.DBConfig.Database, "db-name", "", "Database name (env: DB_NAME)")
	c.Flags().StringVar(&cfg.DBConfig.SSLMode, "db-sslmode", "", "Database SSL mode (env: DB_SSLMODE)")

	return c
}

// applyDBEnvDefaults applies environment variable defaults to database config
// if the corresponding flag was not set.
func applyDBEnvDefaults(cfg *db.Config) {
	if cfg.Host == "" {
		cfg.Host = os.Getenv("DB_HOST")
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}

	if cfg.Port == 0 {
		if portStr := os.Getenv("DB_PORT"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				cfg.Port = port
			}
		}
	}
	if cfg.Port == 0 {
		cfg.Port = 5432
	}

	if cfg.User == "" {
		cfg.User = os.Getenv("DB_USER")
	}
	if cfg.User == "" {
		cfg.User = "postgres"
	}

	if cfg.Password == "" {
		cfg.Password = os.Getenv("DB_PASSWORD")
	}

	if cfg.Database == "" {
		cfg.Database = os.Getenv("DB_NAME")
	}
	if cfg.Database == "" {
		cfg.Database = "cert_observatory"
	}

	if cfg.SSLMode == "" {
		cfg.SSLMode = os.Getenv("DB_SSLMODE")
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}
}

func migrateCmd() *cobra.Command {
	cfg := cmd.DefaultMigrateConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database migrations",
		Long:  "Run database migrations to keep the schema up to date.",
	}

	// Subcommand: up
	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		RunE: func(c *cobra.Command, args []string) error {
			applyDBEnvDefaults(cfg.DBConfig)
			return cmd.MigrateUp(context.Background(), cfg)
		},
	}

	// Subcommand: status
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current migration status",
		RunE: func(c *cobra.Command, args []string) error {
			applyDBEnvDefaults(cfg.DBConfig)
			return cmd.MigrateStatus(context.Background(), cfg)
		},
	}

	// Add database flags to both subcommands
	for _, sub := range []*cobra.Command{upCmd, statusCmd} {
		sub.Flags().StringVar(&cfg.DBConfig.Host, "db-host", "", "Database host (env: DB_HOST)")
		sub.Flags().IntVar(&cfg.DBConfig.Port, "db-port", 0, "Database port (env: DB_PORT)")
		sub.Flags().StringVar(&cfg.DBConfig.User, "db-user", "", "Database user (env: DB_USER)")
		sub.Flags().StringVar(&cfg.DBConfig.Password, "db-password", "", "Database password (env: DB_PASSWORD)")
		sub.Flags().StringVar(&cfg.DBConfig.Database, "db-name", "", "Database name (env: DB_NAME)")
		sub.Flags().StringVar(&cfg.DBConfig.SSLMode, "db-sslmode", "", "Database SSL mode (env: DB_SSLMODE)")
	}

	c.AddCommand(upCmd)
	c.AddCommand(statusCmd)

	return c
}
