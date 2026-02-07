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
	root.AddCommand(crawlDomainsCmd())
	root.AddCommand(serveWebCmd())
	root.AddCommand(migrateCmd())
	root.AddCommand(ingestToplistCmd())
	root.AddCommand(ingestRootsCmd())
	root.AddCommand(addCertCmd())

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

func serveWebCmd() *cobra.Command {
	cfg := cmd.DefaultServeWebConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "serve-web",
		Short: "Start the web server",
		Long: `Starts an HTTP server that provides a web interface for inspecting
TLS certificate chains. Users can enter a domain name to retrieve and
inspect its certificate chain.`,
		RunE: func(c *cobra.Command, args []string) error {
			// Apply environment variable defaults
			if cfg.ListenAddr == "" || cfg.ListenAddr == ":8080" {
				if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
					cfg.ListenAddr = addr
				}
			}
			if timeout := os.Getenv("CRAWL_TIMEOUT"); timeout != "" {
				if d, err := time.ParseDuration(timeout); err == nil {
					cfg.CrawlTimeout = d
				}
			}

			applyDBEnvDefaults(cfg.DBConfig)

			return cmd.ServeWeb(context.Background(), cfg)
		},
	}

	// Server flags
	c.Flags().StringVar(&cfg.ListenAddr, "listen", ":8080", "Address to listen on (env: LISTEN_ADDR)")
	c.Flags().DurationVar(&cfg.CrawlTimeout, "timeout", 30*time.Second, "Timeout for crawl operations (env: CRAWL_TIMEOUT)")
	c.Flags().DurationVar(&cfg.ReadTimeout, "read-timeout", 15*time.Second, "HTTP server read timeout")
	c.Flags().DurationVar(&cfg.WriteTimeout, "write-timeout", 60*time.Second, "HTTP server write timeout")
	c.Flags().DurationVar(&cfg.IdleTimeout, "idle-timeout", 120*time.Second, "HTTP server idle timeout")
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

func crawlDomainsCmd() *cobra.Command {
	cfg := cmd.DefaultCrawlDomainsConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "crawl-domains",
		Short: "Crawl domains that are due for automated re-crawling",
		Long: `A scheduled job that selects domains from the database that are due for
re-crawl based on age threshold, crawls them in parallel, and updates the
database with any new certificate chains.

Domains are eligible for crawling when:
- They are marked for automated crawling (auto_crawl = true)
- They are not in automated backoff (unless --ignore-errors is set)
- They are popular domains (unless --include-non-public is set)
- Their last successful crawl is older than the effective age threshold

The effective age is calculated as: (age_days * 24h) - 1h
This allows the job to run daily with a small overlap window for idempotency.`,
		RunE: func(c *cobra.Command, args []string) error {
			// Apply environment variable defaults
			if ageDays := os.Getenv("CERT_OBS_CRAWL_AGE_DAYS"); ageDays != "" {
				if v, err := strconv.Atoi(ageDays); err == nil {
					cfg.AgeDays = v
				}
			}
			if parallel := os.Getenv("CERT_OBS_CRAWL_PARALLEL"); parallel != "" {
				if v, err := strconv.Atoi(parallel); err == nil {
					cfg.Parallel = v
				}
			}
			if rate := os.Getenv("CERT_OBS_CRAWL_RATE"); rate != "" {
				if v, err := strconv.Atoi(rate); err == nil {
					cfg.Rate = v
				}
			}
			if maxSize := os.Getenv("CERT_OBS_CRAWL_MAX_SIZE"); maxSize != "" {
				if v, err := strconv.Atoi(maxSize); err == nil {
					cfg.MaxCrawlSize = v
				}
			}
			if ignoreErrors := os.Getenv("CERT_OBS_CRAWL_IGNORE_ERRORS"); ignoreErrors != "" {
				cfg.IgnoreErrors = ignoreErrors == "true" || ignoreErrors == "1"
			}
			if includeNonPublic := os.Getenv("CERT_OBS_CRAWL_INCLUDE_NON_PUBLIC"); includeNonPublic != "" {
				cfg.IncludeNonPublic = includeNonPublic == "true" || includeNonPublic == "1"
			}

			applyDBEnvDefaults(cfg.DBConfig)

			return cmd.CrawlDomains(context.Background(), cfg)
		},
	}

	// Crawl configuration flags
	c.Flags().IntVar(&cfg.AgeDays, "age-days", 1, "Days since last crawl to qualify for re-crawl (env: CERT_OBS_CRAWL_AGE_DAYS)")
	c.Flags().IntVar(&cfg.Parallel, "parallel", 2, "Number of domains to crawl concurrently (env: CERT_OBS_CRAWL_PARALLEL)")
	c.Flags().IntVar(&cfg.Rate, "rate", -1, "Maximum crawls per second, -1 for unlimited (env: CERT_OBS_CRAWL_RATE)")
	c.Flags().IntVar(&cfg.MaxCrawlSize, "max-crawl-size", 100, "Maximum number of eligible domains to crawl per run (env: CERT_OBS_CRAWL_MAX_SIZE)")
	c.Flags().DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout for each crawl operation")
	c.Flags().BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose/debug logging")
	c.Flags().BoolVar(&cfg.IgnoreErrors, "ignore-errors", false, "Ignore backoff errors and crawl domains anyway (env: CERT_OBS_CRAWL_IGNORE_ERRORS)")
	c.Flags().BoolVar(&cfg.IncludeNonPublic, "include-non-public", false, "Include non-public domains (env: CERT_OBS_CRAWL_INCLUDE_NON_PUBLIC)")

	// Database connection flags
	c.Flags().StringVar(&cfg.DBConfig.Host, "db-host", "", "Database host (env: DB_HOST)")
	c.Flags().IntVar(&cfg.DBConfig.Port, "db-port", 0, "Database port (env: DB_PORT)")
	c.Flags().StringVar(&cfg.DBConfig.User, "db-user", "", "Database user (env: DB_USER)")
	c.Flags().StringVar(&cfg.DBConfig.Password, "db-password", "", "Database password (env: DB_PASSWORD)")
	c.Flags().StringVar(&cfg.DBConfig.Database, "db-name", "", "Database name (env: DB_NAME)")
	c.Flags().StringVar(&cfg.DBConfig.SSLMode, "db-sslmode", "", "Database SSL mode (env: DB_SSLMODE)")

	return c
}

func ingestToplistCmd() *cobra.Command {
	cfg := cmd.DefaultIngestToplistConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "ingest-toplist",
		Short: "Ingest domains from Cloudflare Radar Top 10k list",
		Long: `Fetches the current top domain list from Cloudflare Radar and upserts
domains into the database without crawling them. This seeds future automated crawls.

Domains are inserted with:
- popular_domain = true
- auto_crawl = true

Existing domains have their flags updated if needed. The operation is idempotent.`,
		RunE: func(c *cobra.Command, args []string) error {
			// Apply environment variable defaults
			if token := os.Getenv("CLOUDFLARE_API_TOKEN"); token != "" && cfg.CloudflareToken == "" {
				cfg.CloudflareToken = token
			}

			if cfg.CloudflareToken == "" {
				return fmt.Errorf("--cloudflare-token is required (or set CLOUDFLARE_API_TOKEN)")
			}

			applyDBEnvDefaults(cfg.DBConfig)

			return cmd.IngestToplist(context.Background(), cfg)
		},
	}

	// Ingest configuration flags
	c.Flags().StringVar(&cfg.CloudflareToken, "cloudflare-token", "", "Cloudflare API token (env: CLOUDFLARE_API_TOKEN)")
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

func ingestRootsCmd() *cobra.Command {
	cfg := cmd.DefaultIngestRootsConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "ingest-roots",
		Short: "Ingest root certificates from trusted sources",
		Long: `Fetches and ingests root certificates (PEM format) into the certificate catalog.

The root sources are configured in the embedded roots.yaml file:
- Apple root certificates
- Google root certificates
- Microsoft root certificates
- Mozilla root certificates

Certificates are inserted if not already present. The operation is idempotent.`,
		RunE: func(c *cobra.Command, args []string) error {
			applyDBEnvDefaults(cfg.DBConfig)
			return cmd.IngestRoots(context.Background(), cfg)
		},
	}

	// Ingest configuration flags
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

func addCertCmd() *cobra.Command {
	cfg := cmd.DefaultAddCertConfig()
	cfg.DBConfig = &db.Config{}

	c := &cobra.Command{
		Use:   "add-cert",
		Short: "Add certificates from a PEM file to the certificate catalog",
		Long: `Parses a PEM file containing one or more certificates and ingests them
into the certificate catalog. This is useful for adding root or intermediate
certificates that may not be returned by servers during TLS handshakes.

Certificates are inserted if not already present. The operation is idempotent.`,
		RunE: func(c *cobra.Command, args []string) error {
			if cfg.PEMFile == "" {
				return fmt.Errorf("--pem-file is required")
			}

			applyDBEnvDefaults(cfg.DBConfig)
			return cmd.AddCert(context.Background(), cfg)
		},
	}

	// Add-cert configuration flags
	c.Flags().StringVar(&cfg.PEMFile, "pem-file", "", "Path to PEM file containing certificates (required)")
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
