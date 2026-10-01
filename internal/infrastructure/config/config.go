// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package config provides application configuration loaded from CLI flags and environment variables.
package config

import (
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
)

// Config holds application configuration.
type Config struct {
	Host  string
	Port  string
	Debug bool

	JWKSUrl  string
	Audience string
	Issuer   string
	// MockLocalPrincipal, when set, replaces JWT verification with a fixed caller. Local development only.
	MockLocalPrincipal string

	PGHost     string
	PGPort     string
	PGUser     string
	PGPassword string
	PGDatabase string
	PGSSLMode  string
	PGMaxConns int
	// PGSSLRootCert is the path to the PEM CA bundle file the server certificate must chain to (pgx sslrootcert);
	// empty uses the system trust store.
	PGSSLRootCert string
	// PGAllowInsecureSSLMode permits a PGSSLMode weaker than verify-full. Local development only.
	PGAllowInsecureSSLMode bool

	// Store is constants.StorePostgres or constants.StoreMemory.
	Store                string
	MigrateOnStart       bool
	MaxActivePerAudience int
}

// LoadConfig loads configuration from CLI flags, then environment variables, then defaults.
// Priority: CLI flags > env vars > defaults.
func LoadConfig() (*Config, error) {
	slog.Info("loading application configuration")

	cfg, err := FromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}

	portF := flag.String("p", cfg.Port, "listen port")
	hostF := flag.String("bind", cfg.Host, "interface to bind on")
	dbgF := flag.Bool("d", cfg.Debug, "enable debug logging")
	flag.Parse()

	cfg.Port = *portF
	cfg.Host = *hostF
	cfg.Debug = *dbgF
	return cfg, nil
}

// FromEnv builds the configuration from the given lookup, applying defaults. It is what LoadConfig uses and
// what tests call directly, since the process-wide flag set can only be parsed once.
func FromEnv(getenv func(string) string) (*Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	maxConns, err := positiveInt(get(constants.EnvPGMaxConns, strconv.Itoa(constants.DefaultPGMaxConns)), constants.EnvPGMaxConns)
	if err != nil {
		return nil, err
	}
	maxActive, err := positiveInt(get(constants.EnvMaxActivePerAudience, strconv.Itoa(constants.DefaultMaxActivePerAudience)), constants.EnvMaxActivePerAudience)
	if err != nil {
		return nil, err
	}
	migrate, err := strconv.ParseBool(get(constants.EnvMigrateOnStart, strconv.FormatBool(constants.DefaultMigrateOnStart)))
	if err != nil {
		return nil, fmt.Errorf("%s must be a boolean: %w", constants.EnvMigrateOnStart, err)
	}
	store := get(constants.EnvStore, constants.DefaultStore)
	if store != constants.StorePostgres && store != constants.StoreMemory {
		return nil, fmt.Errorf("%s must be %q or %q, got %q", constants.EnvStore, constants.StorePostgres, constants.StoreMemory, store)
	}

	allowInsecureSSL, err := strconv.ParseBool(get(constants.EnvPGAllowInsecureSSLMode, "false"))
	if err != nil {
		return nil, fmt.Errorf("%s must be a boolean: %w", constants.EnvPGAllowInsecureSSLMode, err)
	}
	sslMode := get(constants.EnvPGSSLMode, constants.DefaultPGSSLMode)
	if store == constants.StorePostgres {
		if err := checkSSLMode(sslMode, allowInsecureSSL); err != nil {
			return nil, err
		}
	}

	pgPort := get(constants.EnvPGPort, constants.DefaultPGPort)
	if n, err := strconv.Atoi(pgPort); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%s must be a TCP port, got %q", constants.EnvPGPort, pgPort)
	}

	return &Config{
		Host:  get(constants.EnvHost, constants.DefaultHost),
		Port:  get(constants.EnvPort, constants.DefaultHTTPPort),
		Debug: getenv(constants.EnvDebug) == "true",

		JWKSUrl:            get(constants.EnvJWKSURL, constants.DefaultJWKSURL),
		Audience:           get(constants.EnvAudience, constants.DefaultAudience),
		Issuer:             get(constants.EnvIssuer, constants.DefaultIssuer),
		MockLocalPrincipal: strings.TrimSpace(getenv(constants.EnvMockLocalPrincipal)),

		PGHost:     get(constants.EnvPGHost, ""),
		PGPort:     pgPort,
		PGUser:     get(constants.EnvPGUser, ""),
		PGPassword: getenv(constants.EnvPGPassword),
		PGDatabase: get(constants.EnvPGDatabase, ""),
		PGSSLMode:  sslMode,
		PGMaxConns: maxConns,

		PGSSLRootCert:          get(constants.EnvPGSSLRootCert, ""),
		PGAllowInsecureSSLMode: allowInsecureSSL,

		Store:                store,
		MigrateOnStart:       migrate,
		MaxActivePerAudience: maxActive,
	}, nil
}

// ServerAddress returns the address the HTTP server should bind to.
func (c *Config) ServerAddress() string {
	if c.Host == "*" {
		return ":" + c.Port
	}
	return c.Host + ":" + c.Port
}

// DatabaseConfigured reports whether every variable needed to reach Postgres is set.
func (c *Config) DatabaseConfigured() bool {
	return c.PGHost != "" && c.PGUser != "" && c.PGPassword != "" && c.PGDatabase != ""
}

// PostgresURL composes the connection URL in-process so the password is never interpolated by Helm or logged.
// scheme is "postgres" for pgx and "pgx5" for golang-migrate.
func (c *Config) PostgresURL(scheme string) string {
	u := url.URL{
		Scheme: scheme,
		User:   url.UserPassword(c.PGUser, c.PGPassword),
		Host:   net.JoinHostPort(c.PGHost, c.PGPort),
		Path:   "/" + c.PGDatabase,
	}
	q := url.Values{"sslmode": {c.PGSSLMode}}
	if c.PGSSLRootCert != "" {
		// Explicit so the pool and the migrator read the same CA file whatever pgx merges from the env.
		q.Set("sslrootcert", c.PGSSLRootCert)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// checkSSLMode refuses any sslmode that does not authenticate the server unless insecure modes are explicitly
// allowed. Under pgx (libpq semantics) require encrypts but accepts any certificate, and verify-ca accepts any
// certificate the CA issued for any host, so neither authenticates the database server.
func checkSSLMode(mode string, allowInsecure bool) error {
	switch mode {
	case constants.PGSSLModeVerifyFull:
		return nil
	case "disable", "allow", "prefer", "require", "verify-ca":
		if allowInsecure {
			return nil
		}
		return fmt.Errorf("%s=%s does not verify the database server certificate; use %s (with %s set to the CA bundle file "+
			"when the server's CA is not in the system trust store, as for RDS), or set %s=true for local development",
			constants.EnvPGSSLMode, mode, constants.PGSSLModeVerifyFull, constants.EnvPGSSLRootCert, constants.EnvPGAllowInsecureSSLMode)
	default:
		return fmt.Errorf("%s must be one of disable, allow, prefer, require, verify-ca or verify-full, got %q", constants.EnvPGSSLMode, mode)
	}
}

func positiveInt(raw, key string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be a positive integer up to %d, got %q", key, math.MaxInt32, raw)
	}
	return n, nil
}
