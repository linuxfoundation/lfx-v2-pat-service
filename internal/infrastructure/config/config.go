// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package config provides application configuration loaded from CLI flags and environment variables.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
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
	// PGSSLRootCert is the CA bundle path handed to pgx as sslrootcert; empty uses the system roots.
	PGSSLRootCert string
	PGMaxConns    int

	// Store is constants.StorePostgres or constants.StoreMemory.
	Store                string
	MigrateOnStart       bool
	MaxActivePerAudience int
	// AudienceAPIIdentifiers maps an audience slug to the Auth0 API identifier validation reports for it.
	AudienceAPIIdentifiers map[string]string
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
	if !slices.Contains(pgSSLModes, sslMode) {
		return nil, fmt.Errorf("%s must be one of %v, got %q", constants.EnvPGSSLMode, pgSSLModes, sslMode)
	}
	if store == constants.StorePostgres && sslMode != constants.PGSSLModeVerifyFull && !allowInsecureSSL {
		return nil, fmt.Errorf("%s=%s does not verify the database server certificate; use %s, or set %s=true for a local database",
			constants.EnvPGSSLMode, sslMode, constants.PGSSLModeVerifyFull, constants.EnvPGAllowInsecureSSLMode)
	}

	apiIdentifiers, err := audienceAPIIdentifiers(getenv(constants.EnvAudienceAPIIdentifiers))
	if err != nil {
		return nil, err
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

		PGHost:        get(constants.EnvPGHost, ""),
		PGPort:        pgPort,
		PGUser:        get(constants.EnvPGUser, ""),
		PGPassword:    getenv(constants.EnvPGPassword),
		PGDatabase:    get(constants.EnvPGDatabase, ""),
		PGSSLMode:     sslMode,
		PGSSLRootCert: get(constants.EnvPGSSLRootCert, ""),
		PGMaxConns:    maxConns,

		Store:                  store,
		MigrateOnStart:         migrate,
		MaxActivePerAudience:   maxActive,
		AudienceAPIIdentifiers: apiIdentifiers,
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
	q := url.Values{"sslmode": {c.PGSSLMode}}
	if c.PGSSLRootCert != "" {
		q.Set("sslrootcert", c.PGSSLRootCert)
	}
	u := url.URL{
		Scheme:   scheme,
		User:     url.UserPassword(c.PGUser, c.PGPassword),
		Host:     net.JoinHostPort(c.PGHost, c.PGPort),
		Path:     "/" + c.PGDatabase,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// pgSSLModes are the libpq sslmode values pgx accepts.
var pgSSLModes = []string{"disable", "allow", "prefer", "require", "verify-ca", constants.PGSSLModeVerifyFull}

// audienceSlug mirrors the audiences_slug_fmt check constraint.
var audienceSlug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

func audienceAPIIdentifiers(raw string) (map[string]string, error) {
	identifiers := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return identifiers, nil
	}
	if err := json.Unmarshal([]byte(raw), &identifiers); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object of audience slug to API identifier: %w", constants.EnvAudienceAPIIdentifiers, err)
	}
	for slug, identifier := range identifiers {
		if !audienceSlug.MatchString(slug) {
			return nil, fmt.Errorf("%s: %q is not an audience slug", constants.EnvAudienceAPIIdentifiers, slug)
		}
		if strings.TrimSpace(identifier) == "" {
			return nil, fmt.Errorf("%s: audience %q has an empty API identifier", constants.EnvAudienceAPIIdentifiers, slug)
		}
	}
	return identifiers, nil
}

func positiveInt(raw, key string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be a positive integer up to %d, got %q", key, math.MaxInt32, raw)
	}
	return n, nil
}
