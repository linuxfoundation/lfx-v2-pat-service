// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package config provides application configuration loaded from CLI flags and environment variables.
package config

import (
	"flag"
	"fmt"
	"log/slog"
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

	MigrateOnStart bool
	// ValidatorPrincipals is the comma-separated allow-list for the validate endpoint. Empty allows nobody.
	ValidatorPrincipals  string
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

	return &Config{
		Host:  get(constants.EnvHost, constants.DefaultHost),
		Port:  get(constants.EnvPort, constants.DefaultHTTPPort),
		Debug: getenv(constants.EnvDebug) == "true",

		JWKSUrl:            get(constants.EnvJWKSURL, constants.DefaultJWKSURL),
		Audience:           get(constants.EnvAudience, constants.DefaultAudience),
		Issuer:             get(constants.EnvIssuer, constants.DefaultIssuer),
		MockLocalPrincipal: strings.TrimSpace(getenv(constants.EnvMockLocalPrincipal)),

		PGHost:     get(constants.EnvPGHost, ""),
		PGPort:     get(constants.EnvPGPort, constants.DefaultPGPort),
		PGUser:     get(constants.EnvPGUser, ""),
		PGPassword: getenv(constants.EnvPGPassword),
		PGDatabase: get(constants.EnvPGDatabase, ""),
		PGSSLMode:  get(constants.EnvPGSSLMode, constants.DefaultPGSSLMode),
		PGMaxConns: maxConns,

		MigrateOnStart:       migrate,
		ValidatorPrincipals:  getenv(constants.EnvValidatorPrincipals),
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
		Scheme:   scheme,
		User:     url.UserPassword(c.PGUser, c.PGPassword),
		Host:     net.JoinHostPort(c.PGHost, c.PGPort),
		Path:     "/" + c.PGDatabase,
		RawQuery: url.Values{"sslmode": {c.PGSSLMode}}.Encode(),
	}
	return u.String()
}

func positiveInt(raw, key string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, raw)
	}
	return n, nil
}
