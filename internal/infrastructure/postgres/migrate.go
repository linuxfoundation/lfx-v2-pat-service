// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres

import (
	stderrors "errors"
	"fmt"
	neturl "net/url"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers the pgx5:// database driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/infrastructure/postgres/migrations"
)

// Migrate applies every pending up migration from the embedded files. url must use golang-migrate's pgx5://
// scheme. It is safe to run on every startup and from several replicas at once: golang-migrate takes an
// advisory lock and skips applied versions. A partially applied migration leaves the schema dirty, which is
// reported here so the process fails fast instead of retrying into the same wall.
func Migrate(url string) error {
	// net/url quotes the whole URL, password included, when it cannot parse it, and main logs startup errors.
	// Parse first so that failure gets a fixed message; pgx already redacts the errors that follow.
	if _, err := neturl.Parse(url); err != nil {
		return fmt.Errorf("init migrator: invalid connection settings (redacted)")
	}
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("open migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, url)
	if err != nil {
		return fmt.Errorf("init migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !stderrors.Is(err, migrate.ErrNoChange) {
		// golang-migrate marks the version dirty before running the SQL and returns the raw SQL error when it
		// fails, so the dirty state has to be re-read here to report it on the first attempt.
		var dirty migrate.ErrDirty
		if !stderrors.As(err, &dirty) {
			if v, isDirty, verr := m.Version(); verr == nil && isDirty {
				return fmt.Errorf("apply migrations (schema left dirty at version %d): %w", v, err)
			}
		}
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
