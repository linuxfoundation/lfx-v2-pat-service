// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
)

const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"

	// tokenColumns is the owner-visible projection: never salt or secret_hash.
	tokenColumns = `uid, username, COALESCE(email, ''), audience, name, lookup_id, created_at, updated_at, last_used_at, revoked_at, expires_at`
)

// TokenRepository is the Postgres TokenReader, TokenWriter and CredentialReader.
type TokenRepository struct {
	pool *Pool
}

var (
	_ port.TokenReader      = (*TokenRepository)(nil)
	_ port.TokenWriter      = (*TokenRepository)(nil)
	_ port.CredentialReader = (*TokenRepository)(nil)
)

// NewTokenRepository wires the repository.
func NewTokenRepository(pool *Pool) *TokenRepository {
	return &TokenRepository{pool: pool}
}

// Create implements port.TokenWriter. The active count and the insert run in one transaction under an advisory
// lock keyed by owner and audience, so concurrent creates cannot exceed the limit; name uniqueness is the
// partial unique index.
func (r *TokenRepository) Create(ctx context.Context, t model.NewToken, maxActive int) (model.Token, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return model.Token{}, storeErr("begin create token", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2))`, t.Username, t.Audience); err != nil {
		return model.Token{}, storeErr("lock owner", err)
	}
	var active int
	const countQ = `SELECT count(*) FROM tokens WHERE username = $1 AND audience = $2 AND revoked_at IS NULL`
	if err := tx.QueryRow(ctx, countQ, t.Username, t.Audience).Scan(&active); err != nil {
		return model.Token{}, storeErr("count active tokens", err)
	}
	if active >= maxActive {
		return model.Token{}, errors.NewConflict(constants.ErrCodeTokenLimitReached,
			fmt.Sprintf("limit of %d active tokens for audience %s reached", maxActive, t.Audience))
	}

	const insertQ = `INSERT INTO tokens (username, email, audience, name, lookup_id, salt, secret_hash, expires_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8)
		RETURNING ` + tokenColumns
	row := tx.QueryRow(ctx, insertQ, t.Username, t.Email, t.Audience, t.Name, t.LookupID, t.Salt, t.SecretHash, t.ExpiresAt)
	token, err := scanToken(row)
	if err != nil {
		return model.Token{}, createErr(t, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Token{}, storeErr("commit create token", err)
	}
	return token, nil
}

func createErr(t model.NewToken, err error) error {
	var pgErr *pgconn.PgError
	if stderrors.As(err, &pgErr) {
		switch {
		case pgErr.Code == uniqueViolation && pgErr.ConstraintName == "tokens_active_name_key":
			return errors.NewConflict(constants.ErrCodeTokenNameTaken,
				fmt.Sprintf("a token named %q already exists for audience %s", t.Name, t.Audience))
		case pgErr.Code == uniqueViolation && pgErr.ConstraintName == "tokens_lookup_id_key":
			return port.ErrLookupIDTaken
		case pgErr.Code == foreignKeyViolation:
			return errors.NewValidation(constants.ErrCodeUnknownAudience, fmt.Sprintf("audience %q is unknown or disabled", t.Audience))
		}
	}
	return storeErr("insert token", err)
}

// ListActiveByOwner implements port.TokenReader.
func (r *TokenRepository) ListActiveByOwner(ctx context.Context, username, audience string) ([]model.Token, error) {
	const q = `SELECT ` + tokenColumns + ` FROM tokens
		WHERE username = $1 AND ($2 = '' OR audience = $2) AND revoked_at IS NULL
		ORDER BY created_at DESC, uid DESC`
	rows, err := r.pool.Query(ctx, q, username, audience)
	if err != nil {
		return nil, storeErr("list tokens", err)
	}
	defer rows.Close()

	tokens := make([]model.Token, 0)
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, storeErr("scan token", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, storeErr("list tokens", err)
	}
	return tokens, nil
}

// Revoke implements port.TokenWriter. Revoking twice, or revoking someone else's token, is NotFound.
func (r *TokenRepository) Revoke(ctx context.Context, uid, username string) error {
	const q = `UPDATE tokens SET revoked_at = now(), updated_at = now()
		WHERE uid = $1 AND username = $2 AND revoked_at IS NULL RETURNING uid`
	var revoked string
	if err := r.pool.QueryRow(ctx, q, uid, username).Scan(&revoked); err != nil {
		return notFoundOr("revoke token", uid, err)
	}
	return nil
}

// FindActiveByLookupID implements port.CredentialReader: one indexed lookup of an unexpired token joined on an
// enabled audience whose prefix matches the one parsed from the presented secret.
func (r *TokenRepository) FindActiveByLookupID(ctx context.Context, lookupID, prefix string) (model.Credential, error) {
	const q = `SELECT t.uid, t.username, COALESCE(t.email, ''), t.audience, t.salt, t.secret_hash
		FROM tokens t JOIN audiences a ON a.slug = t.audience
		WHERE t.lookup_id = $1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())
			AND a.enabled AND a.token_prefix = $2`
	var c model.Credential
	err := r.pool.QueryRow(ctx, q, lookupID, prefix).Scan(&c.UID, &c.Username, &c.Email, &c.Audience, &c.Salt, &c.SecretHash)
	if err != nil {
		if stderrors.Is(err, pgx.ErrNoRows) {
			return model.Credential{}, errors.NewNotFound("no active token for lookup id")
		}
		return model.Credential{}, storeErr("find credential", err)
	}
	return c, nil
}

// TouchLastUsed implements port.CredentialReader. It deliberately leaves updated_at alone.
func (r *TokenRepository) TouchLastUsed(ctx context.Context, uid string) error {
	const q = `UPDATE tokens SET last_used_at = now()
		WHERE uid = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`
	tag, err := r.pool.Exec(ctx, q, uid)
	if err != nil {
		return storeErr("touch last used", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.NewNotFound(fmt.Sprintf("no active token %s", uid))
	}
	return nil
}

func scanToken(row pgx.Row) (model.Token, error) {
	var (
		t         model.Token
		created   time.Time
		updated   time.Time
		lastUsed  *time.Time
		revokedAt *time.Time
		expiresAt *time.Time
	)
	err := row.Scan(&t.UID, &t.Username, &t.Email, &t.Audience, &t.Name, &t.LookupID, &created, &updated, &lastUsed, &revokedAt, &expiresAt)
	if err != nil {
		return model.Token{}, err
	}
	t.CreatedAt = created.UTC()
	t.UpdatedAt = updated.UTC()
	t.LastUsedAt = utcPtr(lastUsed)
	t.RevokedAt = utcPtr(revokedAt)
	t.ExpiresAt = utcPtr(expiresAt)
	return t, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func notFoundOr(op, uid string, err error) error {
	if stderrors.Is(err, pgx.ErrNoRows) {
		return errors.NewNotFound(fmt.Sprintf("no active token %s owned by the caller", uid))
	}
	return storeErr(op, err)
}
