// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package auth verifies the Heimdall-issued JWT on every request and resolves the caller behind it.
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/linuxfoundation/lfx-v2-pat-service/internal/domain"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/log"
)

const (
	// signatureAlgorithm is the default for Heimdall's JWT finalizer.
	signatureAlgorithm = validator.PS256
	jwksCacheTTL       = 5 * time.Minute
	allowedClockSkew   = 5 * time.Second
)

// Config holds the parameters for verifying Heimdall JWTs.
type Config struct {
	// JWKSURL is the JSON Web Key Set endpoint Heimdall signs with.
	JWKSURL string
	// Issuer is the expected "iss" claim.
	Issuer string
	// Audience is the expected "aud" claim.
	Audience string
}

// HeimdallClaims are the custom claims Heimdall's create_jwt finalizer emits. principal is the LFID username
// for users, "<client_id>@clients" for machine tokens and "_anonymous" for the anonymous authenticator.
type HeimdallClaims struct {
	Principal string `json:"principal"`
	Email     string `json:"email,omitempty"`
}

// Validate rejects tokens that carry no usable principal. Heimdall's anonymous fallback still mints a valid JWT,
// so the anonymous principal is refused here rather than trusted downstream.
func (c *HeimdallClaims) Validate(_ context.Context) error {
	switch c.Principal {
	case "":
		return fmt.Errorf("principal must be provided")
	case constants.AnonymousPrincipal:
		return fmt.Errorf("anonymous principal is not allowed")
	}
	return nil
}

// JWTAuth verifies JWTs issued by Heimdall.
type JWTAuth struct {
	validator *validator.Validator
	config    Config
}

var _ domain.Authenticator = (*JWTAuth)(nil)

// NewJWTAuth builds a verifier that fetches and caches Heimdall's JWKS.
func NewJWTAuth(config Config) (*JWTAuth, error) {
	jwksURL, err := url.Parse(config.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %w", err)
	}
	if (jwksURL.Scheme != "http" && jwksURL.Scheme != "https") || jwksURL.Host == "" {
		return nil, fmt.Errorf("invalid JWKS URL %q: must be an absolute http or https URL", config.JWKSURL)
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	provider := jwks.NewCachingProvider(issuer, jwksCacheTTL, jwks.WithCustomJWKSURI(jwksURL))

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		signatureAlgorithm,
		issuer.String(),
		[]string{config.Audience},
		validator.WithCustomClaims(func() validator.CustomClaims { return &HeimdallClaims{} }),
		validator.WithAllowedClockSkew(allowedClockSkew),
	)
	if err != nil {
		return nil, fmt.Errorf("set up JWT validator: %w", err)
	}
	return &JWTAuth{validator: jwtValidator, config: config}, nil
}

// Authenticate implements domain.Authenticator. Every failure is an Unauthorized error whose message is trimmed
// to at most two nesting levels so library internals do not reach the client.
func (j *JWTAuth) Authenticate(ctx context.Context, token string) (domain.Caller, error) {
	parsed, err := j.validator.ValidateToken(ctx, token)
	if err != nil {
		slog.WarnContext(ctx, "authorization failed",
			"audience", j.config.Audience,
			"issuer", j.config.Issuer,
			log.ErrKey, err,
		)
		return domain.Caller{}, errors.NewUnauthorized(sanitize(err))
	}

	claims, ok := parsed.(*validator.ValidatedClaims)
	if !ok {
		return domain.Caller{}, errors.NewUnauthorized("failed to get validated authorization claims")
	}
	heimdall, ok := claims.CustomClaims.(*HeimdallClaims)
	if !ok {
		return domain.Caller{}, errors.NewUnauthorized("failed to get custom authorization claims")
	}

	slog.DebugContext(ctx, "JWT principal parsed", "principal", heimdall.Principal)
	return domain.Caller{Principal: heimdall.Principal, Email: heimdall.Email}, nil
}

// sanitize drops the tertiary and deeper nested errors, using colons as an approximation of the wrapping
// boundaries, so the client sees why validation failed but not the library's internals.
func sanitize(err error) string {
	msg := strings.Replace(err.Error(), ": go-jose/go-jose/jwt", "", 1)
	first := strings.Index(msg, ":")
	if first == -1 || first+1 >= len(msg) {
		return msg
	}
	if second := strings.Index(msg[first+1:], ":"); second != -1 {
		return msg[:first+1+second]
	}
	return msg
}
