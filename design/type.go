// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package design

import (
	"github.com/linuxfoundation/lfx-v2-pat-service/pkg/constants"
	"goa.design/goa/v3/dsl"
)

// BearerTokenAttribute declares the Heimdall-issued JWT carried in the Authorization header.
func BearerTokenAttribute() {
	dsl.Token("bearer_token", dsl.String, func() {
		dsl.Description("JWT issued by Heimdall")
		dsl.Example("eyJhbGci...")
	})
}

// VersionAttribute declares the optional ?v= query parameter that lfx-one appends to every proxied request.
func VersionAttribute() {
	dsl.Attribute("version", dsl.String, "Version of the API", func() {
		dsl.Enum("1")
		dsl.Example("1")
	})
}

// UIDAttribute declares a token identifier.
func UIDAttribute() {
	dsl.Attribute("uid", dsl.String, "Token UID", func() {
		dsl.Format(dsl.FormatUUID)
		dsl.Example("8d4c5a2e-3b1f-4c6d-9e7a-1f2b3c4d5e6f")
	})
}

// NameAttribute declares a token's display name.
func NameAttribute() {
	dsl.Attribute("name", dsl.String, "Display name, unique (case-insensitive) among the caller's active tokens for the audience", func() {
		dsl.MinLength(1)
		dsl.MaxLength(constants.TokenNameMaxLength)
		dsl.Example("ci-pipeline")
	})
}

// AudienceAttribute declares an audience slug. The set of slugs lives in the audiences table, so the design only
// constrains the shape.
func AudienceAttribute(description string) {
	dsl.Attribute("audience", dsl.String, description, func() {
		dsl.Pattern(`^[a-z][a-z0-9-]{1,31}$`)
		dsl.Example(constants.AudienceInsights)
	})
}

// UsernameAttribute declares the owner's LFID username.
func UsernameAttribute() {
	dsl.Attribute("username", dsl.String, "Owner LFID username", func() {
		dsl.Example("jdoe")
	})
}

// TokenResponse is the owner's view of a token. It never carries the secret, the salt or the hash.
var TokenResponse = dsl.Type("token-response", func() {
	dsl.Description("A personal access token as seen by its owner. The secret is only returned at creation.")
	UIDAttribute()
	NameAttribute()
	AudienceAttribute("Audience the token was minted for")
	dsl.Attribute("lookup_id", dsl.String, "Public locator embedded in the secret; safe to display", func() {
		dsl.MinLength(12)
		dsl.MaxLength(12)
		dsl.Example("Ab3kZ9QmT2xL")
	})
	UsernameAttribute()
	dsl.Attribute("created_at", dsl.String, "Creation time", func() {
		dsl.Format(dsl.FormatDateTime)
		dsl.Example("2026-09-21T12:00:00Z")
	})
	dsl.Attribute("last_used_at", dsl.String, "Time of the last successful validation; absent until first use", func() {
		dsl.Format(dsl.FormatDateTime)
		dsl.Example("2026-09-22T08:30:00Z")
	})
	dsl.Required("uid", "name", "audience", "lookup_id", "username", "created_at")
})

// TokenIdentity is what the validate endpoint returns to the Auth0 Custom Token Exchange action.
var TokenIdentity = dsl.Type("token-identity", func() {
	dsl.Description("Owner identity resolved from a secret")
	UIDAttribute()
	UsernameAttribute()
	AudienceAttribute("Audience the token was minted for. The caller must compare it with the audience it expects.")
	dsl.Attribute("email", dsl.String, "Owner email captured at issuance, when the user JWT carried a verified one", func() {
		dsl.Format(dsl.FormatEmail)
		dsl.Example("jdoe@example.com")
	})
	dsl.Required("uid", "username", "audience")
})

// ConflictError carries a stable code so lfx-one can tell the two 409 causes apart. The attribute is named
// "error" on the wire but "Code" in Go, because the generated type must also implement error.
var ConflictError = dsl.Type("ConflictError", func() {
	dsl.Description("Name already used, or active-token limit reached, for this audience")
	dsl.Attribute("error", dsl.String, "Stable machine-readable code", func() {
		dsl.Meta("struct:field:name", "Code")
		dsl.Enum(constants.ErrCodeTokenNameTaken, constants.ErrCodeTokenLimitReached)
		dsl.Example(constants.ErrCodeTokenNameTaken)
	})
	dsl.Attribute("message", dsl.String, "Human-readable explanation", func() {
		dsl.Example("a token named \"ci-pipeline\" already exists for audience insights")
	})
	dsl.Required("error", "message")
})

// InvalidTokenError is the single 404 body the validate endpoint returns for every rejected secret, so callers
// cannot tell an unknown secret from a revoked one.
var InvalidTokenError = dsl.Type("InvalidTokenError", func() {
	dsl.Description("Secret is invalid or revoked")
	dsl.Attribute("error", dsl.String, "Stable machine-readable code", func() {
		dsl.Meta("struct:field:name", "Code")
		dsl.Enum(constants.ErrCodeInvalidToken)
		dsl.Example(constants.ErrCodeInvalidToken)
	})
	dsl.Attribute("message", dsl.String, "Human-readable explanation", func() {
		dsl.Example("secret is invalid or revoked")
	})
	dsl.Required("error", "message")
})

// AuthErrors declares the errors the JWTAuth security handler can return. Undeclared errors from a security
// handler are rendered as 400 by Goa, so every secured method declares these.
func AuthErrors() {
	dsl.Error("Unauthorized", dsl.ErrorResult, "Missing, invalid or anonymous bearer token")
	dsl.Error("Forbidden", dsl.ErrorResult, "Principal is not allowed to call this endpoint")
}

// AuthResponses maps AuthErrors to HTTP statuses.
func AuthResponses() {
	dsl.Response("Unauthorized", dsl.StatusUnauthorized)
	dsl.Response("Forbidden", dsl.StatusForbidden)
}

// ServerErrors declares the errors every endpoint can produce regardless of input.
func ServerErrors() {
	dsl.Error("NotImplemented", dsl.ErrorResult, "Endpoint not implemented")
	dsl.Error("InternalServerError", dsl.ErrorResult, "Internal server error", func() { dsl.Fault() })
	dsl.Error("ServiceUnavailable", dsl.ErrorResult, "Service unavailable", func() { dsl.Temporary() })
}

// ServerResponses maps ServerErrors to HTTP statuses.
func ServerResponses() {
	dsl.Response("NotImplemented", dsl.StatusNotImplemented)
	dsl.Response("InternalServerError", dsl.StatusInternalServerError)
	dsl.Response("ServiceUnavailable", dsl.StatusServiceUnavailable)
}
