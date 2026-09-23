// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package design defines the Goa API and service endpoints.
// Run `make apigen` to regenerate the code in gen/ after modifying this file.
package design

import "goa.design/goa/v3/dsl"

var _ = dsl.API("lfx-v2-pat-service", func() {
	dsl.Title("LFX V2 Personal Access Token Service")
	dsl.Description("Issues, lists, revokes and validates audience-scoped personal access tokens.")
	dsl.Version("1.0")
})

// JWTAuth is the Heimdall-issued JWT every endpoint except the health probes requires. Token endpoints need a
// user principal; validate is the machine-to-machine route, and who may call it is decided at the gateway by
// OpenFGA team membership, not by the service.
var JWTAuth = dsl.JWTSecurity("jwt", func() {
	dsl.Description("Heimdall authorization")
})

var _ = dsl.Service("lfx_v2_pat_service", func() {
	dsl.Description("LFX V2 Personal Access Token Service")

	dsl.Method("create-token", func() {
		dsl.Description("Create a token for the caller. The secret is returned once and is never retrievable again.")
		dsl.Security(JWTAuth)
		dsl.Payload(func() {
			BearerTokenAttribute()
			VersionAttribute()
			NameAttribute()
			AudienceAttribute("Audience to mint the token for")
			dsl.Required("name", "audience")
		})
		dsl.Result(func() {
			dsl.Attribute("secret", dsl.String, "Plaintext secret. Shown once; store it now.", func() {
				dsl.Example("lfi_aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			})
			dsl.Attribute("token", TokenResponse, "The created token")
			dsl.Required("secret", "token")
		})
		AuthErrors()
		dsl.Error("BadRequest", BadRequestError, "Invalid name, or unknown or disabled audience")
		dsl.Error("Conflict", ConflictError, "Name already used, or active-token limit reached, for this audience")
		ServerErrors()
		dsl.HTTP(func() {
			dsl.POST("/tokens")
			dsl.Header("bearer_token:Authorization")
			dsl.Param("version:v")
			dsl.Response(dsl.StatusCreated)
			AuthResponses()
			dsl.Response("BadRequest", dsl.StatusBadRequest)
			dsl.Response("Conflict", dsl.StatusConflict)
			ServerResponses()
		})
	})

	dsl.Method("list-tokens", func() {
		dsl.Description("List the caller's active tokens, newest first. Not paginated: the per-audience limit bounds the size.")
		dsl.Security(JWTAuth)
		dsl.Payload(func() {
			BearerTokenAttribute()
			VersionAttribute()
			AudienceAttribute("Only return tokens minted for this audience")
		})
		dsl.Result(func() {
			dsl.Attribute("tokens", dsl.ArrayOf(TokenResponse), "Active tokens owned by the caller")
			dsl.Required("tokens")
		})
		AuthErrors()
		dsl.Error("BadRequest", BadRequestError, "Invalid filter")
		ServerErrors()
		dsl.HTTP(func() {
			dsl.GET("/tokens")
			dsl.Header("bearer_token:Authorization")
			dsl.Param("version:v")
			dsl.Param("audience")
			dsl.Response(dsl.StatusOK)
			AuthResponses()
			dsl.Response("BadRequest", dsl.StatusBadRequest)
			ServerResponses()
		})
	})

	dsl.Method("delete-token", func() {
		dsl.Description("Revoke one of the caller's tokens. The row is kept for audit; later reads return 404 and validation fails.")
		dsl.Security(JWTAuth)
		dsl.Payload(func() {
			BearerTokenAttribute()
			VersionAttribute()
			UIDAttribute()
			dsl.Required("uid")
		})
		AuthErrors()
		dsl.Error("BadRequest", BadRequestError, "uid is not a UUID")
		dsl.Error("NotFound", NotFoundError, "No active token with this uid is owned by the caller")
		ServerErrors()
		dsl.HTTP(func() {
			dsl.DELETE("/tokens/{uid}")
			dsl.Header("bearer_token:Authorization")
			dsl.Param("version:v")
			dsl.Param("uid")
			dsl.Response(dsl.StatusNoContent)
			AuthResponses()
			dsl.Response("BadRequest", dsl.StatusBadRequest)
			dsl.Response("NotFound", dsl.StatusNotFound)
			ServerResponses()
		})
	})

	dsl.Method("validate-token", func() {
		dsl.Description("Resolve a secret to its owner identity and record the use. Machine-to-machine: the gateway admits only members of the validator OpenFGA team. The caller must check the returned audience against the one it expects.")
		dsl.Security(JWTAuth)
		dsl.Payload(func() {
			BearerTokenAttribute()
			VersionAttribute()
			dsl.Attribute("secret", dsl.String, "Opaque secret presented by the end user", func() {
				dsl.MinLength(1)
				dsl.MaxLength(128)
				dsl.Example("lfi_aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			})
			dsl.Required("secret")
		})
		dsl.Result(TokenIdentity)
		AuthErrors()
		dsl.Error("BadRequest", BadRequestError, "Malformed request body")
		dsl.Error("InvalidToken", InvalidTokenError, "Unknown, malformed, revoked, or disabled-audience secret")
		ServerErrors()
		dsl.HTTP(func() {
			dsl.POST("/_tokens/validate")
			dsl.Header("bearer_token:Authorization")
			dsl.Param("version:v")
			dsl.Response(dsl.StatusOK)
			AuthResponses()
			dsl.Response("BadRequest", dsl.StatusBadRequest)
			dsl.Response("InvalidToken", dsl.StatusNotFound)
			ServerResponses()
		})
	})

	dsl.Method("livez", func() {
		dsl.Description("Liveness probe.")
		dsl.Meta("swagger:generate", "false")
		dsl.Result(dsl.Bytes, func() { dsl.Example("OK") })
		dsl.HTTP(func() {
			dsl.GET("/livez")
			dsl.Response(dsl.StatusOK, func() { dsl.ContentType("text/plain") })
		})
	})

	dsl.Method("readyz", func() {
		dsl.Description("Readiness probe.")
		dsl.Meta("swagger:generate", "false")
		dsl.Result(dsl.Bytes, func() { dsl.Example("OK") })
		dsl.Error("ServiceUnavailable", ServiceUnavailableError, "Service unavailable", func() { dsl.Temporary() })
		dsl.HTTP(func() {
			dsl.GET("/readyz")
			dsl.Response(dsl.StatusOK, func() { dsl.ContentType("text/plain") })
			dsl.Response("ServiceUnavailable", dsl.StatusServiceUnavailable)
		})
	})

	dsl.Files("/_tokens/openapi3.json", "gen/http/openapi3.json", func() {
		dsl.Meta("swagger:generate", "false")
	})
})
