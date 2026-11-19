<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Agent guide

## Go version

This repo targets Go 1.27.x (currently 1.27.4, the latest patch). This
supersedes the Go version policy in the `lfx-megalinter` skill, which targets
the latest stable minor minus one: don't move `go.mod` back to Go 1.26. Take
every 1.27.x patch release, and update `go.mod` and `GO_VERSION` in the
`Makefile` together. Release images are built with the `go.mod` version
(`setup-go` reads `go-version-file: go.mod`).

MegaLinter (v10.2.0) runs Go 1.26.10 in its image, so
`.github/workflows/mega-linter.yaml` sets `GOTOOLCHAIN: auto` to let its Go
linters download the `go.mod` toolchain. Its bundled golangci-lint 2.15.0 is
built with Go 1.27.0 and can load this module, but it stays in
`DISABLE_LINTERS` until the existing findings listed in `.mega-linter.yml`
are fixed; run `make lint` locally. osv-scanner's govulncheck call analysis
is built with Go 1.26 and cannot load this module, so osv-scanner falls back
to matching vulnerabilities by version: any known vulnerability in a
dependency version fails the check, reachable or not.
