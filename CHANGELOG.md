# Changelog

## v0.0.22 — 2026-11-09

- Reject all static remote MCP headers; every remote header must use a host-vault reference.
- Update the API dependency to v0.0.24.
- Reject control bytes and empty names in host-vault header templates.

## v0.0.21 — 2026-11-08

- Bind M7 pre-tag approval to the exact reviewed commit.
- Add typed host-vault-backed remote MCP headers and reject malformed references, duplicate names, and daemon API versions without support.
- Update the API dependency to v0.0.23.
- Update golang.org/x/sys from v0.49.0 to v0.50.0.

## v0.0.20 — 2026-11-08

- Add remote streamable-HTTP MCP server registration with optional URL and non-secret headers; the daemon enforces its fail-closed host allowlist.

## v0.0.19 — 2026-11-07

- Expose presence-only account refresh metadata without returning token material, expiry values or validity claims.

## v0.0.18 — 2026-11-07

- Add curated MCP inventory and bounded tool-call APIs. Daemon policy and trusted approval remain required before execution.

## v0.0.17 — 2026-11-07

- Add SDK methods for policy refresh and reset.

## v0.0.16 — 2026-11-06

- Add the optional `DynamicSecretCreator` capability for host-side references or shell commands, refresh controls, and captured 1Password account/AWS profile selectors; fail closed unless daemon API v0.0.16 or newer is available.

## v0.0.15 — 2026-11-05

- Add nested Docker Kits v2-shaped OAuth credential configuration to sandbox Create requests; this does not imply daemon runtime support.
- Add the optional `SecretCreator` capability for atomic create-only writes; existing `SecretService` implementations remain source compatible.
- Fail closed before sending OAuth metadata when daemon API version support cannot be verified or is older than 0.0.15.
- Preserve absent optional OAuth messages in the protobuf request, including sentinels omitted for passthrough credentials.

## v0.0.12 — 2026-11-03

### Added

- Add Windows named-pipe transport with contract tests for the local daemon.
- Expose account device-login and credential-presence status APIs from `sandboxes-api v0.0.12`.
- Publish a CycloneDX module SBOM as a CI artifact.

### Changed

- Normalize the Go module path to `github.com/rheic/sandboxes-go-sdk`.
- Update `golang.org/x/net` to v0.62.0.
