# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

JA4Plus is a small, dependency-free Go library that generates [JA4+ fingerprints](https://github.com/FoxIO-LLC/ja4) from TLS handshake data. It currently implements only the **JA4** fingerprint (based on `tls.ClientHelloInfo`). JA4H is intentionally omitted because Go's `net/http` doesn't expose header order (see README for details).

## Commands

- Run all tests: `go test ./...`
- Run tests with the race detector (as CI does): `go test -v -race ./...`
- Run a single test/subtest: `go test -run 'TestJA4/Basic_ClientHelloInfo' -v`
- Run benchmarks with allocation stats: `go test -bench=. -benchmem`
- Check for dependency/go.mod drift (as CI does): `go mod tidy -diff`

CI (`.github/workflows/ci.yml`) runs on Go 1.24 and 1.25: `go mod tidy -diff` then `go test -v -race ./...`.

## Architecture

The public API is split across two files:

- **ja4plus.go** — the `JA4()` function and its helpers. It's a direct, byte-level implementation of the JA4 spec: a fixed-width prefix (protocol/TLS version/SNI presence/cipher+extension counts/first-ALPN) is built as raw bytes via `appendTwoDigits`/`appendHexUint16`, followed by two truncated (6-byte) SHA-256 hashes from `cipherSuiteHash` and `extensionHash`. GREASE values ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html)) must be filtered out of versions, cipher suites, extensions, and ALPN protocols before anything is counted or hashed — `greaseFilter` is the single source of truth for that check. The SNI (0x0000) and ALPN (0x0010) extension IDs are counted in the prefix but must still be excluded from `extensionHash`'s input.
- **middlewares.go** — `JA4Middleware`, a helper for wiring JA4 into an `http.Server` despite Go not exposing `tls.ClientHelloInfo` to HTTP handlers. It caches fingerprints keyed by remote address (`StoreFingerprintFromClientHello`, invoked from `tls.Config.GetConfigForClient`), evicts them on connection close/hijack (`ConnStateCallback`, wired to `http.Server.ConnState`), and exposes the cached fingerprint to handlers via `Wrap` + `JA4FromContext`. All three hooks must be wired together (see the doc comment on `JA4Middleware` for the full example) or fingerprints won't be available/will leak.

There are no external dependencies — only the Go standard library is used.

## Performance

`JA4()` is optimized down to a single heap allocation per call; `old.bench`/`new.bench` capture the before/after of a past optimization pass (15 allocs & 682ns/op → 1 alloc & 207ns/op). When touching this hot path, avoid reintroducing allocations — e.g. prefer appending bytes directly to the preallocated `out`/list slices over `string`/`fmt` formatting — and re-run `go test -bench=BenchmarkJA4 -benchmem` before/after to confirm allocation count and ns/op don't regress.

## Testing conventions

Tests are table-driven (`TestJA4`, `TestExtensionHash`). Expected fingerprint/hash values are hardcoded hex strings derived from the real SHA-256 output — when hashing/format logic changes intentionally, recompute expected values from the new behavior rather than hand-guessing them.

`examples_test.go` and `middlewares_test.go` contain `Example*` functions that double as runnable documentation on pkg.go.dev; keep them consistent with real usage. `ExampleJA4`'s `// Output:` comment is Go-version-sensitive (default cipher suites can change across Go releases) — see the comment above it.
