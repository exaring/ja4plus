# JA4Plus

JA4Plus is a go library for generating [ja4+ fingerprints](https://github.com/FoxIO-LLC/ja4).

## Overview

JA4Plus currently offers three fingerprinting functions:
- **JA4**: Fingerprint based on [TLS ClientHello](https://pkg.go.dev/crypto/tls#ClientHelloInfo) information.
- **JA4H**: Fingerprint based on HTTP request details.
- **JA4T**: Fingerprint based on TCP connection parameters.

## Examples

For example usage, checkou out [examples_test.go](./examples_test.go).