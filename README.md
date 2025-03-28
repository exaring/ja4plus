# JA4Plus

JA4Plus is a go library for generating [ja4+ fingerprints](https://github.com/FoxIO-LLC/ja4).

## Overview

JA4Plus currently offers a single fingerprinting function:
- **JA4**: Fingerprint based on [TLS ClientHello](https://pkg.go.dev/crypto/tls#ClientHelloInfo) information.

Contributions are welcome for the other fingerprints in the family 😉

### Omission of JA4H

The JA4H hash, based on properties of the HTTP request, cannot currently be easily implemented in go, since it requires
headers to be observed in the order sent by the client. See e.g.: https://go.dev/issue/24375

## Examples

For example usage, checkou out [examples_test.go](./examples_test.go).