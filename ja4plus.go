package ja4plus

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// greaseFilter returns true if the provided value is a GREASE entry as defined in
// https://www.rfc-editor.org/rfc/rfc8701.html
func greaseFilter(suite uint16) bool {
	return suite&0x000F == 0x000A && // low word is 0x*A
		suite>>8 == (suite&0x00FF) // high word is equal to low word
}

// JA4 generates a JA4 fingerprint from the given [tls.ClientHelloInfo].
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
func JA4(hello *tls.ClientHelloInfo) string {
	out := make([]byte, 0, 36)

	// Determine protocol type based on the network type
	if hello.Conn != nil {
		switch hello.Conn.LocalAddr().Network() {
		case "udp", "sctp":
			out = append(out, 'd')
		case "quic":
			out = append(out, 'q')
		default:
			out = append(out, 't')
		}
	} else {
		out = append(out, 't')
	}

	// Extract TLS version
	var (
		maxVersion uint16
		hasVersion bool
	)
	for _, version := range hello.SupportedVersions {
		if greaseFilter(version) {
			continue
		}
		if !hasVersion || version > maxVersion {
			maxVersion = version
			hasVersion = true
		}
	}
	if !hasVersion {
		out = append(out, '0', '0')
	} else {
		switch maxVersion {
		case tls.VersionTLS10:
			out = append(out, '1', '0')
		case tls.VersionTLS11:
			out = append(out, '1', '1')
		case tls.VersionTLS12:
			out = append(out, '1', '2')
		case tls.VersionTLS13:
			out = append(out, '1', '3')
		case tls.VersionSSL30: // deprecated, but still seen in the wild
			out = append(out, 's', '3')
		case 0x0002: // unsupported by go; still seen in the wild
			out = append(out, 's', '2')
		case 0xfeff: // DTLS 1.0
			out = append(out, 'd', '1')
		case 0xfefd: // DTLS 1.2
			out = append(out, 'd', '2')
		case 0xfefc: // DTLS 1.3
			out = append(out, 'd', '3')
		default:
			out = append(out, '0', '0')
		}
	}

	// Check for presence of SNI
	if hello.ServerName != "" {
		out = append(out, 'd')
	} else {
		out = append(out, 'i')
	}

	// Count cipher suites; copy to avoid modifying the original
	filteredCipherSuites := make([]uint16, 0, len(hello.CipherSuites))
	for _, suite := range hello.CipherSuites {
		if !greaseFilter(suite) {
			filteredCipherSuites = append(filteredCipherSuites, suite)
		}
	}
	cipherCount := min(len(filteredCipherSuites), 99)
	out = appendTwoDigits(out, cipherCount)

	// Count extensions; copy to avoid modifying the original
	filteredExtensions := make([]uint16, 0, len(hello.Extensions))
	for _, ext := range hello.Extensions {
		if !greaseFilter(ext) {
			filteredExtensions = append(filteredExtensions, ext)
		}
	}
	extensionCount := min(len(filteredExtensions), 99)
	out = appendTwoDigits(out, extensionCount)

	// Extract first ALPN value
	var firstALPN string
	for _, proto := range hello.SupportedProtos {
		// Protocols are tecnically strings, but grease values are 2-byte non-printable, so we convert.
		// see: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		if len(proto) >= 2 && !greaseFilter(binary.BigEndian.Uint16([]byte(proto[:2]))) {
			firstALPN = proto
			break
		}
	}
	if firstALPN == "" {
		out = append(out, '0', '0')
	} else if first, last := firstALPN[0], firstALPN[len(firstALPN)-1]; isASCIIAlphanumeric(first) && isASCIIAlphanumeric(last) {
		out = append(out, first, last)
	} else {
		// If the first or last byte is not ASCII alphanumeric, the JA4 spec uses
		// the first and last characters of the hex representation of the whole
		// value. Those are the high nibble of the first byte and the low nibble
		// of the last byte, so we can emit them without hex-encoding the rest.
		const hexdigits = "0123456789abcdef"
		out = append(out, hexdigits[first>>4], hexdigits[last&0x0F])
	}

	out = append(out, '_')

	ciphersHash := cipherSuiteHash(filteredCipherSuites)
	out = hex.AppendEncode(out, ciphersHash[:])

	out = append(out, '_')

	extensionsHash := extensionHash(filteredExtensions, hello.SignatureSchemes)
	out = hex.AppendEncode(out, extensionsHash[:])

	return string(out)
}

// cipherSuiteHash computes the truncated SHA256 of sorted cipher suites.
// The input must be filtered for GREASE values.
// The return value is an unencoded byte array of the hash.
func cipherSuiteHash(filteredCipherSuites []uint16) [6]byte {
	if len(filteredCipherSuites) == 0 {
		return [6]byte{}
	}
	slices.Sort(filteredCipherSuites)
	cipherSuiteList := make([]byte, 0, len(filteredCipherSuites) /* 4 chars + comma */ *5 /* last comma */ -1)
	for i, suite := range filteredCipherSuites {
		if i > 0 {
			cipherSuiteList = append(cipherSuiteList, ',')
		}
		cipherSuiteList = appendHexUint16(cipherSuiteList, suite)
	}
	cipherSuiteHash := sha256.Sum256(cipherSuiteList)
	var truncated [6]byte
	copy(truncated[:], cipherSuiteHash[:6])
	return truncated
}

// extensionHash computes the truncated SHA256 of sorted and filtered extensions and unsorted signature algorithms.
// The provided extensions must be filtered for GREASE values.
// It sorts the provided extensions in-place.
// The return value is an unencoded byte array of the hash.
func extensionHash(filteredExtensions []uint16, signatureSchemes []tls.SignatureScheme) [6]byte {
	slices.Sort(filteredExtensions)
	extensionsList := make([]byte, 0, len(filteredExtensions)*5+len(signatureSchemes)*5+1)
	for _, ext := range filteredExtensions {
		// SNI and ALPN are counted above, but MUST be ignored for the hash.
		if ext == 0x0000 /* SNI */ || ext == 0x0010 /* ALPN */ {
			continue
		}
		if len(extensionsList) > 0 {
			extensionsList = append(extensionsList, ',')
		}
		extensionsList = appendHexUint16(extensionsList, ext)
	}
	if len(extensionsList) == 0 {
		return [6]byte{}
	}

	hasSignature := false
	for _, sig := range signatureSchemes {
		if greaseFilter(uint16(sig)) {
			continue
		}
		if !hasSignature {
			extensionsList = append(extensionsList, '_')
			hasSignature = true
		} else {
			extensionsList = append(extensionsList, ',')
		}
		extensionsList = appendHexUint16(extensionsList, uint16(sig))
	}
	extensionsHash := sha256.Sum256(extensionsList)
	var truncated [6]byte
	copy(truncated[:], extensionsHash[:6])
	return truncated
}

// isASCIIAlphanumeric reports whether b is 0-9, A-Z, or a-z.
func isASCIIAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func appendTwoDigits(dst []byte, v int) []byte {
	return append(dst, byte('0'+v/10), byte('0'+v%10))
}

func appendHexUint16(dst []byte, v uint16) []byte {
	const hex = "0123456789abcdef"
	return append(dst,
		hex[v>>12],
		hex[(v>>8)&0xF],
		hex[(v>>4)&0xF],
		hex[v&0xF],
	)
}
