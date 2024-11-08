// Vendored from go stdlib
package main

import (
	"errors"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type echCipher struct {
	KDFID  uint16
	AEADID uint16
}

type echExtension struct {
	Type uint16
	Data []byte
}

type echConfig struct {
	raw []byte

	Version uint16
	Length  uint16

	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []echCipher

	MaxNameLength uint8
	PublicName    []byte
	Extensions    []echExtension
}

const extensionEncryptedClientHello uint16 = 0xfe0d

var errMalformedECHConfig = errors.New("tls: malformed ECHConfigList")

// parseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList, returning a
// slice of parsed ECHConfigs, in the same order they were parsed, or an error
// if the list is malformed.
func parseECHConfigList(data []byte) ([]echConfig, error) {
	s := cryptobyte.String(data)
	// Skip the length prefix
	var length uint16
	if !s.ReadUint16(&length) {
		return nil, errMalformedECHConfig
	}
	if length != uint16(len(data)-2) {
		return nil, errMalformedECHConfig
	}
	var configs []echConfig
	for len(s) > 0 {
		var ec echConfig
		ec.raw = []byte(s)
		if !s.ReadUint16(&ec.Version) {
			return nil, errMalformedECHConfig
		}
		if !s.ReadUint16(&ec.Length) {
			return nil, errMalformedECHConfig
		}
		if len(ec.raw) < int(ec.Length)+4 {
			return nil, errMalformedECHConfig
		}
		ec.raw = ec.raw[:ec.Length+4]
		if ec.Version != extensionEncryptedClientHello {
			s.Skip(int(ec.Length))
			continue
		}
		if !s.ReadUint8(&ec.ConfigID) {
			return nil, errMalformedECHConfig
		}
		if !s.ReadUint16(&ec.KemID) {
			return nil, errMalformedECHConfig
		}
		if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&ec.PublicKey)) {
			return nil, errMalformedECHConfig
		}
		var cipherSuites cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&cipherSuites) {
			return nil, errMalformedECHConfig
		}
		for !cipherSuites.Empty() {
			var c echCipher
			if !cipherSuites.ReadUint16(&c.KDFID) {
				return nil, errMalformedECHConfig
			}
			if !cipherSuites.ReadUint16(&c.AEADID) {
				return nil, errMalformedECHConfig
			}
			ec.SymmetricCipherSuite = append(ec.SymmetricCipherSuite, c)
		}
		if !s.ReadUint8(&ec.MaxNameLength) {
			return nil, errMalformedECHConfig
		}
		var publicName cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&publicName) {
			return nil, errMalformedECHConfig
		}
		ec.PublicName = publicName
		var extensions cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&extensions) {
			return nil, errMalformedECHConfig
		}
		for !extensions.Empty() {
			var e echExtension
			if !extensions.ReadUint16(&e.Type) {
				return nil, errMalformedECHConfig
			}
			if !extensions.ReadUint16LengthPrefixed((*cryptobyte.String)(&e.Data)) {
				return nil, errMalformedECHConfig
			}
			ec.Extensions = append(ec.Extensions, e)
		}

		configs = append(configs, ec)
	}
	return configs, nil
}

func generateOuterECHExt(id uint8, kdfID, aeadID uint16, encodedKey []byte, payload []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(0) // outer
	b.AddUint16(kdfID)
	b.AddUint16(aeadID)
	b.AddUint8(id)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(encodedKey) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(payload) })
	return b.Bytes()
}

// validDNSName is a rather rudimentary check for the validity of a DNS name.
// This is used to check if the public_name in a ECHConfig is valid when we are
// picking a config. This can be somewhat lax because even if we pick a
// valid-looking name, the DNS layer will later reject it anyway.
func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) <= 1 {
		return false
	}
	for _, l := range labels {
		labelLen := len(l)
		if labelLen == 0 {
			return false
		}
		for i, r := range l {
			if r == '-' && (i == 0 || i == labelLen-1) {
				return false
			}
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
				return false
			}
		}
	}
	return true
}

// ECHRejectionError is the error type returned when ECH is rejected by a remote
// server. If the server offered a ECHConfigList to use for retries, the
// RetryConfigList field will contain this list.
//
// The client may treat an ECHRejectionError with an empty set of RetryConfigs
// as a secure signal from the server.
type ECHRejectionError struct {
	RetryConfigList []byte
}

func (e *ECHRejectionError) Error() string {
	return "tls: server rejected ECH"
}
