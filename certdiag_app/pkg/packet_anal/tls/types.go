package tls

import "fmt"

// TLS record content types
type ContentType uint8

const (
	ContentChangeCipherSpec ContentType = 20
	ContentAlert            ContentType = 21
	ContentHandshake        ContentType = 22
	ContentApplicationData  ContentType = 23
)

func (c ContentType) String() string {
	switch c {
	case ContentChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentAlert:
		return "Alert"
	case ContentHandshake:
		return "Handshake"
	case ContentApplicationData:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// TLS handshake message types
type HandshakeType uint8

const (
	HandshakeClientHello        HandshakeType = 1
	HandshakeServerHello        HandshakeType = 2
	HandshakeCertificate        HandshakeType = 11
	HandshakeServerKeyExchange  HandshakeType = 12
	HandshakeCertificateRequest HandshakeType = 13
	HandshakeServerHelloDone    HandshakeType = 14
	HandshakeClientKeyExchange  HandshakeType = 16
	HandshakeFinished           HandshakeType = 20
)

func (h HandshakeType) String() string {
	switch h {
	case HandshakeClientHello:
		return "ClientHello"
	case HandshakeServerHello:
		return "ServerHello"
	case HandshakeCertificate:
		return "Certificate"
	case HandshakeServerKeyExchange:
		return "ServerKeyExchange"
	case HandshakeCertificateRequest:
		return "CertificateRequest"
	case HandshakeServerHelloDone:
		return "ServerHelloDone"
	case HandshakeClientKeyExchange:
		return "ClientKeyExchange"
	case HandshakeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(%d)", h)
	}
}

// TLS version
type Version struct {
	Major uint8
	Minor uint8
}

var (
	VersionSSL30 = Version{3, 0}
	VersionTLS10 = Version{3, 1}
	VersionTLS11 = Version{3, 2}
	VersionTLS12 = Version{3, 3}
	VersionTLS13 = Version{3, 4} // only in supported_versions extension
)

func (v Version) String() string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(%d.%d)", v.Major, v.Minor)
	}
}

func (v Version) Code() uint16 {
	return uint16(v.Major)<<8 | uint16(v.Minor)
}

func VersionFromCode(code uint16) Version {
	return Version{Major: uint8(code >> 8), Minor: uint8(code & 0xff)}
}

// Record is a parsed TLS record header + payload.
type Record struct {
	Type    ContentType
	Version Version
	Payload []byte
}

const recordHeaderSize = 5
const maxRecordPayload = 16384 + 2048 // 16KB + allowance for overhead
