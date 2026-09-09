package tls

import (
	"encoding/binary"
	"errors"
)

var ErrHandshakeTruncated = errors.New("truncated handshake message")

// HandshakeMessage is a parsed TLS handshake message header.
type HandshakeMessage struct {
	Type    HandshakeType
	Length  uint32
	Payload []byte
}

// ClientHelloMsg holds parsed ClientHello fields.
type ClientHelloMsg struct {
	Version           Version
	Random            []byte
	SessionID         []byte
	CipherSuites      []uint16
	CompressionMethods []uint8
	Extensions        []Extension
	// Extracted from extensions:
	SNI               string
	SupportedVersions []Version
	SupportedGroups   []uint16
	SignatureAlgs     []uint16
	ALPNProtocols     []string
}

// ServerHelloMsg holds parsed ServerHello fields.
type ServerHelloMsg struct {
	Version           Version
	Random            []byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []Extension
	// Extracted from extensions:
	SupportedVersion  *Version // from supported_versions extension (TLS 1.3)
}

// NegotiatedVersion returns the actual negotiated TLS version,
// checking supported_versions extension first (TLS 1.3).
func (s *ServerHelloMsg) NegotiatedVersion() Version {
	if s.SupportedVersion != nil {
		return *s.SupportedVersion
	}
	return s.Version
}

// CertificateMsg holds parsed Certificate message fields.
type CertificateMsg struct {
	Certificates [][]byte // DER-encoded X.509 certificates
}

// ParseHandshakeMessages extracts handshake messages from a handshake record payload.
// A single record payload can contain multiple handshake messages.
// Returns parsed messages and any leftover bytes (for cross-record handshake messages).
func ParseHandshakeMessages(data []byte) ([]HandshakeMessage, []byte) {
	var msgs []HandshakeMessage

	for len(data) >= 4 {
		msgType := HandshakeType(data[0])
		msgLen := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		data = data[4:]

		if uint32(len(data)) < msgLen {
			// Incomplete message -- return remaining including the 4-byte header
			leftover := make([]byte, len(data)+4)
			leftover[0] = byte(msgType)
			leftover[1] = byte(msgLen >> 16)
			leftover[2] = byte(msgLen >> 8)
			leftover[3] = byte(msgLen)
			copy(leftover[4:], data)
			return msgs, leftover
		}

		payload := make([]byte, msgLen)
		copy(payload, data[:msgLen])

		msgs = append(msgs, HandshakeMessage{
			Type:    msgType,
			Length:  msgLen,
			Payload: payload,
		})
		data = data[msgLen:]
	}

	if len(data) > 0 {
		return msgs, data
	}
	return msgs, nil
}

// ParseClientHello parses a ClientHello handshake message payload.
func ParseClientHello(data []byte) (*ClientHelloMsg, error) {
	if len(data) < 34 {
		return nil, ErrHandshakeTruncated
	}

	msg := &ClientHelloMsg{
		Version: Version{Major: data[0], Minor: data[1]},
		Random:  data[2:34],
	}
	offset := 34

	// Session ID
	if offset >= len(data) {
		return nil, ErrHandshakeTruncated
	}
	sidLen := int(data[offset])
	offset++
	if offset+sidLen > len(data) {
		return nil, ErrHandshakeTruncated
	}
	msg.SessionID = data[offset : offset+sidLen]
	offset += sidLen

	// Cipher suites
	if offset+2 > len(data) {
		return nil, ErrHandshakeTruncated
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return nil, ErrHandshakeTruncated
	}
	for i := 0; i+1 < csLen; i += 2 {
		msg.CipherSuites = append(msg.CipherSuites, binary.BigEndian.Uint16(data[offset+i:offset+i+2]))
	}
	offset += csLen

	// Compression methods
	if offset >= len(data) {
		return nil, ErrHandshakeTruncated
	}
	compLen := int(data[offset])
	offset++
	if offset+compLen > len(data) {
		return nil, ErrHandshakeTruncated
	}
	msg.CompressionMethods = data[offset : offset+compLen]
	offset += compLen

	// Extensions (optional)
	if offset < len(data) {
		exts, err := ParseExtensions(data[offset:])
		if err != nil {
			return msg, err // return partial result
		}
		msg.Extensions = exts
		extractClientHelloExtensions(msg)
	}

	return msg, nil
}

func extractClientHelloExtensions(msg *ClientHelloMsg) {
	for _, ext := range msg.Extensions {
		switch ext.Type {
		case ExtServerName:
			msg.SNI = ExtractSNI(ext.Data)
		case ExtSupportedVersions:
			msg.SupportedVersions = ExtractSupportedVersions(ext.Data, false)
		case ExtSupportedGroups:
			msg.SupportedGroups = ExtractSupportedGroups(ext.Data)
		case ExtSignatureAlgs:
			msg.SignatureAlgs = ExtractSignatureAlgorithms(ext.Data)
		case ExtALPN:
			msg.ALPNProtocols = ExtractALPN(ext.Data)
		}
	}
}

// ParseServerHello parses a ServerHello handshake message payload.
func ParseServerHello(data []byte) (*ServerHelloMsg, error) {
	if len(data) < 34 {
		return nil, ErrHandshakeTruncated
	}

	msg := &ServerHelloMsg{
		Version: Version{Major: data[0], Minor: data[1]},
		Random:  data[2:34],
	}
	offset := 34

	// Session ID
	if offset >= len(data) {
		return nil, ErrHandshakeTruncated
	}
	sidLen := int(data[offset])
	offset++
	if offset+sidLen > len(data) {
		return nil, ErrHandshakeTruncated
	}
	msg.SessionID = data[offset : offset+sidLen]
	offset += sidLen

	// Cipher suite (single)
	if offset+2 > len(data) {
		return nil, ErrHandshakeTruncated
	}
	msg.CipherSuite = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Compression method (single)
	if offset >= len(data) {
		return nil, ErrHandshakeTruncated
	}
	msg.CompressionMethod = data[offset]
	offset++

	// Extensions (optional)
	if offset < len(data) {
		exts, err := ParseExtensions(data[offset:])
		if err != nil {
			return msg, err
		}
		msg.Extensions = exts

		for _, ext := range exts {
			if ext.Type == ExtSupportedVersions {
				versions := ExtractSupportedVersions(ext.Data, true)
				if len(versions) > 0 {
					v := versions[0]
					msg.SupportedVersion = &v
				}
			}
		}
	}

	return msg, nil
}

// ParseCertificateTLS13 parses a TLS 1.3 Certificate handshake message (RFC 8446
// 4.4.2), which prepends a certificate_request_context and wraps each entry with
// per-certificate extensions - unlike the TLS 1.2 format.
func ParseCertificateTLS13(data []byte) (*CertificateMsg, error) {
	if len(data) < 1 {
		return nil, ErrHandshakeTruncated
	}
	ctxLen := int(data[0])
	data = data[1:]
	if len(data) < ctxLen {
		return nil, ErrHandshakeTruncated
	}
	data = data[ctxLen:]

	if len(data) < 3 {
		return nil, ErrHandshakeTruncated
	}
	listLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	data = data[3:]
	if len(data) < listLen {
		return nil, ErrHandshakeTruncated
	}
	data = data[:listLen]

	msg := &CertificateMsg{}
	for len(data) >= 3 {
		certLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < certLen {
			return msg, ErrHandshakeTruncated
		}
		cert := make([]byte, certLen)
		copy(cert, data[:certLen])
		msg.Certificates = append(msg.Certificates, cert)
		data = data[certLen:]

		// Per-entry extensions (2-byte length prefix), skipped.
		if len(data) < 2 {
			break
		}
		extLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if len(data) < extLen {
			break
		}
		data = data[extLen:]
	}
	return msg, nil
}

// ParseCertificate parses a Certificate handshake message payload.
// Returns the list of DER-encoded certificates.
func ParseCertificate(data []byte) (*CertificateMsg, error) {
	if len(data) < 3 {
		return nil, ErrHandshakeTruncated
	}

	// Total certificates length (3 bytes)
	totalLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	data = data[3:]
	if len(data) < totalLen {
		return nil, ErrHandshakeTruncated
	}
	data = data[:totalLen]

	msg := &CertificateMsg{}

	for len(data) >= 3 {
		certLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < certLen {
			return msg, ErrHandshakeTruncated
		}
		cert := make([]byte, certLen)
		copy(cert, data[:certLen])
		msg.Certificates = append(msg.Certificates, cert)
		data = data[certLen:]
	}

	return msg, nil
}
