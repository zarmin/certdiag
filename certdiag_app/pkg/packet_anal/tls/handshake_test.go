package tls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- helper builders ---

func buildSNIExtension(host string) []byte {
	// nameEntry: type(1) + nameLen(2) + name(N)
	nameEntry := make([]byte, 3+len(host))
	nameEntry[0] = 0 // host_name
	binary.BigEndian.PutUint16(nameEntry[1:3], uint16(len(host)))
	copy(nameEntry[3:], host)

	// serverNameList: listLen(2) + entries
	snList := make([]byte, 2+len(nameEntry))
	binary.BigEndian.PutUint16(snList[:2], uint16(len(nameEntry)))
	copy(snList[2:], nameEntry)

	return snList
}

func buildALPNExtension(protos []string) []byte {
	var protoList []byte
	for _, p := range protos {
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, []byte(p)...)
	}
	// listLen(2) + protoList
	buf := make([]byte, 2+len(protoList))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(protoList)))
	copy(buf[2:], protoList)
	return buf
}

func buildSupportedVersionsClientExtension(versions []uint16) []byte {
	// 1-byte list length + N*2 bytes
	listLen := len(versions) * 2
	buf := make([]byte, 1+listLen)
	buf[0] = byte(listLen)
	for i, v := range versions {
		binary.BigEndian.PutUint16(buf[1+i*2:], v)
	}
	return buf
}

func buildSupportedVersionsServerExtension(version uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, version)
	return buf
}

// buildExtensionBlock creates an extensions block with 2-byte total length prefix.
func buildExtensionBlock(extensions []Extension) []byte {
	var extBytes []byte
	for _, ext := range extensions {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[:2], ext.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(ext.Data)))
		extBytes = append(extBytes, hdr...)
		extBytes = append(extBytes, ext.Data...)
	}
	buf := make([]byte, 2+len(extBytes))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(extBytes)))
	copy(buf[2:], extBytes)
	return buf
}

func buildHandshakeMessage(hsType HandshakeType, payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	buf[0] = byte(hsType)
	buf[1] = byte(len(payload) >> 16)
	buf[2] = byte(len(payload) >> 8)
	buf[3] = byte(len(payload))
	copy(buf[4:], payload)
	return buf
}

func buildClientHelloPayload(
	version Version,
	random []byte,
	sessionID []byte,
	cipherSuites []uint16,
	compressionMethods []byte,
	extensions []Extension,
) []byte {
	var buf []byte

	// version (2)
	buf = append(buf, version.Major, version.Minor)
	// random (32)
	buf = append(buf, random...)
	// sessionID
	buf = append(buf, byte(len(sessionID)))
	buf = append(buf, sessionID...)
	// cipher suites
	csLen := make([]byte, 2)
	binary.BigEndian.PutUint16(csLen, uint16(len(cipherSuites)*2))
	buf = append(buf, csLen...)
	for _, cs := range cipherSuites {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, cs)
		buf = append(buf, b...)
	}
	// compression methods
	buf = append(buf, byte(len(compressionMethods)))
	buf = append(buf, compressionMethods...)
	// extensions
	if len(extensions) > 0 {
		buf = append(buf, buildExtensionBlock(extensions)...)
	}
	return buf
}

func buildServerHelloPayload(
	version Version,
	random []byte,
	sessionID []byte,
	cipherSuite uint16,
	compressionMethod byte,
	extensions []Extension,
) []byte {
	var buf []byte

	buf = append(buf, version.Major, version.Minor)
	buf = append(buf, random...)
	buf = append(buf, byte(len(sessionID)))
	buf = append(buf, sessionID...)
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherSuite)
	buf = append(buf, cs...)
	buf = append(buf, compressionMethod)
	if len(extensions) > 0 {
		buf = append(buf, buildExtensionBlock(extensions)...)
	}
	return buf
}

func buildCertificatePayload(certs [][]byte) []byte {
	var certEntries []byte
	for _, cert := range certs {
		entry := make([]byte, 3+len(cert))
		entry[0] = byte(len(cert) >> 16)
		entry[1] = byte(len(cert) >> 8)
		entry[2] = byte(len(cert))
		copy(entry[3:], cert)
		certEntries = append(certEntries, entry...)
	}
	buf := make([]byte, 3+len(certEntries))
	buf[0] = byte(len(certEntries) >> 16)
	buf[1] = byte(len(certEntries) >> 8)
	buf[2] = byte(len(certEntries))
	copy(buf[3:], certEntries)
	return buf
}

// --- tests ---

func TestParseHandshakeMessages_Single(t *testing.T) {
	payload := []byte{0xAA, 0xBB}
	msg := buildHandshakeMessage(HandshakeClientHello, payload)

	msgs, leftover := ParseHandshakeMessages(msg)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if leftover != nil {
		t.Fatalf("expected no leftover, got %d bytes", len(leftover))
	}
	if msgs[0].Type != HandshakeClientHello {
		t.Errorf("expected type ClientHello, got %s", msgs[0].Type)
	}
	if msgs[0].Length != 2 {
		t.Errorf("expected length 2, got %d", msgs[0].Length)
	}
	if !bytes.Equal(msgs[0].Payload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestParseHandshakeMessages_Two(t *testing.T) {
	p1 := []byte{0x01, 0x02, 0x03}
	p2 := []byte{0x04, 0x05}
	data := append(buildHandshakeMessage(HandshakeClientHello, p1), buildHandshakeMessage(HandshakeServerHello, p2)...)

	msgs, leftover := ParseHandshakeMessages(data)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if leftover != nil {
		t.Fatalf("expected no leftover, got %d bytes", len(leftover))
	}
	if msgs[0].Type != HandshakeClientHello {
		t.Errorf("msg[0] type: expected ClientHello, got %s", msgs[0].Type)
	}
	if msgs[1].Type != HandshakeServerHello {
		t.Errorf("msg[1] type: expected ServerHello, got %s", msgs[1].Type)
	}
	if !bytes.Equal(msgs[0].Payload, p1) {
		t.Errorf("msg[0] payload mismatch")
	}
	if !bytes.Equal(msgs[1].Payload, p2) {
		t.Errorf("msg[1] payload mismatch")
	}
}

func TestParseHandshakeMessages_Incomplete(t *testing.T) {
	// Build a message that claims length 10 but only has 3 bytes of payload
	fullPayload := []byte{0x01, 0x02, 0x03}
	data := make([]byte, 4+len(fullPayload))
	data[0] = byte(HandshakeClientHello)
	data[1] = 0
	data[2] = 0
	data[3] = 10 // claims 10 bytes, only 3 available
	copy(data[4:], fullPayload)

	msgs, leftover := ParseHandshakeMessages(data)
	if len(msgs) != 0 {
		t.Fatalf("expected 0 complete messages, got %d", len(msgs))
	}
	if leftover == nil {
		t.Fatal("expected leftover bytes for incomplete message")
	}
	// The leftover should reconstruct the header + available data
	if len(leftover) != 4+len(fullPayload) {
		t.Errorf("leftover length: expected %d, got %d", 4+len(fullPayload), len(leftover))
	}
}

func TestParseClientHello(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	cipherSuites := []uint16{0x1301, 0xc02f}
	sniExt := Extension{Type: ExtServerName, Data: buildSNIExtension("example.com")}
	alpnExt := Extension{Type: ExtALPN, Data: buildALPNExtension([]string{"h2", "http/1.1"})}

	payload := buildClientHelloPayload(
		VersionTLS12,
		random,
		nil, // no session ID
		cipherSuites,
		[]byte{0x00}, // null compression
		[]Extension{sniExt, alpnExt},
	)

	msg, err := ParseClientHello(payload)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}

	if msg.Version != VersionTLS12 {
		t.Errorf("Version: expected TLS 1.2, got %s", msg.Version)
	}
	if !bytes.Equal(msg.Random, random) {
		t.Errorf("Random mismatch")
	}
	if len(msg.CipherSuites) != 2 {
		t.Fatalf("CipherSuites: expected 2, got %d", len(msg.CipherSuites))
	}
	if msg.CipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites[0]: expected 0x1301, got 0x%04x", msg.CipherSuites[0])
	}
	if msg.CipherSuites[1] != 0xc02f {
		t.Errorf("CipherSuites[1]: expected 0xc02f, got 0x%04x", msg.CipherSuites[1])
	}
	if msg.SNI != "example.com" {
		t.Errorf("SNI: expected 'example.com', got '%s'", msg.SNI)
	}
	if len(msg.ALPNProtocols) != 2 {
		t.Fatalf("ALPNProtocols: expected 2, got %d", len(msg.ALPNProtocols))
	}
	if msg.ALPNProtocols[0] != "h2" {
		t.Errorf("ALPNProtocols[0]: expected 'h2', got '%s'", msg.ALPNProtocols[0])
	}
	if msg.ALPNProtocols[1] != "http/1.1" {
		t.Errorf("ALPNProtocols[1]: expected 'http/1.1', got '%s'", msg.ALPNProtocols[1])
	}
}

func TestParseClientHello_Truncated(t *testing.T) {
	_, err := ParseClientHello([]byte{0x03, 0x03}) // too short
	if err != ErrHandshakeTruncated {
		t.Errorf("expected ErrHandshakeTruncated, got %v", err)
	}
}

func TestParseServerHello(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(0xFF - i)
	}

	payload := buildServerHelloPayload(
		VersionTLS12,
		random,
		nil,    // no session ID
		0x1301, // TLS_AES_128_GCM_SHA256
		0x00,
		nil, // no extensions
	)

	msg, err := ParseServerHello(payload)
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}

	if msg.Version != VersionTLS12 {
		t.Errorf("Version: expected TLS 1.2, got %s", msg.Version)
	}
	if msg.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite: expected 0x1301, got 0x%04x", msg.CipherSuite)
	}
	if msg.CompressionMethod != 0x00 {
		t.Errorf("CompressionMethod: expected 0, got %d", msg.CompressionMethod)
	}
}

func TestParseServerHello_Truncated(t *testing.T) {
	_, err := ParseServerHello([]byte{0x03, 0x03})
	if err != ErrHandshakeTruncated {
		t.Errorf("expected ErrHandshakeTruncated, got %v", err)
	}
}

func TestParseCertificate(t *testing.T) {
	fakeDER1 := []byte{0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC}
	fakeDER2 := []byte{0x30, 0x82, 0x02, 0xFF}

	payload := buildCertificatePayload([][]byte{fakeDER1, fakeDER2})

	msg, err := ParseCertificate(payload)
	if err != nil {
		t.Fatalf("ParseCertificate error: %v", err)
	}
	if len(msg.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(msg.Certificates))
	}
	if !bytes.Equal(msg.Certificates[0], fakeDER1) {
		t.Errorf("cert[0] mismatch")
	}
	if !bytes.Equal(msg.Certificates[1], fakeDER2) {
		t.Errorf("cert[1] mismatch")
	}
}

func TestParseCertificate_Truncated(t *testing.T) {
	_, err := ParseCertificate([]byte{0x00})
	if err != ErrHandshakeTruncated {
		t.Errorf("expected ErrHandshakeTruncated, got %v", err)
	}
}

func TestServerHelloMsg_NegotiatedVersion_NoExtension(t *testing.T) {
	random := make([]byte, 32)
	payload := buildServerHelloPayload(
		VersionTLS12,
		random,
		nil,
		0xc02f,
		0x00,
		nil,
	)

	msg, err := ParseServerHello(payload)
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}

	got := msg.NegotiatedVersion()
	if got != VersionTLS12 {
		t.Errorf("NegotiatedVersion: expected TLS 1.2, got %s", got)
	}
}

func TestServerHelloMsg_NegotiatedVersion_WithExtension(t *testing.T) {
	random := make([]byte, 32)
	svExt := Extension{
		Type: ExtSupportedVersions,
		Data: buildSupportedVersionsServerExtension(0x0304), // TLS 1.3
	}

	payload := buildServerHelloPayload(
		VersionTLS12, // legacy version field
		random,
		nil,
		0x1301,
		0x00,
		[]Extension{svExt},
	)

	msg, err := ParseServerHello(payload)
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}

	got := msg.NegotiatedVersion()
	if got != VersionTLS13 {
		t.Errorf("NegotiatedVersion: expected TLS 1.3, got %s", got)
	}
}
