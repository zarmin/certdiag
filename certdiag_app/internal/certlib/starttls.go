package certlib

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// PerformStarttls runs the STARTTLS negotiation for proto and bounds it with the
// caller's deadline. The deadline is absolute, so it also stays in effect for the
// caller's subsequent TLS handshake: a server that stalls after STARTTLS cannot
// hang the probe, and the caller's timeout is honored end to end (rather than a
// fixed value that ignored --timeout). Interactive callers that keep the
// connection open past the handshake (e.g. the pipe view) must clear the deadline
// afterwards; pass a non-zero deadline so the plaintext exchange stays bounded.
func PerformStarttls(conn net.Conn, proto StarttlsProtocol, hostname string, deadline time.Time) error {
	conn.SetDeadline(deadline)
	return performStarttlsProto(conn, proto, hostname)
}

func performStarttlsProto(conn net.Conn, proto StarttlsProtocol, hostname string) error {
	switch proto {
	case StarttlsSMTP:
		return starttlsSMTP(conn)
	case StarttlsIMAP:
		return starttlsIMAP(conn)
	case StarttlsPOP3:
		return starttlsPOP3(conn)
	case StarttlsFTP:
		return starttlsFTP(conn)
	case StarttlsLDAP:
		return starttlsLDAP(conn)
	case StarttlsMySQL:
		return starttlsMySQL(conn)
	case StarttlsPostgres:
		return starttlsPostgres(conn)
	default:
		return fmt.Errorf("protocol not supported: %s", proto)
	}
}

func starttlsSMTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Read server greeting (may be multi-line: 220-... then 220 ...)
	for {
		greeting, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading SMTP greeting: %w", err)
		}
		if !strings.HasPrefix(greeting, "220") {
			return fmt.Errorf("unexpected SMTP greeting: %s", strings.TrimSpace(greeting))
		}
		if len(greeting) >= 4 && greeting[3] == ' ' {
			break
		}
	}

	// Send EHLO
	if _, err := fmt.Fprintf(conn, "EHLO certdiag\r\n"); err != nil {
		return fmt.Errorf("sending EHLO: %w", err)
	}

	// Read EHLO response (multi-line: 250-... then 250 ...)
	hasStarttls := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading EHLO response: %w", err)
		}
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			hasStarttls = true
		}
		// Final line is "250 " (space, not dash)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	if !hasStarttls {
		return fmt.Errorf("server does not advertise STARTTLS")
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("sending STARTTLS: %w", err)
	}

	// Read response
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading STARTTLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "220") {
		return fmt.Errorf("STARTTLS command rejected: %s", strings.TrimSpace(resp))
	}

	return nil
}

const (
	imapCapabilityTag = "a001"
	imapStarttlsTag   = "a002"
)

func starttlsIMAP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading IMAP greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("unexpected IMAP greeting: %s", strings.TrimSpace(greeting))
	}

	// Check if STARTTLS is in the capability line
	if !strings.Contains(strings.ToUpper(greeting), "STARTTLS") {
		// Try CAPABILITY command to check
		if _, err := fmt.Fprintf(conn, "%s CAPABILITY\r\n", imapCapabilityTag); err != nil {
			return fmt.Errorf("sending CAPABILITY: %w", err)
		}
		hasStarttls := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading CAPABILITY response: %w", err)
			}
			if strings.Contains(strings.ToUpper(line), "STARTTLS") {
				hasStarttls = true
			}
			if strings.HasPrefix(line, imapCapabilityTag+" ") {
				break
			}
		}
		if !hasStarttls {
			return fmt.Errorf("server does not advertise STARTTLS")
		}
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "%s STARTTLS\r\n", imapStarttlsTag); err != nil {
		return fmt.Errorf("sending STARTTLS: %w", err)
	}

	// Success is only the tagged completion line "aNNN OK ...".
	// Untagged "*" lines and banners containing "OK" must not be mistaken for it.
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading STARTTLS response: %w", err)
		}
		if !strings.HasPrefix(resp, imapStarttlsTag+" ") {
			continue
		}
		if strings.HasPrefix(resp, imapStarttlsTag+" OK") {
			return nil
		}
		return fmt.Errorf("STARTTLS command rejected: %s", strings.TrimSpace(resp))
	}
}

func starttlsPOP3(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("unexpected POP3 greeting: %s", strings.TrimSpace(greeting))
	}

	// Send STLS
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("sending STLS: %w", err)
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading STLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "+OK") {
		return fmt.Errorf("STARTTLS command rejected: %s", strings.TrimSpace(resp))
	}

	return nil
}

func starttlsFTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Read server greeting (may be multi-line: 220-... then 220 ...)
	for {
		greeting, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading FTP greeting: %w", err)
		}
		if !strings.HasPrefix(greeting, "220") {
			return fmt.Errorf("unexpected FTP greeting: %s", strings.TrimSpace(greeting))
		}
		// Final line is "220 " (space, not dash)
		if len(greeting) >= 4 && greeting[3] == ' ' {
			break
		}
	}

	// Send AUTH TLS
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("sending AUTH TLS: %w", err)
	}

	// Read AUTH TLS response (may be multi-line: 234-... then 234 ...)
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading AUTH TLS response: %w", err)
		}
		if !strings.HasPrefix(resp, "234") {
			return fmt.Errorf("STARTTLS command rejected: %s", strings.TrimSpace(resp))
		}
		// Final line is "234 " (space, not dash)
		if len(resp) >= 4 && resp[3] == ' ' {
			break
		}
	}

	return nil
}

func starttlsLDAP(conn net.Conn) error {

	// LDAP StartTLS Extended Operation
	// OID: 1.3.6.1.4.1.1466.20037
	oid := "1.3.6.1.4.1.1466.20037"
	oidBytes := encodeLDAPOID(oid)

	// Build LDAP ExtendedRequest
	// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	//     requestName  [0] LDAPOID
	// }
	requestName := encodeBERTag(0x80, oidBytes) // [0] context-specific
	extReq := encodeBERTag(0x77, requestName)   // [APPLICATION 23]

	// Wrap in LDAPMessage
	// LDAPMessage ::= SEQUENCE {
	//     messageID  INTEGER
	//     protocolOp CHOICE { ... }
	// }
	msgID := encodeBERTag(0x02, []byte{0x01}) // INTEGER 1
	msg := encodeBERTag(0x30, append(msgID, extReq...))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("sending LDAP StartTLS request: %w", err)
	}

	// Read the full BER-encoded LDAPMessage; a fragmented TCP response must not
	// be parsed from a single Read.
	resp, err := readLDAPMessage(conn)
	if err != nil {
		return fmt.Errorf("reading LDAP StartTLS response: %w", err)
	}

	// Parse minimal: look for resultCode in ExtendedResponse
	// resultCode 0 = success
	resultCode, err := parseLDAPExtendedResponse(resp)
	if err != nil {
		return fmt.Errorf("parsing LDAP response: %w", err)
	}
	if resultCode != 0 {
		return fmt.Errorf("LDAP StartTLS failed with result code %d", resultCode)
	}

	return nil
}

func readLDAPMessage(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	lenByte := header[1]
	if lenByte < 0x80 {
		body := make([]byte, int(lenByte))
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		return append(header, body...), nil
	}
	numLenBytes := int(lenByte & 0x7F)
	if numLenBytes == 0 || numLenBytes > 4 {
		return nil, fmt.Errorf("unsupported LDAP length encoding")
	}
	lenOctets := make([]byte, numLenBytes)
	if _, err := io.ReadFull(conn, lenOctets); err != nil {
		return nil, err
	}
	length := 0
	for _, b := range lenOctets {
		length = (length << 8) | int(b)
	}
	msg := make([]byte, 2+numLenBytes+length)
	copy(msg, header)
	copy(msg[2:], lenOctets)
	if _, err := io.ReadFull(conn, msg[2+numLenBytes:]); err != nil {
		return nil, err
	}
	return msg, nil
}

func encodeLDAPOID(oid string) []byte {
	return []byte(oid)
}

func encodeBERTag(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	}
	// Long form length encoding
	if length <= 0xFF {
		return append([]byte{tag, 0x81, byte(length)}, data...)
	}
	return append([]byte{tag, 0x82, byte(length >> 8), byte(length)}, data...)
}

func parseLDAPExtendedResponse(data []byte) (int, error) {
	if len(data) < 2 {
		return -1, fmt.Errorf("response too short")
	}

	// Outer SEQUENCE (0x30)
	if data[0] != 0x30 {
		return -1, fmt.Errorf("expected SEQUENCE, got 0x%02x", data[0])
	}

	inner, err := berContents(data)
	if err != nil {
		return -1, err
	}

	// Skip messageID (INTEGER, tag 0x02)
	if len(inner) < 2 || inner[0] != 0x02 {
		return -1, fmt.Errorf("expected INTEGER for messageID")
	}
	idLen := int(inner[1])
	if len(inner) < 2+idLen {
		return -1, fmt.Errorf("truncated messageID")
	}
	inner = inner[2+idLen:]

	// ExtendedResponse [APPLICATION 24] (tag 0x78)
	if len(inner) < 2 || inner[0] != 0x78 {
		return -1, fmt.Errorf("expected ExtendedResponse (0x78), got 0x%02x", inner[0])
	}

	extResp, err := berContents(inner)
	if err != nil {
		return -1, err
	}

	// First element is resultCode (ENUMERATED, tag 0x0A)
	if len(extResp) < 2 || extResp[0] != 0x0A {
		return -1, fmt.Errorf("expected ENUMERATED for resultCode, got 0x%02x", extResp[0])
	}
	rcLen := int(extResp[1])
	if rcLen != 1 || len(extResp) < 3 {
		return -1, fmt.Errorf("unexpected resultCode length")
	}
	return int(extResp[2]), nil
}

func berContents(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("BER data too short")
	}
	lenByte := data[1]
	if lenByte < 128 {
		end := 2 + int(lenByte)
		if end > len(data) {
			return nil, fmt.Errorf("BER length exceeds data")
		}
		return data[2:end], nil
	}
	numLenBytes := int(lenByte & 0x7F)
	if len(data) < 2+numLenBytes {
		return nil, fmt.Errorf("BER long length exceeds data")
	}
	var length int
	for i := 0; i < numLenBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	start := 2 + numLenBytes
	end := start + length
	if end > len(data) {
		return nil, fmt.Errorf("BER content exceeds data")
	}
	return data[start:end], nil
}

func starttlsMySQL(conn net.Conn) error {

	// Read initial handshake packet
	// MySQL packet: 3 bytes length + 1 byte seq + payload
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading MySQL handshake header: %w", err)
	}

	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLen > 65535 {
		return fmt.Errorf("MySQL handshake packet too large: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("reading MySQL handshake payload: %w", err)
	}

	// Parse handshake to find capability flags
	// Protocol version is first byte (should be 10)
	if len(payload) < 1 {
		return fmt.Errorf("empty MySQL handshake payload")
	}
	if payload[0] != 10 {
		return fmt.Errorf("unexpected MySQL protocol version: %d", payload[0])
	}

	// Skip server version (null-terminated string)
	nullIdx := 0
	for nullIdx < len(payload) && payload[nullIdx] != 0 {
		nullIdx++
	}
	if nullIdx >= len(payload) {
		return fmt.Errorf("malformed MySQL handshake: missing null terminator")
	}
	pos := nullIdx + 1

	// Skip connection ID (4 bytes) + auth-plugin-data-part-1 (8 bytes) + filler (1 byte)
	pos += 4 + 8 + 1
	if pos+2 > len(payload) {
		return fmt.Errorf("malformed MySQL handshake: too short for capabilities")
	}

	// Capability flags (lower 2 bytes)
	capLower := binary.LittleEndian.Uint16(payload[pos : pos+2])
	const clientSSL = 0x0800
	if capLower&clientSSL == 0 {
		return fmt.Errorf("server does not advertise STARTTLS (CLIENT_SSL capability not set)")
	}

	// Send SSL Request packet
	// Capability flags (4 bytes) + max packet size (4 bytes) + charset (1 byte) + reserved (23 bytes)
	sslReq := make([]byte, 32)
	// Set CLIENT_SSL and CLIENT_PROTOCOL_41 flags
	binary.LittleEndian.PutUint32(sslReq[0:4], uint32(clientSSL)|0x00000200)
	// Max packet size
	binary.LittleEndian.PutUint32(sslReq[4:8], 16777216)
	// Charset (utf8_general_ci = 33)
	sslReq[8] = 33

	// Wrap in MySQL packet header
	pktHeader := make([]byte, 4)
	pktHeader[0] = byte(len(sslReq))
	pktHeader[1] = byte(len(sslReq) >> 8)
	pktHeader[2] = byte(len(sslReq) >> 16)
	pktHeader[3] = 1 // sequence number

	if _, err := conn.Write(append(pktHeader, sslReq...)); err != nil {
		return fmt.Errorf("sending MySQL SSL request: %w", err)
	}

	return nil
}

func starttlsPostgres(conn net.Conn) error {

	// SSLRequest message: 8 bytes
	// Int32(8) = length (including self)
	// Int32(80877103) = SSL request code
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)

	if _, err := conn.Write(sslReq); err != nil {
		return fmt.Errorf("sending PostgreSQL SSLRequest: %w", err)
	}

	// Read response: single byte 'S' or 'N'
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("reading PostgreSQL SSL response: %w", err)
	}

	switch resp[0] {
	case 'S':
		return nil
	case 'N':
		return fmt.Errorf("server does not advertise STARTTLS (SSL not supported)")
	default:
		return fmt.Errorf("unexpected PostgreSQL response: 0x%02x", resp[0])
	}
}
