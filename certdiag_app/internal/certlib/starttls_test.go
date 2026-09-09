package certlib

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func startMockServer(t *testing.T, handler func(conn net.Conn)) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return listener
}

func dialMock(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// --- SMTP tests ---

func TestStarttlsSMTP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220 mail.test ESMTP\r\n"))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "EHLO") {
				return
			}
			conn.Write([]byte("250-mail.test\r\n250-STARTTLS\r\n250 OK\r\n"))
			n, _ = conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "STARTTLS") {
				return
			}
			conn.Write([]byte("220 Ready to start TLS\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsSMTP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("multiline greeting", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220-mail.test ESMTP Exim 4.99\r\n"))
			conn.Write([]byte("220-We do not authorize unsolicited email.\r\n"))
			conn.Write([]byte("220 Ready\r\n"))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "EHLO") {
				return
			}
			conn.Write([]byte("250-mail.test\r\n250-STARTTLS\r\n250 OK\r\n"))
			n, _ = conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "STARTTLS") {
				return
			}
			conn.Write([]byte("220 Ready to start TLS\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsSMTP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no STARTTLS advertised", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220 mail.test ESMTP\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("250-mail.test\r\n250 OK\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsSMTP(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "does not advertise STARTTLS") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("STARTTLS rejected", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220 mail.test ESMTP\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("250-mail.test\r\n250-STARTTLS\r\n250 OK\r\n"))
			conn.Read(buf)
			conn.Write([]byte("454 TLS not available\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsSMTP(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Errorf("wrong error: %v", err)
		}
	})
}

// --- IMAP tests ---

func TestStarttlsIMAP(t *testing.T) {
	t.Run("STARTTLS in greeting", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] server ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("a002 OK Begin TLS\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsIMAP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("STARTTLS via CAPABILITY", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("* OK server ready\r\n"))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "CAPABILITY") {
				conn.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK\r\n"))
			}
			n, _ = conn.Read(buf)
			if strings.Contains(string(buf[:n]), "STARTTLS") {
				conn.Write([]byte("a002 OK Begin TLS\r\n"))
			}
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsIMAP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("tagged NO despite untagged OK", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] server ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			// Untagged line contains "OK" but the tagged completion is NO.
			conn.Write([]byte("* OK still here\r\na002 NO STARTTLS not available\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsIMAP(conn)
		if err == nil {
			t.Fatal("expected error, STARTTLS should be rejected on tagged NO")
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("untagged lines before tagged OK", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] server ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("* some untagged chatter\r\na002 OK Begin TLS\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsIMAP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- POP3 tests ---

func TestStarttlsPOP3(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("+OK POP3 ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("+OK Begin TLS\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsPOP3(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("+OK POP3 ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("-ERR not supported\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsPOP3(conn)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- FTP tests ---

func TestStarttlsFTP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220 FTP ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("234 Proceed\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsFTP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("multiline greeting", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220-FTP server ready\r\n"))
			conn.Write([]byte("220-Unauthorized access is prohibited\r\n"))
			conn.Write([]byte("220 Welcome\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("234 Proceed\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsFTP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("multiline AUTH TLS response", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220-FTP server ready\r\n"))
			conn.Write([]byte("220 Welcome\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("234-Beginning TLS negotiation\r\n"))
			conn.Write([]byte("234 AUTH TLS OK\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsFTP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			conn.Write([]byte("220 FTP ready\r\n"))
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte("500 AUTH not understood\r\n"))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsFTP(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Errorf("wrong error: %v", err)
		}
	})
}

// --- LDAP tests ---

func TestStarttlsLDAP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n == 0 {
				return
			}
			// Build a minimal ExtendedResponse with resultCode=0 (success)
			// resultCode: ENUMERATED 0
			resultCode := encodeBERTag(0x0A, []byte{0x00})
			// matchedDN: OCTET STRING ""
			matchedDN := encodeBERTag(0x04, []byte{})
			// diagnosticMessage: OCTET STRING ""
			diagMsg := encodeBERTag(0x04, []byte{})

			extResp := append(resultCode, matchedDN...)
			extResp = append(extResp, diagMsg...)
			extRespWrapped := encodeBERTag(0x78, extResp) // [APPLICATION 24]

			msgID := encodeBERTag(0x02, []byte{0x01})
			msg := encodeBERTag(0x30, append(msgID, extRespWrapped...))
			conn.Write(msg)
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsLDAP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure result code", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)

			resultCode := encodeBERTag(0x0A, []byte{0x01}) // resultCode=1 (operationsError)
			matchedDN := encodeBERTag(0x04, []byte{})
			diagMsg := encodeBERTag(0x04, []byte{})

			extResp := append(resultCode, matchedDN...)
			extResp = append(extResp, diagMsg...)
			extRespWrapped := encodeBERTag(0x78, extResp)

			msgID := encodeBERTag(0x02, []byte{0x01})
			msg := encodeBERTag(0x30, append(msgID, extRespWrapped...))
			conn.Write(msg)
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsLDAP(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "result code") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("malformed response", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
			conn.Write([]byte{0xFF, 0x00})
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsLDAP(conn)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("fragmented success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)

			resultCode := encodeBERTag(0x0A, []byte{0x00})
			matchedDN := encodeBERTag(0x04, []byte{})
			diagMsg := encodeBERTag(0x04, []byte{})
			extResp := append(resultCode, matchedDN...)
			extResp = append(extResp, diagMsg...)
			extRespWrapped := encodeBERTag(0x78, extResp)
			msgID := encodeBERTag(0x02, []byte{0x01})
			msg := encodeBERTag(0x30, append(msgID, extRespWrapped...))

			// Deliver the BER message split across two TCP writes.
			split := len(msg) / 2
			conn.Write(msg[:split])
			time.Sleep(50 * time.Millisecond)
			conn.Write(msg[split:])
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsLDAP(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- PostgreSQL tests ---

func TestStarttlsPostgres(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 8)
			conn.Read(buf)
			conn.Write([]byte{'S'})
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsPostgres(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("SSL not supported", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 8)
			conn.Read(buf)
			conn.Write([]byte{'N'})
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsPostgres(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("wrong error: %v", err)
		}
	})
}

// --- MySQL tests ---

func TestStarttlsMySQL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			// Build a minimal MySQL handshake packet
			// Protocol version (1 byte) + server version (null-term) +
			// connection ID (4) + auth data part1 (8) + filler (1) + capabilities (2)
			serverVersion := append([]byte("8.0.30"), 0) // null terminated
			payload := []byte{10}                        // protocol v10
			payload = append(payload, serverVersion...)
			payload = append(payload, 0, 0, 0, 0)             // connection ID
			payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0) // auth data
			payload = append(payload, 0)                      // filler
			capBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(capBytes, 0x0800) // CLIENT_SSL
			payload = append(payload, capBytes...)

			// MySQL packet header: 3 bytes length + 1 byte seq
			header := make([]byte, 4)
			header[0] = byte(len(payload))
			header[1] = byte(len(payload) >> 8)
			header[2] = byte(len(payload) >> 16)
			header[3] = 0 // seq 0
			conn.Write(append(header, payload...))

			// Read SSL request
			sslHeader := make([]byte, 4)
			conn.Read(sslHeader)
			sslPayload := make([]byte, 32)
			conn.Read(sslPayload)
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		if err := starttlsMySQL(conn); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no CLIENT_SSL", func(t *testing.T) {
		listener := startMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			serverVersion := append([]byte("5.7.0"), 0)
			payload := []byte{10}
			payload = append(payload, serverVersion...)
			payload = append(payload, 0, 0, 0, 0)
			payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0)
			payload = append(payload, 0)
			capBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(capBytes, 0x0000) // no CLIENT_SSL
			payload = append(payload, capBytes...)

			header := make([]byte, 4)
			header[0] = byte(len(payload))
			conn.Write(append(header, payload...))
		})
		defer listener.Close()

		conn := dialMock(t, listener)
		defer conn.Close()

		err := starttlsMySQL(conn)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "CLIENT_SSL") {
			t.Errorf("wrong error: %v", err)
		}
	})
}

// --- BER encoding tests ---

func TestEncodeBERTag(t *testing.T) {
	// Short form
	data := []byte{0x01, 0x02, 0x03}
	result := encodeBERTag(0x30, data)
	if result[0] != 0x30 || result[1] != 3 {
		t.Errorf("expected tag=0x30 len=3, got tag=0x%02x len=%d", result[0], result[1])
	}
	if len(result) != 5 {
		t.Errorf("expected 5 bytes, got %d", len(result))
	}
}

func TestParseLDAPExtendedResponse(t *testing.T) {
	// Build a valid response with resultCode=0
	resultCode := encodeBERTag(0x0A, []byte{0x00})
	matchedDN := encodeBERTag(0x04, []byte{})
	diagMsg := encodeBERTag(0x04, []byte{})

	extResp := append(resultCode, matchedDN...)
	extResp = append(extResp, diagMsg...)
	extRespWrapped := encodeBERTag(0x78, extResp)

	msgID := encodeBERTag(0x02, []byte{0x01})
	msg := encodeBERTag(0x30, append(msgID, extRespWrapped...))

	code, err := parseLDAPExtendedResponse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("resultCode = %d, want 0", code)
	}
}

// --- PerformStarttls dispatch tests ---

func TestPerformStarttlsUnknownProtocol(t *testing.T) {
	conn, _ := net.Pipe()
	defer conn.Close()

	err := PerformStarttls(conn, StarttlsProtocol("unknown"), "host", time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestDefaultStarttlsPortMapping(t *testing.T) {
	// Already tested in remote_test.go but verify here too
	expected := map[StarttlsProtocol]int{
		StarttlsSMTP:     587,
		StarttlsIMAP:     143,
		StarttlsPOP3:     110,
		StarttlsFTP:      21,
		StarttlsLDAP:     389,
		StarttlsMySQL:    3306,
		StarttlsPostgres: 5432,
	}

	for proto, port := range expected {
		got := DefaultStarttlsPort(proto)
		if got != port {
			t.Errorf("DefaultStarttlsPort(%s) = %d, want %d", proto, got, port)
		}
	}
}

// Suppress unused import warnings
var _ = fmt.Sprintf
