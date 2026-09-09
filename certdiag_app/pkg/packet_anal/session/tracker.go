package session

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

const maxPreamble = 4096

// Tracker processes TCP connections and extracts TLS session information.
type Tracker struct {
	Aggressive bool
	KeyLog     *tls.KeyLog // optional SSLKEYLOGFILE for TLS 1.3 decryption
}

// ProcessConnections takes reassembled TCP connections and returns parsed TLS sessions.
func (t *Tracker) ProcessConnections(connections []*tcp.Connection) []*Session {
	var sessions []*Session
	for _, conn := range connections {
		s := t.processConnection(conn)
		if s != nil {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

func (t *Tracker) processConnection(conn *tcp.Connection) *Session {
	clientData, clientOffset := t.findTLSData(conn.ClientData)
	serverData, serverOffset := t.findTLSData(conn.ServerData)

	if clientData == nil && serverData == nil {
		return nil
	}

	s := &Session{
		ClientAddr: conn.ClientAddr,
		ServerAddr: conn.ServerAddr,
		StartTime:  conn.StartTime,
		EndTime:    conn.EndTime,
		State:      StateInit,
		Status:     StatusIncomplete,
		ClientRST:  conn.ClientRST,
		ServerRST:  conn.ServerRST,
		ClientFIN:  conn.ClientFIN,
		ServerFIN:  conn.ServerFIN,
	}

	if clientOffset > 0 {
		s.ClientTLSOffset = clientOffset
		s.ClientPreamble = conn.ClientData[:min(clientOffset, maxPreamble)]
	}
	if serverOffset > 0 {
		s.ServerTLSOffset = serverOffset
		s.ServerPreamble = conn.ServerData[:min(serverOffset, maxPreamble)]
	}

	t.parseDirection(s, clientData, "client")
	t.parseDirection(s, serverData, "server")

	t.maybeDecryptTLS13(s, clientData, serverData)
	t.maybeDecryptTLS12(s, clientData, serverData)

	t.finalize(s)
	return s
}

// maybeDecryptTLS12 decrypts the application data of a TLS 1.2 flow when a keylog
// with the master secret is available. The certificate is already visible in
// TLS 1.2, so this only recovers the encrypted application payload.
func (t *Tracker) maybeDecryptTLS12(s *Session, clientData, serverData []byte) {
	if s.NegotiatedVersion == nil || *s.NegotiatedVersion != tls.VersionTLS12 {
		return
	}
	if t.KeyLog == nil || t.KeyLog.Len() == 0 || s.ClientHello == nil || s.ServerHello == nil {
		return
	}

	clientApp, serverApp, err := tls.DecryptTLS12(
		clientData, serverData, s.ClientHello.Random, s.ServerHello.Random, s.ServerHello.CipherSuite, t.KeyLog)
	if err != nil {
		s.DecryptError = err.Error()
		return
	}
	s.DecryptedClientData = clientApp
	s.DecryptedServerData = serverApp
	s.AppDataDecrypted = len(clientApp) > 0 || len(serverApp) > 0
}

// maybeDecryptTLS13 recovers the server certificate from an encrypted TLS 1.3
// handshake when a keylog is available. In TLS 1.3 the Certificate message is
// encrypted, so without keys it is unrecoverable - flagged for honest reporting.
func (t *Tracker) maybeDecryptTLS13(s *Session, clientData, serverData []byte) {
	if s.NegotiatedVersion == nil || *s.NegotiatedVersion != tls.VersionTLS13 {
		return
	}
	if s.Certificates != nil {
		return
	}
	if s.ClientHello == nil || s.ServerHello == nil || len(serverData) == 0 {
		s.TLS13CertEncrypted = true
		return
	}
	if t.KeyLog == nil || t.KeyLog.Len() == 0 {
		s.TLS13CertEncrypted = true
		return
	}

	dec, err := tls.DecryptTLS13(clientData, serverData, s.ClientHello.Random, s.ServerHello.CipherSuite, t.KeyLog)
	if err != nil {
		s.TLS13CertEncrypted = true
		s.DecryptError = err.Error()
		return
	}

	msgs, _ := tls.ParseHandshakeMessages(dec.ServerHandshake)
	for _, m := range msgs {
		if m.Type != tls.HandshakeCertificate {
			continue
		}
		if cm, cerr := tls.ParseCertificateTLS13(m.Payload); cerr == nil && len(cm.Certificates) > 0 {
			s.Certificates = cm
			s.CertsDecrypted = true
			s.State = maxState(s.State, StateCertificate)
			break
		}
	}

	if len(dec.ClientApp) > 0 || len(dec.ServerApp) > 0 {
		s.DecryptedClientData = dec.ClientApp
		s.DecryptedServerData = dec.ServerApp
		s.AppDataDecrypted = true
	}

	if s.Certificates == nil {
		s.TLS13CertEncrypted = true
	}
}

func (t *Tracker) findTLSData(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return nil, 0
	}
	if tls.IsTLSData(data) {
		return data, 0
	}
	if !t.Aggressive {
		return nil, 0
	}
	offset, found := tls.FindTLSStart(data)
	if !found {
		return nil, 0
	}
	return data[offset:], offset
}

func (t *Tracker) parseDirection(s *Session, data []byte, direction string) {
	if len(data) == 0 {
		return
	}

	records, _, err := tls.ParseRecords(data)
	if err != nil {
		return
	}

	// Set record version from first record seen
	if len(records) > 0 && s.RecordVersion == (tls.Version{}) {
		s.RecordVersion = records[0].Version
	}

	// Collect all handshake payloads and parse as a contiguous stream
	// (handles handshake messages split across multiple records)
	var handshakeBuf []byte

	for _, rec := range records {
		switch rec.Type {
		case tls.ContentHandshake:
			handshakeBuf = append(handshakeBuf, rec.Payload...)

		case tls.ContentChangeCipherSpec:
			if direction == "client" {
				s.State = maxState(s.State, StateClientCCS)
			} else {
				s.State = maxState(s.State, StateServerCCS)
			}

		case tls.ContentAlert:
			alert, err := tls.ParseAlert(rec.Payload)
			if err == nil {
				s.Alert = &alert
				s.AlertFrom = direction
				s.State = StateFailed
			}

		case tls.ContentApplicationData:
			if s.State != StateFailed {
				s.State = StateEstablished
			}
		}
	}

	// Parse accumulated handshake messages
	if len(handshakeBuf) > 0 {
		t.parseHandshakeMessages(s, handshakeBuf, direction)
	}
}

func (t *Tracker) parseHandshakeMessages(s *Session, data []byte, direction string) {
	msgs, _ := tls.ParseHandshakeMessages(data)

	for _, msg := range msgs {
		switch msg.Type {
		case tls.HandshakeClientHello:
			ch, err := tls.ParseClientHello(msg.Payload)
			if err == nil {
				s.ClientHello = ch
				s.JA3, s.JA3String = tls.JA3(ch)
				s.JA4 = tls.JA4(ch)
				s.State = maxState(s.State, StateClientHello)
			}

		case tls.HandshakeServerHello:
			sh, err := tls.ParseServerHello(msg.Payload)
			if err == nil {
				s.ServerHello = sh
				v := sh.NegotiatedVersion()
				s.NegotiatedVersion = &v
				s.State = maxState(s.State, StateServerHello)
			}

		case tls.HandshakeCertificate:
			cert, err := tls.ParseCertificate(msg.Payload)
			if err == nil {
				if direction == "server" {
					s.Certificates = cert
					s.State = maxState(s.State, StateCertificate)
				} else {
					s.HasClientCertificate = true
				}
			}

		case tls.HandshakeServerKeyExchange:
			s.HasServerKeyExchange = true

		case tls.HandshakeCertificateRequest:
			s.HasCertificateRequest = true

		case tls.HandshakeServerHelloDone:
			s.State = maxState(s.State, StateServerDone)

		case tls.HandshakeClientKeyExchange:
			s.State = maxState(s.State, StateClientKX)
		}
	}
}

func (t *Tracker) finalize(s *Session) {
	switch {
	case s.State == StateEstablished:
		s.Status = StatusOK
	case s.State == StateFailed:
		s.Status = StatusFailed
		s.Diagnostic = t.alertDiagnostic(s)
	case s.ClientRST || s.ServerRST || s.ClientFIN || s.ServerFIN:
		s.State = StateAborted
		s.Status = StatusAborted
		s.Diagnostic = t.abortDiagnostic(s)
	default:
		s.Status = StatusIncomplete
	}
}

func (t *Tracker) alertDiagnostic(s *Session) string {
	if s.Alert == nil {
		return ""
	}

	lastState := s.lastMeaningfulState()
	base := fmt.Sprintf("Alert(%s) from %s after %s",
		s.Alert.Description, s.AlertFrom, lastState)

	// Add hints based on alert type and handshake state
	switch s.Alert.Description {
	case tls.AlertHandshakeFailure:
		if lastState == StateClientHello {
			return base + ". Possible causes: no overlapping cipher suites, TLS version mismatch, or SNI not recognized"
		}
		return base
	case tls.AlertProtocolVersion:
		return base + ". No common TLS version between client and server"
	case tls.AlertUnknownCA:
		return base + ". Client does not trust the server's CA"
	case tls.AlertCertificateRequired:
		return base + ". Server requires client certificate (mTLS)"
	case tls.AlertBadCertificate:
		return base + ". Peer rejected the certificate"
	case tls.AlertCertificateExpired:
		return base + ". Certificate has expired"
	case tls.AlertInsufficientSecurity:
		return base + ". Cipher suite or key too weak"
	case tls.AlertUnrecognizedName:
		return base + ". SNI hostname not recognized by server"
	default:
		return base
	}
}

func (t *Tracker) abortDiagnostic(s *Session) string {
	rstSource := ""
	if s.ClientRST {
		rstSource = "client"
	} else if s.ServerRST {
		rstSource = "server"
	}

	lastState := s.lastMeaningfulState()

	if rstSource != "" {
		return fmt.Sprintf("TCP RST from %s after %s", rstSource, lastState)
	}
	return fmt.Sprintf("Connection closed after %s (handshake incomplete)", lastState)
}

// lastMeaningfulState returns the last state before failure/abort for diagnostic messages.
func (s *Session) lastMeaningfulState() State {
	// Walk backwards through states to find the last meaningful one
	states := []State{
		StateServerCCS, StateClientCCS, StateClientKX,
		StateServerDone, StateCertificate, StateServerHello, StateClientHello,
	}
	for _, st := range states {
		if s.State >= st || s.hasReachedState(st) {
			return st
		}
	}
	return StateInit
}

func (s *Session) hasReachedState(target State) bool {
	switch target {
	case StateClientHello:
		return s.ClientHello != nil
	case StateServerHello:
		return s.ServerHello != nil
	case StateCertificate:
		return s.Certificates != nil
	default:
		return false
	}
}

func maxState(a, b State) State {
	if b > a {
		return b
	}
	return a
}
