package session

import (
	"fmt"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

type State int

const (
	StateInit           State = iota
	StateClientHello          // ClientHello seen
	StateServerHello          // ServerHello seen
	StateCertificate          // Certificate seen
	StateServerDone           // ServerHelloDone seen
	StateClientKX             // ClientKeyExchange seen
	StateClientCCS            // Client ChangeCipherSpec seen
	StateServerCCS            // Server ChangeCipherSpec seen
	StateEstablished          // ApplicationData seen (handshake succeeded)
	StateFailed               // Alert received
	StateAborted              // TCP RST/FIN without completion
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateClientHello:
		return "ClientHello"
	case StateServerHello:
		return "ServerHello"
	case StateCertificate:
		return "Certificate"
	case StateServerDone:
		return "ServerHelloDone"
	case StateClientKX:
		return "ClientKeyExchange"
	case StateClientCCS:
		return "ClientCCS"
	case StateServerCCS:
		return "ServerCCS"
	case StateEstablished:
		return "Established"
	case StateFailed:
		return "Failed"
	case StateAborted:
		return "Aborted"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

type Status int

const (
	StatusOK       Status = iota // Handshake completed successfully
	StatusFailed                 // Alert received
	StatusAborted                // TCP ended before handshake completed
	StatusIncomplete             // Still in progress (shouldn't appear in final output)
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusFailed:
		return "FAILED"
	case StatusAborted:
		return "ABORTED"
	case StatusIncomplete:
		return "INCOMPLETE"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// Session represents a single TLS session with all extracted information.
type Session struct {
	ClientAddr string
	ServerAddr string
	StartTime  time.Time
	EndTime    time.Time
	State      State
	Status     Status

	// TLS version
	RecordVersion    tls.Version    // from the record layer
	NegotiatedVersion *tls.Version  // from ServerHello (or supported_versions)

	// Handshake data
	ClientHello *tls.ClientHelloMsg
	ServerHello *tls.ServerHelloMsg
	Certificates *tls.CertificateMsg

	// Client fingerprints (computed from the ClientHello).
	JA3       string
	JA3String string
	JA4       string

	// TLS 1.3: the Certificate message is encrypted. CertsDecrypted is set when
	// certs were recovered via a keylog; TLS13CertEncrypted is set when they
	// could not be (no keylog, or decryption failed). DecryptError carries why.
	CertsDecrypted     bool
	TLS13CertEncrypted bool
	DecryptError       string

	// Decrypted application data (TLS 1.2 via keylog; populated when keys resolve).
	DecryptedClientData []byte
	DecryptedServerData []byte
	AppDataDecrypted    bool

	// Flags for presence of optional messages
	HasCertificateRequest bool // server requested client cert (mTLS)
	HasServerKeyExchange  bool // ephemeral key exchange
	HasClientCertificate  bool // client sent a certificate

	// Alert (if handshake failed)
	Alert     *tls.Alert
	AlertFrom string // "client" or "server"

	// Aggressive scan (STARTTLS)
	ClientTLSOffset int
	ServerTLSOffset int
	ClientPreamble  []byte
	ServerPreamble  []byte

	// TCP-level info
	ClientRST bool
	ServerRST bool
	ClientFIN bool
	ServerFIN bool

	// Diagnostic message (set by Finalize)
	Diagnostic string
}

func (s *Session) MatchesSearch(query string) bool {
	if query == "" {
		return true
	}
	q := strings.ToLower(query)
	for _, f := range []string{
		s.ClientAddr, s.ServerAddr,
		s.SNI(), s.CipherSuite(), s.VersionString(),
		s.Status.String(),
	} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (s *Session) SNI() string {
	if s.ClientHello != nil {
		return s.ClientHello.SNI
	}
	return ""
}

func (s *Session) CipherSuite() string {
	if s.ServerHello != nil {
		return tls.CipherSuiteName(s.ServerHello.CipherSuite)
	}
	return "--"
}

func (s *Session) CipherSuiteCode() uint16 {
	if s.ServerHello != nil {
		return s.ServerHello.CipherSuite
	}
	return 0
}

func (s *Session) VersionString() string {
	if s.NegotiatedVersion != nil {
		return s.NegotiatedVersion.String()
	}
	return "--"
}
