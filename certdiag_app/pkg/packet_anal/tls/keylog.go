package tls

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// NSS Key Log labels (SSLKEYLOGFILE format). Every producer that supports the
// format (browsers, curl, OpenSSL, Go's tls.KeyLogWriter, a Java JSSE agent)
// emits these.
const (
	KeyLogClientRandom                 = "CLIENT_RANDOM"                    // TLS 1.2 master secret
	KeyLogClientHandshakeTrafficSecret = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"  // TLS 1.3
	KeyLogServerHandshakeTrafficSecret = "SERVER_HANDSHAKE_TRAFFIC_SECRET"  // TLS 1.3
	KeyLogClientTrafficSecret0         = "CLIENT_TRAFFIC_SECRET_0"          // TLS 1.3 app data
	KeyLogServerTrafficSecret0         = "SERVER_TRAFFIC_SECRET_0"          // TLS 1.3 app data
	KeyLogClientEarlyTrafficSecret     = "CLIENT_EARLY_TRAFFIC_SECRET"      // TLS 1.3 0-RTT
	KeyLogExporterSecret               = "EXPORTER_SECRET"                  // TLS 1.3
)

// KeyLog holds parsed SSLKEYLOGFILE secrets, indexed by client random and label.
// The client random (the ClientHello.Random, 32 bytes) is the join key back to a
// captured TLS session.
type KeyLog struct {
	entries map[string]map[string][]byte // clientRandomHex(lower) -> label -> secret
}

// ParseKeyLog reads an NSS Key Log stream. Malformed and comment lines are
// skipped; a keylog with no usable lines yields an empty (non-nil) KeyLog.
func ParseKeyLog(r io.Reader) (*KeyLog, error) {
	kl := &KeyLog{entries: make(map[string]map[string][]byte)}
	sc := bufio.NewScanner(r)
	// Secrets are short, but allow generous lines.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		label := fields[0]
		randomHex := strings.ToLower(fields[1])
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			continue
		}
		if _, err := hex.DecodeString(randomHex); err != nil {
			continue
		}
		byLabel := kl.entries[randomHex]
		if byLabel == nil {
			byLabel = make(map[string][]byte)
			kl.entries[randomHex] = byLabel
		}
		byLabel[label] = secret
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return kl, nil
}

// ParseKeyLogFile reads and parses an SSLKEYLOGFILE from disk.
func ParseKeyLogFile(path string) (*KeyLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseKeyLog(f)
}

// Secret returns the secret for a client random + label, if present.
func (k *KeyLog) Secret(clientRandom []byte, label string) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	byLabel, ok := k.entries[hex.EncodeToString(clientRandom)]
	if !ok {
		return nil, false
	}
	secret, ok := byLabel[label]
	return secret, ok
}

// Len returns the number of distinct client randoms with secrets.
func (k *KeyLog) Len() int {
	if k == nil {
		return 0
	}
	return len(k.entries)
}
