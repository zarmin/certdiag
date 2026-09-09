package certops

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func selfSignedHTTPCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestHTTPRemote_RedirectChainStatusCodes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/c", http.StatusFound)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("done"))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:          srv.URL + "/a",
		FollowRedirects: true,
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("HTTPRemote: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("result error: %s", result.Error)
	}

	chain := result.Response.RedirectChain
	if len(chain) != 2 {
		t.Fatalf("expected 2 redirect hops, got %d: %+v", len(chain), chain)
	}
	if chain[0].StatusCode != http.StatusMovedPermanently {
		t.Errorf("hop 0 StatusCode = %d, want %d", chain[0].StatusCode, http.StatusMovedPermanently)
	}
	if chain[1].StatusCode != http.StatusFound {
		t.Errorf("hop 1 StatusCode = %d, want %d", chain[1].StatusCode, http.StatusFound)
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("final StatusCode = %d, want 200", result.Response.StatusCode)
	}
}

func startSMTPStartTLSHTTPServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				conn.Write([]byte("220 test ESMTP\r\n"))
				r.ReadString('\n') // EHLO
				conn.Write([]byte("250-test\r\n250 STARTTLS\r\n"))
				r.ReadString('\n') // STARTTLS
				conn.Write([]byte("220 go ahead\r\n"))

				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				br := bufio.NewReader(tlsConn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestHTTPRemote_StarttlsHonored(t *testing.T) {
	cert := selfSignedHTTPCert(t)
	addr, stop := startSMTPStartTLSHTTPServer(t, cert)
	defer stop()

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:   "https://" + addr,
		Starttls: "smtp",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("HTTPRemote: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("expected STARTTLS+HTTP success, got error: %s", result.Error)
	}
	if result.Response == nil || result.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 over STARTTLS, got %+v", result.Response)
	}
}

func TestHTTPRemote_StarttlsRequiredForStarttlsServer(t *testing.T) {
	cert := selfSignedHTTPCert(t)
	addr, stop := startSMTPStartTLSHTTPServer(t, cert)
	defer stop()

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:  "https://" + addr,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("HTTPRemote: %v", err)
	}
	if result.Error == "" {
		t.Fatal("expected TLS failure without STARTTLS against a STARTTLS-only server")
	}
}

func TestHTTPRemote_InvalidStarttls(t *testing.T) {
	_, err := HTTPRemote(HTTPRemoteOptions{
		Target:   "https://example.com",
		Starttls: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid STARTTLS protocol")
	}
}
