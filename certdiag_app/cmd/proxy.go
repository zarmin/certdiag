package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	pktoutput "github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/proxy"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"

	"gopkg.in/yaml.v3"
)

var (
	proxyListen     string
	proxyTarget     string
	proxyAggressive bool
	proxyFilter     string
	proxyDetail     bool
	proxyDumpDir    string
	proxyNDJSON     bool
	proxyMultiYAML  bool
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [flags]",
	Short: "Transparent TCP proxy for live TLS interception",
	Long: `Start a transparent TCP proxy that intercepts TLS handshakes.

The proxy does NOT terminate TLS -- it forwards raw TCP bytes and passively
parses the TLS handshake from the stream. Use this when you can control
routing but don't have root for packet capture.`,
	Run: func(cmd *cobra.Command, args []string) {
		if proxyListen == "" || proxyTarget == "" {
			fmt.Fprintln(os.Stderr, "Error: both --listen and --target are required")
			os.Exit(1)
		}
		runProxy()
	},
}

func init() {
	proxyCmd.Flags().StringVarP(&proxyListen, "listen", "l", "", "Proxy listen address (e.g. :8443)")
	proxyCmd.Flags().StringVarP(&proxyTarget, "target", "t", "", "Proxy target address (e.g. host:443)")
	proxyCmd.Flags().BoolVarP(&proxyAggressive, "aggressive", "a", false, "Scan for TLS within streams (STARTTLS)")
	proxyCmd.Flags().StringVarP(&proxyFilter, "filter", "f", "", "Search string for session filtering")
	proxyCmd.Flags().BoolVarP(&proxyDetail, "detail", "d", false, "Show detailed session info")
	proxyCmd.Flags().StringVar(&proxyDumpDir, "dump-dir", "", "Auto-save intercepted certs to directory")
	proxyCmd.Flags().BoolVar(&proxyNDJSON, "ndjson", false, "Output as NDJSON (one JSON object per line)")
	proxyCmd.Flags().BoolVar(&proxyMultiYAML, "multiyaml", false, "Output as multi-document YAML")

	rootCmd.AddCommand(proxyCmd)
}

func runProxy() {
	if proxyDumpDir != "" {
		if err := os.MkdirAll(proxyDumpDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating dump directory: %v\n", err)
			os.Exit(1)
		}
	}

	var mu sync.Mutex
	sessionIndex := 0
	totalSessions := 0
	matchedSessions := 0
	usedNames := make(map[string]int)

	tracker := &session.Tracker{Aggressive: proxyAggressive}

	p := proxy.New(proxyListen, proxyTarget)

	p.OnConnection = func(c *tcp.Connection) {
		sessions := tracker.ProcessConnections([]*tcp.Connection{c})

		mu.Lock()
		defer mu.Unlock()

		for _, s := range sessions {
			totalSessions++
			if !s.MatchesSearch(proxyFilter) {
				continue
			}
			matchedSessions++
			sessionIndex++

			emitSession(os.Stdout, s, sessionIndex)
			if proxyDetail {
				pktoutput.PrintDetail(os.Stdout, s, sessionIndex)
			}

			if proxyDumpDir != "" {
				dumpSessionCerts(s, proxyDumpDir, usedNames)
			}
		}
	}

	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Proxy listening on %s -> %s\n", proxyListen, proxyTarget)

	if !proxyNDJSON && !proxyMultiYAML {
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', 0)
		fmt.Fprintln(tw, "#\tTimestamp\tSource\tDest\tVer\tCipher Suite\tSNI\tStatus")
		tw.Flush()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintln(os.Stderr)
	p.Stop()

	mu.Lock()
	defer mu.Unlock()

	if proxyFilter != "" {
		fmt.Fprintf(os.Stderr, "Connections: %d | TLS sessions: %d (%d matched filter)\n",
			p.ConnCount(), totalSessions, matchedSessions)
	} else {
		fmt.Fprintf(os.Stderr, "Connections: %d | TLS sessions: %d\n",
			p.ConnCount(), totalSessions)
	}
}

func dumpSessionCerts(s *session.Session, dir string, usedNames map[string]int) {
	if s.Certificates == nil || len(s.Certificates.Certificates) == 0 {
		return
	}

	name := proxyChainFileName(s)
	usedNames[name]++
	if usedNames[name] > 1 {
		name = fmt.Sprintf("%s_%d", name, usedNames[name])
	}

	outPath := filepath.Join(dir, name+"_chain.pem")
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
		return
	}
	defer f.Close()

	for _, der := range s.Certificates.Certificates {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	fmt.Fprintf(os.Stderr, "  Saved: %s\n", outPath)
}

func proxyChainFileName(s *session.Session) string {
	if s.Certificates != nil && len(s.Certificates.Certificates) > 0 {
		if cert, err := x509.ParseCertificate(s.Certificates.Certificates[0]); err == nil && cert.Subject.CommonName != "" {
			return stringutil.SanitizeFilename(cert.Subject.CommonName)
		}
	}
	if sni := s.SNI(); sni != "" {
		return stringutil.SanitizeFilename(sni)
	}
	return stringutil.SanitizeFilename(s.ServerAddr)
}

func emitSession(w io.Writer, s *session.Session, index int) {
	if proxyNDJSON {
		emitNDJSON(w, s, index)
	} else if proxyMultiYAML {
		emitMultiYAML(w, s, index)
	} else {
		emitLine(w, s, index)
	}
}

func emitLine(w io.Writer, s *session.Session, index int) {
	ts := "--"
	if !s.StartTime.IsZero() {
		ts = s.StartTime.Format("15:04:05")
	}
	ver := s.VersionString()
	cipher := s.CipherSuite()
	sni := s.SNI()
	if sni == "" {
		sni = "--"
	}
	status := s.Status.String()

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		index, ts, s.ClientAddr, s.ServerAddr, ver, cipher, sni, status)
}

type sessionJSON struct {
	Index       int       `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	Client      string    `json:"client"`
	Server      string    `json:"server"`
	TLSVersion  string    `json:"tls_version"`
	CipherSuite string    `json:"cipher_suite"`
	SNI         string    `json:"sni,omitempty"`
	Status      string    `json:"status"`
}

func emitNDJSON(w io.Writer, s *session.Session, index int) {
	obj := sessionJSON{
		Index:       index,
		Timestamp:   s.StartTime,
		Client:      s.ClientAddr,
		Server:      s.ServerAddr,
		TLSVersion:  s.VersionString(),
		CipherSuite: s.CipherSuite(),
		SNI:         s.SNI(),
		Status:      s.Status.String(),
	}
	data, _ := json.Marshal(obj)
	fmt.Fprintf(w, "%s\n", data)
}

func emitMultiYAML(w io.Writer, s *session.Session, index int) {
	obj := map[string]interface{}{
		"index":        index,
		"timestamp":    s.StartTime.Format(time.RFC3339),
		"client":       s.ClientAddr,
		"server":       s.ServerAddr,
		"tls_version":  s.VersionString(),
		"cipher_suite": s.CipherSuite(),
		"status":       strings.ToUpper(s.Status.String()),
	}
	if sni := s.SNI(); sni != "" {
		obj["sni"] = sni
	}
	fmt.Fprintln(w, "---")
	data, _ := yaml.Marshal(obj)
	w.Write(data)
}
