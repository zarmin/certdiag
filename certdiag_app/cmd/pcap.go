package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/pcapint"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	pktoutput "github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/pcap"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

var (
	pcapAggressive bool
	pcapFilter     string
	pcapDetail     bool
	pcapTargetDir  string
	pcapKeyLog     string
	pcapLiveIface  string
	pcapLiveCount  int
	pcapLiveDur    time.Duration
)

var pcapCmd = &cobra.Command{
	Use:   "pcap [command] [flags] <file.pcap>",
	Short: "Analyze TLS sessions in pcap captures",
	Long: `Analyze TLS handshakes found in pcap/pcapng capture files.

If no command is given and a file is provided, defaults to sessions.
Use "-" to read a capture stream from stdin, e.g.:
  tcpdump -i eth0 -w - | certdiag pcap -`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		runPcapSessions(args[0])
		return nil
	},
}

var pcapSessionsCmd = &cobra.Command{
	Use:   "sessions <file.pcap>",
	Short: "Show TLS session summary",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runPcapSessions(args[0])
	},
}

var pcapCheckCmd = &cobra.Command{
	Use:   "check <file.pcap>",
	Short: "Extract certificates and run checks",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runPcapCheck(args[0])
	},
}

var pcapExtractCmd = &cobra.Command{
	Use:   "extract <file.pcap>",
	Short: "Save certificates from pcap to files",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runPcapExtract(args[0])
	},
}

var pcapLiveCmd = &cobra.Command{
	Use:   "live --iface <interface>",
	Short: "Capture and analyze TLS live from an interface (Linux, no cgo)",
	Long: `Capture packets live from a network interface and analyze TLS sessions.

Uses AF_PACKET raw sockets (Linux only, pure Go, no libpcap). Requires
CAP_NET_RAW or root. On other platforms, pipe a capture tool through stdin:
  tcpdump -i <iface> -w - | certdiag pcap -

Stops on Ctrl-C, or after --count packets / --duration.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPcapLive()
	},
}

func init() {
	pcapCmd.PersistentFlags().BoolVarP(&pcapAggressive, "aggressive", "a", false, "Scan for TLS within streams (STARTTLS)")
	pcapCmd.PersistentFlags().StringVarP(&pcapFilter, "filter", "f", "", "Search string for session filtering")
	pcapCmd.PersistentFlags().BoolVarP(&pcapDetail, "detail", "d", false, "Show detailed session info")
	pcapCmd.PersistentFlags().StringVar(&pcapKeyLog, "keylog", "", "SSLKEYLOGFILE (NSS key log) to decrypt TLS 1.3 handshakes (env: SSLKEYLOGFILE)")
	pcapExtractCmd.Flags().StringVar(&pcapTargetDir, "target-dir", "", "Directory for extracted certs (default: <file>_extracted_certs/)")
	pcapLiveCmd.Flags().StringVar(&pcapLiveIface, "iface", "", "Network interface to capture on (required)")
	pcapLiveCmd.Flags().IntVar(&pcapLiveCount, "count", 0, "Stop after N packets (0 = until Ctrl-C)")
	pcapLiveCmd.Flags().DurationVar(&pcapLiveDur, "duration", 0, "Stop after this duration (e.g. 10s; 0 = until Ctrl-C)")

	pcapCmd.AddCommand(pcapSessionsCmd)
	pcapCmd.AddCommand(pcapCheckCmd)
	pcapCmd.AddCommand(pcapExtractCmd)
	pcapCmd.AddCommand(pcapLiveCmd)
	rootCmd.AddCommand(pcapCmd)
}

// stopOnSignal closes stop on the first received signal. done lets the watcher
// exit when the capture ends without a signal (--count/--duration), so it does
// not outlive the command.
func stopOnSignal(sig <-chan os.Signal, done <-chan struct{}, stop chan<- struct{}) {
	select {
	case <-sig:
		close(stop)
	case <-done:
	}
}

func runPcapLive() {
	if pcapLiveIface == "" {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: pcap live requires --iface"))
		os.Exit(1)
	}

	source, linkType, closeFn, err := pcap.OpenLive(pcapLiveIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
	closeCapture := pcapint.CloseOnce(closeFn)
	defer closeCapture()

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	watchDone := make(chan struct{})
	defer close(watchDone)
	go stopOnSignal(sig, watchDone, stop)

	fmt.Fprintf(os.Stderr, "capturing on %s (Ctrl-C to stop)...\n", pcapLiveIface)
	result, err := pcapint.AnalyzeLive(pcapint.LiveOptions{
		Source:     source,
		LinkType:   linkType,
		Aggressive: pcapAggressive,
		KeyLog:     resolveKeyLog(),
		MaxPackets: pcapLiveCount,
		Duration:   pcapLiveDur,
		Stop:       stop,
		Close:      closeCapture,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if pcapFilter != "" {
		var filtered []*session.Session
		for _, s := range result.Sessions {
			if s.MatchesSearch(pcapFilter) {
				filtered = append(filtered, s)
			}
		}
		result.Sessions = filtered
	}
	printSessions(result)
}

func printSessions(result *pcapint.AnalyzeResult) {
	printPcapSummary(result)
	pktoutput.PrintSummaryTable(os.Stdout, result.Sessions)
	if pcapDetail && len(result.Sessions) > 0 {
		fmt.Fprintln(os.Stdout)
		for i, s := range result.Sessions {
			pktoutput.PrintDetail(os.Stdout, s, i+1)
			if i < len(result.Sessions)-1 {
				fmt.Fprintln(os.Stdout, "---")
			}
		}
	}
}

func resolveKeyLog() *tls.KeyLog {
	path := pcapKeyLog
	if path == "" {
		path = os.Getenv("SSLKEYLOGFILE")
	}
	if path == "" {
		return nil
	}
	kl, err := tls.ParseKeyLogFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read keylog %q: %v\n", path, err)
		return nil
	}
	return kl
}

func analyzePcap(path string) *pcapint.AnalyzeResult {
	result, err := pcapint.Analyze(pcapint.AnalyzeOptions{
		Path:       path,
		Aggressive: pcapAggressive,
		KeyLog:     resolveKeyLog(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if pcapFilter != "" {
		var filtered []*session.Session
		for _, s := range result.Sessions {
			if s.MatchesSearch(pcapFilter) {
				filtered = append(filtered, s)
			}
		}
		result.Sessions = filtered
	}
	return result
}

func printPcapSummary(result *pcapint.AnalyzeResult) {
	if result.Total != len(result.Sessions) {
		fmt.Fprintf(os.Stderr, "Packets: %d, TCP connections: %d, TLS sessions: %d (%d matched filter)\n\n",
			result.Packets, result.Connections, result.Total, len(result.Sessions))
	} else {
		fmt.Fprintf(os.Stderr, "Packets: %d, TCP connections: %d, TLS sessions: %d\n\n",
			result.Packets, result.Connections, result.Total)
	}
}

func runPcapSessions(path string) {
	printSessions(analyzePcap(path))
}

func runPcapCheck(path string) {
	result := analyzePcap(path)
	printPcapSummary(result)

	store := pcapint.ToCertStore(result.Sessions)
	if len(store.Containers) == 0 {
		fmt.Fprintln(os.Stderr, "No certificates found in capture (TLS 1.3 encrypts certificates).")
		return
	}

	// The same analysis the file scan runs, with the same config: disabled
	// checks and expiry thresholds apply to a capture as to a directory.
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	checkOpts := certlib.CheckOptions{}
	if cfg != nil {
		checkOpts.DisabledChecks = cfg.Defaults.Check.DisabledChecks
		checkOpts.ExpiryWarnDays = resolveExpiryThreshold(0, cfg.Defaults.Check.ExpiryWarnDays)
		checkOpts.ExpiryCriticalDays = resolveExpiryThreshold(0, cfg.Defaults.Check.ExpiryCriticalDays)
	}
	analysis := certops.Analyze(store, certops.ScanOptions{Check: true, CheckOptions: checkOpts})
	fmt.Print(output.FormatCheckHuman(analysis.CheckResult, 0))
}

func runPcapExtract(path string) {
	result := analyzePcap(path)

	targetDir := pcapTargetDir
	if targetDir == "" {
		targetDir = path + "_extracted_certs"
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
		os.Exit(1)
	}

	usedNames := make(map[string]int)
	written := 0

	for _, s := range result.Sessions {
		if s.Certificates == nil || len(s.Certificates.Certificates) == 0 {
			continue
		}

		name := chainFileName(s)
		usedNames[name]++
		if usedNames[name] > 1 {
			name = fmt.Sprintf("%s_%d", name, usedNames[name])
		}

		outPath := filepath.Join(targetDir, name+"_chain.pem")
		if err := writeChainPEM(outPath, s.Certificates.Certificates); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
			continue
		}
		fmt.Fprintf(os.Stdout, "  %s\n", outPath)
		written++
	}

	if written == 0 {
		fmt.Fprintln(os.Stderr, "No certificates found in capture (TLS 1.3 encrypts certificates).")
	} else {
		fmt.Fprintf(os.Stderr, "Extracted %d certificate chain(s) to %s/\n", written, targetDir)
	}
}

func chainFileName(s *session.Session) string {
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

func writeChainPEM(path string, certs [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, der := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return nil
}
