package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

func PrintSummaryTable(w io.Writer, sessions []*session.Session) {
	if len(sessions) == 0 {
		fmt.Fprintln(w, "No TLS sessions found.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tTimestamp\tSource\tDest\tVer\tCipher Suite\tSNI\tStatus")

	for i, s := range sessions {
		ts := "--"
		if !s.StartTime.IsZero() {
			ts = s.StartTime.Format("2006-01-02 15:04:05")
		}

		ver := s.VersionString()
		cipher := s.CipherSuite()
		sni := s.SNI()
		if sni == "" {
			sni = "--"
		}

		status := statusString(s)

		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1, ts, s.ClientAddr, s.ServerAddr, ver, cipher, sni, status)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nTotal: %d TLS sessions\n", len(sessions))

	// Quick stats
	ok, failed, aborted := 0, 0, 0
	for _, s := range sessions {
		switch s.Status {
		case session.StatusOK:
			ok++
		case session.StatusFailed:
			failed++
		case session.StatusAborted:
			aborted++
		}
	}
	if failed > 0 || aborted > 0 {
		fmt.Fprintf(w, "  OK: %d  Failed: %d  Aborted: %d\n", ok, failed, aborted)
	}
}

func statusString(s *session.Session) string {
	var base string
	switch s.Status {
	case session.StatusOK:
		base = "OK"
	case session.StatusFailed:
		base = "FAILED"
		if s.Diagnostic != "" {
			base = "FAILED: " + truncate(s.Diagnostic, 60)
		}
	case session.StatusAborted:
		base = "ABORTED"
		if s.Diagnostic != "" {
			base = "ABORTED: " + truncate(s.Diagnostic, 60)
		}
	default:
		base = s.Status.String()
	}

	offset := s.ClientTLSOffset
	if offset == 0 {
		offset = s.ServerTLSOffset
	}
	if offset > 0 {
		base += fmt.Sprintf(" [STARTTLS @%d]", offset)
	}
	return base
}

func truncate(s string, maxLen int) string {
	// Take first line only for table display
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
