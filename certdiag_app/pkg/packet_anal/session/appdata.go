package session

import (
	"fmt"
	"strings"
)

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

// SummarizeAppData returns a one-line preview of decrypted application data: an
// HTTP request or response start-line when recognized, otherwise a byte count.
// It deliberately does not parse full protocols - this is a diagnostic hint.
func SummarizeAppData(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	line := firstLine(data)
	if isHTTPStartLine(line) {
		return truncateLine(line, 80)
	}
	return fmt.Sprintf("%d bytes (non-HTTP or binary)", len(data))
}

func firstLine(data []byte) string {
	end := len(data)
	for i, b := range data {
		if b == '\r' || b == '\n' {
			end = i
			break
		}
		if i >= 200 {
			end = i
			break
		}
	}
	return string(data[:end])
}

func isHTTPStartLine(line string) bool {
	if strings.HasPrefix(line, "HTTP/") {
		return true
	}
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m) && strings.Contains(line, " HTTP/") {
			return true
		}
	}
	return false
}

func truncateLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
