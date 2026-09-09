package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrTruncated   = errors.New("truncated TLS record")
	ErrNotTLS      = errors.New("not a TLS record")
	ErrOversized   = errors.New("TLS record too large")
)

// ParseRecords extracts all complete TLS records from data.
// Returns the parsed records and any remaining bytes (incomplete record at the end).
// A single TCP segment can contain multiple TLS records, and a single TLS record
// can span multiple TCP segments.
func ParseRecords(data []byte) ([]Record, []byte, error) {
	var records []Record
	offset := 0

	for offset < len(data) {
		remaining := data[offset:]

		// Need at least the 5-byte header
		if len(remaining) < recordHeaderSize {
			return records, remaining, nil
		}

		contentType := ContentType(remaining[0])
		if !isValidContentType(contentType) {
			// Not a TLS record -- could be garbage after encryption starts
			return records, remaining, nil
		}

		version := Version{Major: remaining[1], Minor: remaining[2]}
		if version.Major != 3 {
			return records, remaining, fmt.Errorf("%w: version %d.%d", ErrNotTLS, version.Major, version.Minor)
		}

		payloadLen := int(binary.BigEndian.Uint16(remaining[3:5]))
		if payloadLen > maxRecordPayload {
			return records, remaining, fmt.Errorf("%w: %d bytes", ErrOversized, payloadLen)
		}

		totalLen := recordHeaderSize + payloadLen
		if len(remaining) < totalLen {
			// Incomplete record, need more data
			return records, remaining, nil
		}

		records = append(records, Record{
			Type:    contentType,
			Version: version,
			Payload: remaining[recordHeaderSize:totalLen],
		})
		offset += totalLen
	}

	return records, nil, nil
}

// RecordParser is a stateful parser that handles TLS records arriving in chunks
// (e.g. from TCP reassembly where record boundaries don't align with segment boundaries).
type RecordParser struct {
	buf []byte
}

// Feed adds data to the parser buffer and returns all complete records found.
func (p *RecordParser) Feed(data []byte) ([]Record, error) {
	p.buf = append(p.buf, data...)

	records, remaining, err := ParseRecords(p.buf)
	if remaining != nil {
		// Keep leftover bytes for next Feed() call
		p.buf = make([]byte, len(remaining))
		copy(p.buf, remaining)
	} else {
		p.buf = p.buf[:0]
	}

	return records, err
}

// Buffered returns the number of bytes buffered (incomplete record).
func (p *RecordParser) Buffered() int {
	return len(p.buf)
}

func isValidContentType(ct ContentType) bool {
	return ct == ContentChangeCipherSpec ||
		ct == ContentAlert ||
		ct == ContentHandshake ||
		ct == ContentApplicationData
}

// IsTLSData returns true if data starts with what looks like a TLS record header.
// Useful for detecting whether a TCP stream carries TLS traffic.
func IsTLSData(data []byte) bool {
	if len(data) < recordHeaderSize {
		return false
	}
	if !isValidContentType(ContentType(data[0])) {
		return false
	}
	// TLS version major must be 3
	if data[1] != 3 {
		return false
	}
	return true
}

func FindTLSStart(data []byte) (int, bool) {
	for i := 0; i <= len(data)-recordHeaderSize; i++ {
		if data[i] != byte(ContentHandshake) {
			continue
		}
		if data[i+1] != 3 || data[i+2] > 4 {
			continue
		}

		payloadLen := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if payloadLen == 0 || payloadLen > maxRecordPayload {
			continue
		}

		totalLen := recordHeaderSize + payloadLen
		if len(data)-i < totalLen {
			continue
		}

		records, _, err := ParseRecords(data[i:])
		if err != nil || len(records) == 0 {
			continue
		}

		if records[0].Type != ContentHandshake {
			continue
		}
		msgs, _ := ParseHandshakeMessages(records[0].Payload)
		if len(msgs) == 0 {
			continue
		}
		if msgs[0].Type == HandshakeClientHello || msgs[0].Type == HandshakeServerHello {
			return i, true
		}
	}
	return 0, false
}
