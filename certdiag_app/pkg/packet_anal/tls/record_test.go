package tls

import (
	"encoding/binary"
	"testing"
)

// buildRecord constructs a raw TLS record: 1-byte type, 2-byte version, 2-byte length, payload.
func buildRecord(ct ContentType, major, minor uint8, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	rec[0] = byte(ct)
	rec[1] = major
	rec[2] = minor
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

// buildClientHelloRecord builds a minimal valid Handshake record containing a ClientHello.
// The ClientHello has a valid structure that ParseHandshakeMessages + ParseClientHello accept.
func buildClientHelloRecord() []byte {
	// Minimal ClientHello payload:
	//   version(2) + random(32) + session_id_len(1,0) + cipher_suites_len(2) + 1 suite(2) + comp_len(1) + comp(1)
	ch := make([]byte, 0, 42)
	ch = append(ch, 3, 3)          // client version TLS 1.2
	ch = append(ch, make([]byte, 32)...) // random
	ch = append(ch, 0)             // session ID length = 0
	ch = append(ch, 0, 2)         // cipher suites length = 2
	ch = append(ch, 0x13, 0x01)   // TLS_AES_128_GCM_SHA256
	ch = append(ch, 1, 0)         // compression methods: length=1, null

	// Wrap in handshake header: type(1) + length(3)
	hsPayload := make([]byte, 4+len(ch))
	hsPayload[0] = byte(HandshakeClientHello) // 1
	hsPayload[1] = 0
	hsPayload[2] = byte(len(ch) >> 8)
	hsPayload[3] = byte(len(ch))
	copy(hsPayload[4:], ch)

	return buildRecord(ContentHandshake, 3, 1, hsPayload)
}

func TestParseRecords_SingleRecord(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	data := buildRecord(ContentHandshake, 3, 3, payload)

	records, remainder, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if remainder != nil {
		t.Fatalf("expected no remainder, got %d bytes", len(remainder))
	}
	if records[0].Type != ContentHandshake {
		t.Errorf("type = %v, want Handshake", records[0].Type)
	}
	if records[0].Version != VersionTLS12 {
		t.Errorf("version = %v, want TLS 1.2", records[0].Version)
	}
	if len(records[0].Payload) != 3 {
		t.Errorf("payload length = %d, want 3", len(records[0].Payload))
	}
}

func TestParseRecords_TwoRecords(t *testing.T) {
	rec1 := buildRecord(ContentHandshake, 3, 3, []byte{0xAA})
	rec2 := buildRecord(ContentAlert, 3, 3, []byte{0xBB, 0xCC})
	data := append(rec1, rec2...)

	records, remainder, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if remainder != nil {
		t.Fatalf("expected no remainder, got %d bytes", len(remainder))
	}
	if records[0].Type != ContentHandshake {
		t.Errorf("record[0].Type = %v, want Handshake", records[0].Type)
	}
	if records[1].Type != ContentAlert {
		t.Errorf("record[1].Type = %v, want Alert", records[1].Type)
	}
	if len(records[1].Payload) != 2 {
		t.Errorf("record[1].Payload length = %d, want 2", len(records[1].Payload))
	}
}

func TestParseRecords_IncompletePayload(t *testing.T) {
	// Header says 10 bytes of payload but only provide 3
	data := buildRecord(ContentHandshake, 3, 3, []byte{0x01, 0x02, 0x03})
	// Overwrite the length field to claim a larger payload
	binary.BigEndian.PutUint16(data[3:5], 10)

	records, remainder, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
	if len(remainder) != len(data) {
		t.Errorf("expected remainder of %d bytes, got %d", len(data), len(remainder))
	}
}

func TestParseRecords_TruncatedHeader(t *testing.T) {
	data := []byte{0x16, 0x03, 0x03} // only 3 bytes, need 5

	records, remainder, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
	if len(remainder) != 3 {
		t.Errorf("expected 3 bytes remainder, got %d", len(remainder))
	}
}

func TestParseRecords_EmptyInput(t *testing.T) {
	records, remainder, err := ParseRecords(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
	if remainder != nil {
		t.Fatalf("expected nil remainder, got %d bytes", len(remainder))
	}
}

func TestParseRecords_InvalidContentType(t *testing.T) {
	// Content type 0x99 is not valid -- parser should return remainder
	data := []byte{0x99, 0x03, 0x03, 0x00, 0x01, 0xFF}

	records, remainder, err := ParseRecords(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
	if len(remainder) != len(data) {
		t.Errorf("expected all bytes as remainder, got %d", len(remainder))
	}
}

func TestParseRecords_InvalidVersion(t *testing.T) {
	// Major version 4 is not valid TLS
	data := []byte{0x16, 0x04, 0x00, 0x00, 0x01, 0xFF}

	_, _, err := ParseRecords(data)
	if err == nil {
		t.Fatal("expected error for invalid version, got nil")
	}
}

func TestIsTLSData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "valid handshake record header",
			data: buildRecord(ContentHandshake, 3, 3, []byte{0x01}),
			want: true,
		},
		{
			name: "valid alert record header",
			data: buildRecord(ContentAlert, 3, 1, []byte{0x02, 0x28}),
			want: true,
		},
		{
			name: "random bytes",
			data: []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB},
			want: false,
		},
		{
			name: "too short",
			data: []byte{0x16, 0x03},
			want: false,
		},
		{
			name: "empty",
			data: nil,
			want: false,
		},
		{
			name: "invalid content type but valid version",
			data: []byte{0x00, 0x03, 0x03, 0x00, 0x01},
			want: false,
		},
		{
			name: "valid content type but wrong major version",
			data: []byte{0x16, 0x04, 0x00, 0x00, 0x01},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTLSData(tt.data); got != tt.want {
				t.Errorf("IsTLSData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindTLSStart(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantOffset int
		wantFound  bool
	}{
		{
			name:       "TLS at offset 0",
			data:       buildClientHelloRecord(),
			wantOffset: 0,
			wantFound:  true,
		},
		{
			name: "TLS after SMTP greeting",
			data: func() []byte {
				greeting := []byte("220 mail.example.com ESMTP\r\n")
				return append(greeting, buildClientHelloRecord()...)
			}(),
			wantOffset: 28,
			wantFound:  true,
		},
		{
			name:       "no TLS data",
			data:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantOffset: 0,
			wantFound:  false,
		},
		{
			name:       "empty input",
			data:       nil,
			wantOffset: 0,
			wantFound:  false,
		},
		{
			name:       "too short for TLS",
			data:       []byte{0x16, 0x03},
			wantOffset: 0,
			wantFound:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, found := FindTLSStart(tt.data)
			if found != tt.wantFound {
				t.Errorf("FindTLSStart() found = %v, want %v", found, tt.wantFound)
			}
			if found && offset != tt.wantOffset {
				t.Errorf("FindTLSStart() offset = %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}

func TestRecordParser_StatefulParsing(t *testing.T) {
	record := buildRecord(ContentHandshake, 3, 3, []byte{0x01, 0x02, 0x03, 0x04, 0x05})
	// Split the record in the middle of the payload
	split := 4 // split inside the header+payload boundary

	var parser RecordParser

	// Feed first part -- should get no complete records
	records, err := parser.Feed(record[:split])
	if err != nil {
		t.Fatalf("unexpected error on first feed: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records after first feed, got %d", len(records))
	}
	if parser.Buffered() == 0 {
		t.Error("expected buffered bytes after partial feed")
	}

	// Feed the rest -- should get 1 complete record
	records, err = parser.Feed(record[split:])
	if err != nil {
		t.Fatalf("unexpected error on second feed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record after second feed, got %d", len(records))
	}
	if records[0].Type != ContentHandshake {
		t.Errorf("type = %v, want Handshake", records[0].Type)
	}
	if len(records[0].Payload) != 5 {
		t.Errorf("payload length = %d, want 5", len(records[0].Payload))
	}
	if parser.Buffered() != 0 {
		t.Errorf("expected 0 buffered bytes after complete record, got %d", parser.Buffered())
	}
}

func TestRecordParser_MultipleRecordsAcrossFeeds(t *testing.T) {
	rec1 := buildRecord(ContentHandshake, 3, 3, []byte{0xAA})
	rec2 := buildRecord(ContentAlert, 3, 3, []byte{0xBB})

	combined := append(rec1, rec2...)
	// Feed everything at once
	var parser RecordParser
	records, err := parser.Feed(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if parser.Buffered() != 0 {
		t.Errorf("expected 0 buffered bytes, got %d", parser.Buffered())
	}
}

func TestRecordParser_ByteByByte(t *testing.T) {
	payload := []byte{0xDE, 0xAD}
	record := buildRecord(ContentApplicationData, 3, 3, payload)

	var parser RecordParser
	var allRecords []Record

	for i, b := range record {
		records, err := parser.Feed([]byte{b})
		if err != nil {
			t.Fatalf("unexpected error at byte %d: %v", i, err)
		}
		allRecords = append(allRecords, records...)
	}

	if len(allRecords) != 1 {
		t.Fatalf("expected 1 record after feeding byte-by-byte, got %d", len(allRecords))
	}
	if allRecords[0].Type != ContentApplicationData {
		t.Errorf("type = %v, want ApplicationData", allRecords[0].Type)
	}
	if len(allRecords[0].Payload) != 2 {
		t.Errorf("payload length = %d, want 2", len(allRecords[0].Payload))
	}
}
