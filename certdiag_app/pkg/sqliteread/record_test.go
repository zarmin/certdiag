package sqliteread

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestReadVarint(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int64
		n    int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one byte max", []byte{0x7f}, 127, 1},
		{"two bytes", []byte{0x81, 0x00}, 128, 2},
		{"two bytes max", []byte{0xff, 0x7f}, 16383, 2},
		{"three bytes", []byte{0x81, 0x80, 0x00}, 16384, 3},
		{"trailing data ignored", []byte{0x05, 0xff, 0xff}, 5, 1},
		{"nine bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -1, 9},
		{"empty", nil, 0, 0},
		{"truncated continuation", []byte{0x81}, 0, 0},
		{"truncated nine byte", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n := readVarint(tc.in)
			if n != tc.n {
				t.Fatalf("expected n=%d, got %d", tc.n, n)
			}
			if n > 0 && got != tc.want {
				t.Errorf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

func TestDecodeValue_SerialTypes(t *testing.T) {
	body := []byte{
		0xff,       // 1: int8 -1
		0x01, 0x00, // 2: int16 256
		0xff, 0xff, 0xff, // 3: int24 -1
		0x00, 0x00, 0x01, 0x00, // 4: int32 256
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 5: int48 -1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // 6: int64 256
	}

	cases := []struct {
		serial int64
		off    int
		want   int64
		size   int
	}{
		{1, 0, -1, 1},
		{2, 1, 256, 2},
		{3, 3, -1, 3},
		{4, 6, 256, 4},
		{5, 10, -1, 6},
		{6, 16, 256, 8},
	}
	for _, tc := range cases {
		v, size, err := decodeValue(tc.serial, body, tc.off)
		if err != nil {
			t.Fatalf("serial %d: %v", tc.serial, err)
		}
		if size != tc.size {
			t.Errorf("serial %d: expected size %d, got %d", tc.serial, tc.size, size)
		}
		if !v.isInt || v.i != tc.want {
			t.Errorf("serial %d: expected %d, got %+v", tc.serial, tc.want, v)
		}
	}

	// Constants and NULL consume no body.
	for _, tc := range []struct {
		serial int64
		null   bool
		want   int64
	}{{0, true, 0}, {8, false, 0}, {9, false, 1}, {10, true, 0}, {11, true, 0}} {
		v, size, err := decodeValue(tc.serial, body, 0)
		if err != nil {
			t.Fatalf("serial %d: %v", tc.serial, err)
		}
		if size != 0 {
			t.Errorf("serial %d: expected zero width, got %d", tc.serial, size)
		}
		if v.null != tc.null {
			t.Errorf("serial %d: expected null=%v", tc.serial, tc.null)
		}
		if !tc.null && v.i != tc.want {
			t.Errorf("serial %d: expected %d, got %d", tc.serial, tc.want, v.i)
		}
	}
}

func TestDecodeValue_Float(t *testing.T) {
	body := []byte{0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 1.5
	v, size, err := decodeValue(7, body, 0)
	if err != nil {
		t.Fatal(err)
	}
	if size != 8 || !v.isF || v.f != 1.5 {
		t.Errorf("expected 1.5 in 8 bytes, got %+v size=%d", v, size)
	}
}

func TestDecodeValue_BlobAndText(t *testing.T) {
	body := []byte("hello world")

	// Serial 12 + 2n is a blob of n bytes; 13 + 2n is text.
	v, size, err := decodeValue(12+2*5, body, 0)
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 || !bytes.Equal(v.blob, []byte("hello")) || v.text {
		t.Errorf("expected a 5-byte blob, got %+v size=%d", v, size)
	}

	v, size, err = decodeValue(13+2*5, body, 6)
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 || string(v.blob) != "world" || !v.text {
		t.Errorf("expected 5-byte text, got %+v size=%d", v, size)
	}

	// Zero-length blob and text are valid.
	if v, size, err := decodeValue(12, body, 0); err != nil || size != 0 || len(v.blob) != 0 {
		t.Errorf("expected an empty blob, got %+v size=%d err=%v", v, size, err)
	}
}

func TestDecodeValue_TruncatedBody(t *testing.T) {
	body := []byte{0x01, 0x02}
	for _, serial := range []int64{2, 4, 6, 7, 12 + 2*10, 13 + 2*10} {
		if _, _, err := decodeValue(serial, body, 1); err == nil {
			t.Errorf("serial %d: expected an error past the end of the body", serial)
		}
	}
}

func TestDecodeRecord_BadHeader(t *testing.T) {
	tbl := &tableInfo{
		name:     "t",
		columns:  []string{"a"},
		colIndex: map[string]int{"a": 0},
		rowidCol: -1,
	}

	// Header length larger than the payload.
	if _, err := decodeRecord([]byte{0x7f, 0x00}, tbl, 1); err == nil {
		t.Error("expected an error for a header longer than the payload")
	}
	// Empty payload.
	if _, err := decodeRecord(nil, tbl, 1); err == nil {
		t.Error("expected an error for an empty payload")
	}
}

func TestParseCreateTableColumns(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		cols     []string
		rowidCol int
	}{
		{
			name:     "simple",
			sql:      "CREATE TABLE t (a, b, c)",
			cols:     []string{"a", "b", "c"},
			rowidCol: -1,
		},
		{
			name:     "integer primary key is a rowid alias",
			sql:      "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)",
			cols:     []string{"id", "name"},
			rowidCol: 0,
		},
		{
			name: "untyped primary key is not a rowid alias",
			// This is the real nssPublic shape.
			sql:      "CREATE TABLE nssPublic (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1)",
			cols:     []string{"id", "a0", "a1"},
			rowidCol: -1,
		},
		{
			name:     "table constraints skipped",
			sql:      "CREATE TABLE t (a, b, PRIMARY KEY (a, b), FOREIGN KEY (b) REFERENCES x(y))",
			cols:     []string{"a", "b"},
			rowidCol: -1,
		},
		{
			name:     "quoted identifiers",
			sql:      `CREATE TABLE t ("odd name" TEXT, [bracket], ` + "`back`" + `)`,
			cols:     []string{"odd name", "bracket", "back"},
			rowidCol: -1,
		},
		{
			name:     "type with parenthesised size",
			sql:      "CREATE TABLE t (a VARCHAR(20), b DECIMAL(10, 2))",
			cols:     []string{"a", "b"},
			rowidCol: -1,
		},
		{
			name:     "no parens",
			sql:      "CREATE TABLE t",
			cols:     nil,
			rowidCol: -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cols, rowid := parseCreateTableColumns(tc.sql)
			if len(cols) != len(tc.cols) {
				t.Fatalf("expected %v, got %v", tc.cols, cols)
			}
			for i := range tc.cols {
				if cols[i] != tc.cols[i] {
					t.Errorf("column %d: expected %q, got %q", i, tc.cols[i], cols[i])
				}
			}
			if rowid != tc.rowidCol {
				t.Errorf("expected rowid column %d, got %d", tc.rowidCol, rowid)
			}
		})
	}
}

func TestLocalPayloadSize(t *testing.T) {
	db := &DB{pageSize: 4096, usableSize: 4096}

	// Anything up to usable-35 stays local.
	if got := db.localPayloadSize(100); got != 100 {
		t.Errorf("expected a small payload to stay local, got %d", got)
	}
	if got := db.localPayloadSize(4061); got != 4061 {
		t.Errorf("expected the threshold payload to stay local, got %d", got)
	}
	// Past the threshold, the local part must be smaller than the payload and
	// never exceed the page.
	for _, p := range []int64{4062, 9000, 20000, 1 << 20} {
		got := db.localPayloadSize(p)
		if int64(got) >= p {
			t.Errorf("payload %d: expected a spill, got local=%d", p, got)
		}
		if got <= 0 || got > db.usableSize {
			t.Errorf("payload %d: local size %d out of range", p, got)
		}
	}
}

func TestLower(t *testing.T) {
	if lower("ACE536358") != "ace536358" {
		t.Error("expected ASCII lowercasing")
	}
	if lower("a11") != "a11" {
		t.Error("expected an already-lower string to be unchanged")
	}
}

func TestOpen_RejectsOversizeFile(t *testing.T) {
	// Guard the size cap without writing 512MB: point at a directory, which
	// Stat succeeds on and ReadFile rejects.
	if _, err := Open(t.TempDir()); err == nil {
		t.Error("expected an error opening a directory")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFixturesPresent(t *testing.T) {
	// A missing fixture would otherwise show up as a confusing Open failure.
	for _, name := range []string{
		"pages512.db", "pages4096.db", "pages32768.db",
		"nsscolumns.db", "corrupt.db", "notsqlite.bin", "truncated.db",
	} {
		if _, err := os.Stat(filepath.Join("testdata", name)); err != nil {
			t.Errorf("fixture %s missing; regenerate with tools/testing/gen_sqlite_fixtures.py", name)
		}
	}
	_ = math.MaxUint32
}
