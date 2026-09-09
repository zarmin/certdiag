package sqliteread

import (
	"bytes"
	"path/filepath"
	"testing"
)

// pattern mirrors gen_sqlite_fixtures.py: byte i is (i * step) % 251. The
// fixtures hold deterministic content so the tests recompute the expected bytes
// rather than carrying a digest file that can drift.
func pattern(n, step int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i * step) % 251)
	}
	return out
}

func fixture(name string) string { return filepath.Join("testdata", name) }

func openFixture(t *testing.T, name string) *DB {
	t.Helper()
	db, err := Open(fixture(name))
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpen_RejectsNonSQLite(t *testing.T) {
	if _, err := Open(fixture("notsqlite.bin")); err == nil {
		t.Error("expected an error for a file with the wrong magic")
	}
	if _, err := Open(fixture("truncated.db")); err == nil {
		t.Error("expected an error for a file shorter than the header")
	}
	if _, err := Open(fixture("does-not-exist.db")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestOpen_PageSizes(t *testing.T) {
	cases := []struct {
		file string
		want int
	}{
		{"pages512.db", 512},
		{"pages4096.db", 4096},
		{"pages32768.db", 32768},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			db := openFixture(t, tc.file)
			if db.PageSize() != tc.want {
				t.Errorf("expected page size %d, got %d", tc.want, db.PageSize())
			}
		})
	}
}

func TestOpenBytes_PageSize65536Encoding(t *testing.T) {
	// A page size of 65536 is stored as the literal 1, which must not be read
	// as an invalid 1-byte page.
	data := make([]byte, 65536*2)
	copy(data, headerMagic)
	data[16], data[17] = 0x00, 0x01 // page size marker for 65536
	data[20] = 0                    // no reserved space
	data[28], data[29], data[30], data[31] = 0, 0, 0, 2
	// Page 1 needs a plausible leaf header so schema loading does not error.
	data[headerLen] = pageLeafTable

	db, err := OpenBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if db.PageSize() != 65536 {
		t.Errorf("expected 65536, got %d", db.PageSize())
	}
}

func TestTablesAndColumns(t *testing.T) {
	db := openFixture(t, "pages4096.db")

	tables := db.Tables()
	if len(tables) != 1 || tables[0] != "t" {
		t.Fatalf("expected exactly table t, got %v", tables)
	}

	want := []string{"id", "name", "blob1", "num", "flag"}
	got := db.Columns("t")
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("column %d: expected %q, got %q", i, want[i], got[i])
		}
	}

	if db.Columns("nope") != nil {
		t.Error("expected nil columns for an unknown table")
	}
}

func TestScan_UnknownTable(t *testing.T) {
	db := openFixture(t, "pages4096.db")
	err := db.Scan("nope", func(Row) error { return nil })
	if err == nil {
		t.Error("expected an error scanning an unknown table")
	}
}

// TestScan_OverflowChain is the load-bearing case. With a 512-byte page a
// 20000-byte blob spans a long overflow chain, and reassembly must be
// byte-exact -- a one-byte slip here would corrupt every certificate read out
// of a real cert9.db.
func TestScan_OverflowChain(t *testing.T) {
	cases := []struct {
		file string
		big  int
	}{
		{"pages512.db", 20000},
		{"pages4096.db", 9000},
		{"pages32768.db", 40000},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			db := openFixture(t, tc.file)

			found := map[string][]byte{}
			err := db.Scan("t", func(r Row) error {
				switch name := r.Text("name"); name {
				case "small", "big", "mid", "floats":
					found[name] = append([]byte(nil), r.Blob("blob1")...)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			expect := map[string][]byte{
				"small":  pattern(5, 1),
				"big":    pattern(tc.big, 3),
				"mid":    pattern(3000, 7),
				"floats": pattern(9, 11),
			}
			for name, want := range expect {
				got, ok := found[name]
				if !ok {
					t.Fatalf("row %q missing", name)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("row %q: got %d bytes, want %d (first mismatch at %d)",
						name, len(got), len(want), firstDiff(got, want))
				}
			}
		})
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestScan_MultiLevelBTree exercises interior page traversal: 405 rows on
// 512-byte pages cannot fit in a single leaf.
func TestScan_MultiLevelBTree(t *testing.T) {
	db := openFixture(t, "pages512.db")

	rows := 0
	total := 0
	seen := map[string]bool{}
	err := db.Scan("t", func(r Row) error {
		rows++
		total += len(r.Blob("blob1"))
		name := r.Text("name")
		if seen[name] {
			t.Errorf("row %q returned twice", name)
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rows != 405 {
		t.Errorf("expected 405 rows, got %d", rows)
	}
	for i := 0; i < 400; i++ {
		if !seen[rowName(i)] {
			t.Fatalf("row %s missing; interior page traversal dropped rows", rowName(i))
		}
	}
}

func rowName(i int) string {
	return "r" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestScan_RowidAlias covers the INTEGER PRIMARY KEY case: the value is stored
// as NULL in the record and must be read back from the rowid.
func TestScan_RowidAlias(t *testing.T) {
	db := openFixture(t, "pages4096.db")

	byName := map[string]int64{}
	err := db.Scan("t", func(r Row) error {
		id, ok := r.Int("id")
		if !ok {
			t.Errorf("row %q has no id", r.Text("name"))
			return nil
		}
		if id == 0 {
			t.Errorf("row %q got id 0; the rowid alias was not resolved", r.Text("name"))
		}
		byName[r.Text("name")] = id
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if byName["small"] != 1 || byName["big"] != 2 || byName["mid"] != 3 {
		t.Errorf("expected ids 1,2,3 for small,big,mid; got %d,%d,%d",
			byName["small"], byName["big"], byName["mid"])
	}
}

// TestScan_NonIntegerPrimaryKey guards the shape a real cert9.db has: `id
// PRIMARY KEY` on an untyped column is NOT a rowid alias, and the stored value
// must be returned instead.
func TestScan_NonIntegerPrimaryKey(t *testing.T) {
	db := openFixture(t, "nsscolumns.db")

	ids := map[string]bool{}
	err := db.Scan("nssPublic", func(r Row) error {
		ids[r.Text("id")] = true
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !ids["1"] || !ids["2"] {
		t.Errorf("expected the stored text ids, got %v", ids)
	}
}

// TestScan_NSSColumnNames pins the access pattern the NSS reader depends on:
// hex-suffixed column names, a 4-byte big-endian class and a DER-sized blob.
func TestScan_NSSColumnNames(t *testing.T) {
	db := openFixture(t, "nsscolumns.db")

	classes := map[uint32]int{}
	err := db.Scan("nssPublic", func(r Row) error {
		class, ok := r.Uint32BE("a0")
		if !ok {
			t.Error("expected a class on every row")
			return nil
		}
		classes[class]++
		if class == 1 {
			if got := len(r.Blob("a11")); got != 1400 {
				t.Errorf("expected a 1400-byte value, got %d", got)
			}
			if r.Text("a3") != "label-one" {
				t.Errorf("expected the label, got %q", r.Text("a3"))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if classes[1] != 1 || classes[11] != 1 {
		t.Errorf("expected one row of each class, got %v", classes)
	}
}

func TestRow_Accessors(t *testing.T) {
	db := openFixture(t, "pages4096.db")

	err := db.Scan("t", func(r Row) error {
		switch r.Text("name") {
		case "nulls":
			if r.Blob("blob1") != nil {
				t.Error("expected nil for a NULL blob")
			}
			if r.Text("blob1") != "" {
				t.Error("expected empty string for a NULL column")
			}
			if _, ok := r.Int("num"); ok {
				t.Error("expected ok=false for a NULL integer")
			}
			if _, ok := r.Uint32BE("num"); ok {
				t.Error("expected ok=false for a NULL Uint32BE")
			}
		case "small":
			if v, ok := r.Int("num"); !ok || v != 42 {
				t.Errorf("expected 42, got %d (ok=%v)", v, ok)
			}
			if v, ok := r.Int("flag"); !ok || v != 1 {
				t.Errorf("expected flag 1, got %d (ok=%v)", v, ok)
			}
		case "big":
			// Negative values exercise the signed narrow-integer serial types.
			if v, ok := r.Int("num"); !ok || v != -7 {
				t.Errorf("expected -7, got %d (ok=%v)", v, ok)
			}
		case "mid":
			if v, ok := r.Int("num"); !ok || v != 1<<40 {
				t.Errorf("expected 2^40, got %d (ok=%v)", v, ok)
			}
		case "floats":
			if v, ok := r.Int("num"); !ok || v != 1 {
				t.Errorf("expected a float to truncate to 1, got %d (ok=%v)", v, ok)
			}
		}

		if _, ok := r.Int("nosuchcolumn"); ok {
			t.Error("expected ok=false for an unknown column")
		}
		if r.Blob("nosuchcolumn") != nil {
			t.Error("expected nil for an unknown column")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
}

func TestRow_Uint32BE(t *testing.T) {
	db := openFixture(t, "nsscolumns.db")

	err := db.Scan("nssPublic", func(r Row) error {
		// A 4-byte blob decodes; a longer blob does not.
		if _, ok := r.Uint32BE("a0"); !ok {
			t.Error("expected a 4-byte blob to decode")
		}
		if _, ok := r.Uint32BE("a11"); ok {
			t.Error("expected a wrong-length blob to be rejected")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
}

// TestScan_CorruptCellIsSkipped: one bad cell pointer must not cost the rest of
// the table. A partially readable profile is still a useful diagnostic.
func TestScan_CorruptCellIsSkipped(t *testing.T) {
	db, err := Open(fixture("corrupt.db"))
	if err != nil {
		t.Fatalf("a database with one bad cell must still open: %v", err)
	}
	defer db.Close()

	rows := 0
	if err := db.Scan("t", func(Row) error { rows++; return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rows == 0 {
		t.Error("expected the remaining rows to survive one corrupt cell")
	}
	if rows >= 45 {
		t.Errorf("expected fewer than the full 45 rows, got %d", rows)
	}
}

func TestScan_StopsOnCallbackError(t *testing.T) {
	db := openFixture(t, "pages512.db")

	seen := 0
	sentinel := errStop{}
	err := db.Scan("t", func(Row) error {
		seen++
		if seen == 3 {
			return sentinel
		}
		return nil
	})
	if err != sentinel {
		t.Fatalf("expected the callback error to propagate, got %v", err)
	}
	if seen != 3 {
		t.Errorf("expected the scan to stop at 3 rows, saw %d", seen)
	}
}

type errStop struct{}

func (errStop) Error() string { return "stop" }

func TestSidecars(t *testing.T) {
	dir := t.TempDir()
	src, err := filepath.Abs(fixture("pages4096.db"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "copy.db")
	copyFile(t, src, dst)

	db, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Sidecars()) != 0 {
		t.Errorf("expected no sidecars, got %v", db.Sidecars())
	}
	db.Close()

	writeFile(t, dst+"-wal", []byte("not empty"))
	writeFile(t, dst+"-journal", nil) // empty, must be ignored

	db, err = Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got := db.Sidecars()
	if len(got) != 1 {
		t.Fatalf("expected exactly the non-empty -wal, got %v", got)
	}
	if filepath.Base(got[0]) != "copy.db-wal" {
		t.Errorf("expected the -wal sidecar, got %v", got)
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	db := openFixture(t, "pages4096.db")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("a second Close must not error: %v", err)
	}
	if len(db.Tables()) != 0 {
		t.Error("expected no tables after Close")
	}
}
