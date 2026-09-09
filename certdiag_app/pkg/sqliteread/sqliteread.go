// Package sqliteread is a minimal read-only SQLite 3 reader.
//
// It implements exactly what is needed to full-scan a table: the file header,
// the sqlite_master schema, table b-tree traversal and the record format
// including overflow page chains. There is no query engine, no index use, no
// WAL replay and no write path.
package sqliteread

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const (
	headerMagic  = "SQLite format 3\x00"
	headerLen    = 100
	maxFileSize  = 512 << 20
	maxPageCount = 1 << 22
)

// DB is an opened SQLite database file, held in memory.
type DB struct {
	data       []byte
	pageSize   int
	usableSize int
	pageCount  int
	tables     map[string]*tableInfo
	order      []string
	sidecars   []string
}

type tableInfo struct {
	name     string
	rootPage int
	columns  []string
	colIndex map[string]int
	rowidCol int // index of an INTEGER PRIMARY KEY column, -1 when there is none
}

// Row exposes the columns of one decoded record by name.
type Row interface {
	// Blob returns the raw bytes of a column, or nil when the column is
	// absent or NULL.
	Blob(col string) []byte
	// Uint32BE decodes a column stored as a 4-byte big-endian value, the
	// form NSS uses for PKCS#11 CK_ULONG attributes.
	Uint32BE(col string) (uint32, bool)
	// Text returns a column as a string, empty when absent or NULL.
	Text(col string) string
	// Int returns an integer column.
	Int(col string) (int64, bool)
}

// Open reads a SQLite database file. The whole file is loaded into memory; the
// databases this package targets are small.
func Open(path string) (*DB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("sqliteread: %s is %d bytes, above the %d byte limit", path, fi.Size(), maxFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	db, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("sqliteread: %s: %w", path, err)
	}
	db.sidecars = detectSidecars(path)
	return db, nil
}

// OpenBytes parses an in-memory database image.
func OpenBytes(data []byte) (*DB, error) {
	return parse(data)
}

func parse(data []byte) (*DB, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("file too short (%d bytes)", len(data))
	}
	if string(data[:16]) != headerMagic {
		return nil, fmt.Errorf("not a SQLite 3 database")
	}

	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("invalid page size %d", pageSize)
	}

	reserved := int(data[20])
	usable := pageSize - reserved
	if usable < 480 {
		return nil, fmt.Errorf("usable page size %d too small", usable)
	}

	pageCount := int(binary.BigEndian.Uint32(data[28:32]))
	if pageCount <= 0 || pageCount > maxPageCount {
		pageCount = len(data) / pageSize
	}
	if avail := len(data) / pageSize; pageCount > avail {
		pageCount = avail
	}
	if pageCount < 1 {
		return nil, fmt.Errorf("database has no pages")
	}

	db := &DB{
		data:       data,
		pageSize:   pageSize,
		usableSize: usable,
		pageCount:  pageCount,
		tables:     make(map[string]*tableInfo),
	}

	if err := db.loadSchema(); err != nil {
		return nil, err
	}
	return db, nil
}

// Close releases the in-memory image.
func (d *DB) Close() error {
	d.data = nil
	d.tables = nil
	d.order = nil
	return nil
}

// PageSize reports the database page size.
func (d *DB) PageSize() int { return d.pageSize }

// Tables lists the table names found in sqlite_master, in file order.
func (d *DB) Tables() []string {
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// Columns returns the declared column names of a table.
func (d *DB) Columns(table string) []string {
	t := d.tables[strings.ToLower(table)]
	if t == nil {
		return nil
	}
	out := make([]string, len(t.columns))
	copy(out, t.columns)
	return out
}

// Sidecars lists non-empty "-wal" / "-journal" files found next to the
// database. Their presence means committed content may live outside the main
// file, which this reader does not replay.
func (d *DB) Sidecars() []string {
	out := make([]string, len(d.sidecars))
	copy(out, d.sidecars)
	return out
}

// Scan walks every row of a table and calls fn for each. Returning an error
// from fn stops the scan and returns that error.
func (d *DB) Scan(table string, fn func(Row) error) error {
	t := d.tables[strings.ToLower(table)]
	if t == nil {
		return fmt.Errorf("sqliteread: no such table %q", table)
	}
	return d.walkTable(t.rootPage, t, fn, make(map[int]bool))
}

func detectSidecars(path string) []string {
	var out []string
	for _, suffix := range []string{"-wal", "-journal"} {
		fi, err := os.Stat(path + suffix)
		if err == nil && fi.Size() > 0 {
			out = append(out, path+suffix)
		}
	}
	return out
}

func (d *DB) loadSchema() error {
	master := &tableInfo{
		name:     "sqlite_master",
		rootPage: 1,
		columns:  []string{"type", "name", "tbl_name", "rootpage", "sql"},
		rowidCol: -1,
	}
	master.colIndex = indexColumns(master.columns)

	err := d.walkTable(1, master, func(r Row) error {
		if r.Text("type") != "table" {
			return nil
		}
		name := r.Text("name")
		if name == "" {
			return nil
		}
		root, ok := r.Int("rootpage")
		if !ok || root < 1 {
			return nil
		}
		cols, rowidCol := parseCreateTableColumns(r.Text("sql"))
		if len(cols) == 0 {
			return nil
		}
		info := &tableInfo{
			name:     name,
			rootPage: int(root),
			columns:  cols,
			colIndex: indexColumns(cols),
			rowidCol: rowidCol,
		}
		key := strings.ToLower(name)
		if _, seen := d.tables[key]; !seen {
			d.order = append(d.order, name)
		}
		d.tables[key] = info
		return nil
	}, make(map[int]bool))

	return err
}

func indexColumns(cols []string) map[string]int {
	m := make(map[string]int, len(cols))
	for i, c := range cols {
		m[strings.ToLower(c)] = i
	}
	return m
}

// parseCreateTableColumns pulls the column names out of a CREATE TABLE
// statement and reports which column, if any, is an INTEGER PRIMARY KEY (and
// therefore an alias for the rowid rather than a stored value).
func parseCreateTableColumns(sql string) ([]string, int) {
	open := strings.Index(sql, "(")
	if open < 0 {
		return nil, -1
	}
	close := matchingParen(sql, open)
	if close < 0 {
		return nil, -1
	}

	body := sql[open+1 : close]
	var cols []string
	rowidCol := -1

	for _, def := range splitTopLevel(body) {
		def = strings.TrimSpace(def)
		if def == "" {
			continue
		}
		name, rest := firstIdentifier(def)
		if name == "" {
			continue
		}
		if isTableConstraintKeyword(name) {
			continue
		}
		if isIntegerPrimaryKey(rest) {
			rowidCol = len(cols)
		}
		cols = append(cols, name)
	}
	return cols, rowidCol
}

func matchingParen(s string, open int) int {
	depth := 0
	inQuote := byte(0)
	for i := open; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inQuote = c
		case '[':
			inQuote = ']'
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopLevel(s string) []string {
	var parts []string
	depth := 0
	inQuote := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inQuote = c
		case '[':
			inQuote = ']'
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// firstIdentifier returns the leading (possibly quoted) identifier of a column
// definition together with whatever follows it.
func firstIdentifier(def string) (string, string) {
	def = strings.TrimSpace(def)
	if def == "" {
		return "", ""
	}

	var closeQuote byte
	switch def[0] {
	case '"', '`', '\'':
		closeQuote = def[0]
	case '[':
		closeQuote = ']'
	}
	if closeQuote != 0 {
		end := strings.IndexByte(def[1:], closeQuote)
		if end < 0 {
			return "", ""
		}
		return def[1 : 1+end], strings.TrimSpace(def[2+end:])
	}

	end := strings.IndexAny(def, " \t\r\n(")
	if end < 0 {
		return def, ""
	}
	return def[:end], strings.TrimSpace(def[end:])
}

func isTableConstraintKeyword(word string) bool {
	switch strings.ToUpper(word) {
	case "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN":
		return true
	}
	return false
}

func isIntegerPrimaryKey(rest string) bool {
	up := strings.ToUpper(rest)
	if !strings.HasPrefix(up, "INTEGER") {
		return false
	}
	return strings.Contains(up, "PRIMARY") && strings.Contains(up, "KEY")
}
