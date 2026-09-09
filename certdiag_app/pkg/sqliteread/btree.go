package sqliteread

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	pageInteriorIndex = 0x02
	pageInteriorTable = 0x05
	pageLeafIndex     = 0x0a
	pageLeafTable     = 0x0d
)

// page returns the raw bytes of a 1-based page number.
func (d *DB) page(n int) ([]byte, error) {
	if n < 1 || n > d.pageCount {
		return nil, structuralError{fmt.Sprintf("page %d out of range (1..%d)", n, d.pageCount)}
	}
	start := (n - 1) * d.pageSize
	end := start + d.pageSize
	if end > len(d.data) {
		return nil, structuralError{fmt.Sprintf("page %d truncated", n)}
	}
	return d.data[start:end], nil
}

// walkTable traverses a table b-tree depth-first, decoding every leaf cell.
// seen guards against a corrupt file producing a cycle.
func (d *DB) walkTable(pageNum int, t *tableInfo, fn func(Row) error, seen map[int]bool) error {
	if seen[pageNum] {
		return nil
	}
	seen[pageNum] = true

	raw, err := d.page(pageNum)
	if err != nil {
		return err
	}

	// Page 1 carries the 100-byte file header before its b-tree header.
	hdrOffset := 0
	if pageNum == 1 {
		hdrOffset = headerLen
	}
	if hdrOffset+12 > len(raw) {
		return structuralError{fmt.Sprintf("page %d too small for a b-tree header", pageNum)}
	}

	pageType := raw[hdrOffset]
	cellCount := int(binary.BigEndian.Uint16(raw[hdrOffset+3 : hdrOffset+5]))

	headerSize := 8
	if pageType == pageInteriorTable || pageType == pageInteriorIndex {
		headerSize = 12
	}
	ptrArray := hdrOffset + headerSize
	if ptrArray+cellCount*2 > len(raw) {
		return structuralError{fmt.Sprintf("page %d cell pointer array overruns the page", pageNum)}
	}

	switch pageType {
	case pageLeafTable:
		for i := 0; i < cellCount; i++ {
			off := int(binary.BigEndian.Uint16(raw[ptrArray+i*2 : ptrArray+i*2+2]))
			if off <= 0 || off >= len(raw) {
				continue
			}
			row, err := d.readLeafCell(raw, off, t)
			if err != nil {
				// A single unreadable cell must not abort the scan; the
				// remaining rows are still useful diagnostics.
				continue
			}
			if err := fn(row); err != nil {
				return err
			}
		}
		return nil

	case pageInteriorTable:
		// A child pointer that does not resolve costs that subtree, not the
		// whole table: a partially readable profile is still a useful
		// diagnostic. An error raised by fn itself still stops the scan.
		descend := func(child int) error {
			err := d.walkTable(child, t, fn, seen)
			if err == nil || isStructuralError(err) {
				return nil
			}
			return err
		}

		for i := 0; i < cellCount; i++ {
			off := int(binary.BigEndian.Uint16(raw[ptrArray+i*2 : ptrArray+i*2+2]))
			if off <= 0 || off+4 > len(raw) {
				continue
			}
			child := int(binary.BigEndian.Uint32(raw[off : off+4]))
			if err := descend(child); err != nil {
				return err
			}
		}
		right := int(binary.BigEndian.Uint32(raw[hdrOffset+8 : hdrOffset+12]))
		if right > 0 {
			return descend(right)
		}
		return nil

	case pageLeafIndex, pageInteriorIndex:
		// Not reachable for a table root; indexes are never scanned.
		return nil

	default:
		return structuralError{fmt.Sprintf("page %d has unknown type 0x%02x", pageNum, pageType)}
	}
}

// structuralError marks damage in the file itself, as opposed to an error
// raised by the caller's callback. Only the former is skippable.
type structuralError struct{ msg string }

func (e structuralError) Error() string { return e.msg }

func isStructuralError(err error) bool {
	var s structuralError
	return errors.As(err, &s)
}

// readLeafCell decodes one table-leaf cell, following the overflow chain when
// the payload does not fit locally.
func (d *DB) readLeafCell(raw []byte, off int, t *tableInfo) (Row, error) {
	p := off

	payloadLen, n := readVarint(raw[p:])
	if n <= 0 {
		return nil, fmt.Errorf("bad payload varint")
	}
	p += n

	rowid, n := readVarint(raw[p:])
	if n <= 0 {
		return nil, fmt.Errorf("bad rowid varint")
	}
	p += n

	if payloadLen < 0 {
		return nil, fmt.Errorf("negative payload length")
	}

	local := d.localPayloadSize(payloadLen)
	if p+local > len(raw) {
		return nil, fmt.Errorf("cell payload overruns the page")
	}

	payload := make([]byte, 0, payloadLen)
	payload = append(payload, raw[p:p+local]...)

	if int64(local) < payloadLen {
		if p+local+4 > len(raw) {
			return nil, fmt.Errorf("missing overflow pointer")
		}
		next := int(binary.BigEndian.Uint32(raw[p+local : p+local+4]))
		rest, err := d.readOverflow(next, payloadLen-int64(local))
		if err != nil {
			return nil, err
		}
		payload = append(payload, rest...)
	}

	return decodeRecord(payload, t, rowid)
}

// localPayloadSize implements the SQLite table-leaf payload spill rule.
func (d *DB) localPayloadSize(payloadLen int64) int {
	u := int64(d.usableSize)
	x := u - 35
	if payloadLen <= x {
		return int(payloadLen)
	}
	m := ((u - 12) * 32 / 255) - 23
	k := m + ((payloadLen - m) % (u - 4))
	if k <= x {
		return int(k)
	}
	return int(m)
}

func (d *DB) readOverflow(pageNum int, remaining int64) ([]byte, error) {
	out := make([]byte, 0, remaining)
	seen := make(map[int]bool)
	perPage := int64(d.usableSize - 4)

	for remaining > 0 {
		if pageNum < 1 {
			return nil, fmt.Errorf("overflow chain ended early, %d bytes missing", remaining)
		}
		if seen[pageNum] {
			return nil, fmt.Errorf("overflow chain loops at page %d", pageNum)
		}
		seen[pageNum] = true

		raw, err := d.page(pageNum)
		if err != nil {
			return nil, err
		}
		next := int(binary.BigEndian.Uint32(raw[0:4]))

		take := perPage
		if remaining < take {
			take = remaining
		}
		if int(4+take) > len(raw) {
			return nil, fmt.Errorf("overflow page %d truncated", pageNum)
		}
		out = append(out, raw[4:4+take]...)
		remaining -= take
		pageNum = next
	}
	return out, nil
}
