package sqliteread

import (
	"encoding/binary"
	"fmt"
	"math"
)

// readVarint decodes a SQLite big-endian base-128 varint. It returns the value
// and the number of bytes consumed, or n <= 0 when the input is truncated.
func readVarint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 8; i++ {
		if i >= len(b) {
			return 0, 0
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return int64(v), i + 1
		}
	}
	if len(b) < 9 {
		return 0, 0
	}
	v = v<<8 | uint64(b[8])
	return int64(v), 9
}

type value struct {
	null  bool
	blob  []byte
	isInt bool
	i     int64
	isF   bool
	f     float64
	text  bool
}

type record struct {
	table  *tableInfo
	values []value
	rowid  int64
}

func decodeRecord(payload []byte, t *tableInfo, rowid int64) (Row, error) {
	headerLen, n := readVarint(payload)
	if n <= 0 || headerLen < int64(n) || headerLen > int64(len(payload)) {
		return nil, fmt.Errorf("bad record header")
	}

	var serials []int64
	p := n
	for int64(p) < headerLen {
		s, m := readVarint(payload[p:])
		if m <= 0 {
			return nil, fmt.Errorf("bad serial type varint")
		}
		serials = append(serials, s)
		p += m
	}

	body := payload[headerLen:]
	values := make([]value, 0, len(serials))
	off := 0

	for _, s := range serials {
		v, size, err := decodeValue(s, body, off)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		off += size
	}

	return &record{table: t, values: values, rowid: rowid}, nil
}

func decodeValue(serial int64, body []byte, off int) (value, int, error) {
	need := func(n int) error {
		if off+n > len(body) {
			return fmt.Errorf("record body truncated")
		}
		return nil
	}

	switch {
	case serial == 0:
		return value{null: true}, 0, nil
	case serial == 1:
		if err := need(1); err != nil {
			return value{}, 0, err
		}
		return value{isInt: true, i: int64(int8(body[off]))}, 1, nil
	case serial == 2:
		if err := need(2); err != nil {
			return value{}, 0, err
		}
		return value{isInt: true, i: int64(int16(binary.BigEndian.Uint16(body[off : off+2])))}, 2, nil
	case serial == 3:
		if err := need(3); err != nil {
			return value{}, 0, err
		}
		u := uint32(body[off])<<16 | uint32(body[off+1])<<8 | uint32(body[off+2])
		if u&0x800000 != 0 {
			u |= 0xff000000
		}
		return value{isInt: true, i: int64(int32(u))}, 3, nil
	case serial == 4:
		if err := need(4); err != nil {
			return value{}, 0, err
		}
		return value{isInt: true, i: int64(int32(binary.BigEndian.Uint32(body[off : off+4])))}, 4, nil
	case serial == 5:
		if err := need(6); err != nil {
			return value{}, 0, err
		}
		var u uint64
		for i := 0; i < 6; i++ {
			u = u<<8 | uint64(body[off+i])
		}
		if u&0x800000000000 != 0 {
			u |= 0xffff000000000000
		}
		return value{isInt: true, i: int64(u)}, 6, nil
	case serial == 6:
		if err := need(8); err != nil {
			return value{}, 0, err
		}
		return value{isInt: true, i: int64(binary.BigEndian.Uint64(body[off : off+8]))}, 8, nil
	case serial == 7:
		if err := need(8); err != nil {
			return value{}, 0, err
		}
		return value{isF: true, f: math.Float64frombits(binary.BigEndian.Uint64(body[off : off+8]))}, 8, nil
	case serial == 8:
		return value{isInt: true, i: 0}, 0, nil
	case serial == 9:
		return value{isInt: true, i: 1}, 0, nil
	case serial == 10, serial == 11:
		return value{null: true}, 0, nil
	case serial >= 12 && serial%2 == 0:
		n := int((serial - 12) / 2)
		if err := need(n); err != nil {
			return value{}, 0, err
		}
		return value{blob: body[off : off+n]}, n, nil
	default: // serial >= 13, odd
		n := int((serial - 13) / 2)
		if err := need(n); err != nil {
			return value{}, 0, err
		}
		return value{blob: body[off : off+n], text: true}, n, nil
	}
}

func (r *record) at(col string) (value, bool) {
	idx, ok := r.table.colIndex[lower(col)]
	if !ok || idx >= len(r.values) {
		return value{}, false
	}
	// An INTEGER PRIMARY KEY column is stored as NULL; its value is the rowid.
	if idx == r.table.rowidCol {
		return value{isInt: true, i: r.rowid}, true
	}
	return r.values[idx], true
}

func (r *record) Blob(col string) []byte {
	v, ok := r.at(col)
	if !ok || v.null {
		return nil
	}
	return v.blob
}

func (r *record) Text(col string) string {
	v, ok := r.at(col)
	if !ok || v.null {
		return ""
	}
	if v.blob != nil {
		return string(v.blob)
	}
	return ""
}

func (r *record) Int(col string) (int64, bool) {
	v, ok := r.at(col)
	if !ok || v.null {
		return 0, false
	}
	if v.isInt {
		return v.i, true
	}
	if v.isF {
		return int64(v.f), true
	}
	return 0, false
}

// Uint32BE reads a column stored as a 4-byte big-endian blob, the encoding NSS
// uses for PKCS#11 CK_ULONG attributes. Integer columns are accepted too.
func (r *record) Uint32BE(col string) (uint32, bool) {
	v, ok := r.at(col)
	if !ok || v.null {
		return 0, false
	}
	if len(v.blob) == 4 {
		return binary.BigEndian.Uint32(v.blob), true
	}
	if v.isInt && v.i >= 0 && v.i <= math.MaxUint32 {
		return uint32(v.i), true
	}
	return 0, false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
