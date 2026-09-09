package tableformat

import (
	"bytes"
	"io"
	"os"
)

type Table struct {
	Options TableOptions
	Headers []string
	Columns []ColumnConfig
	rows    [][]interface{}
}

func New(opts ...TableOption) *Table {
	t := &Table{
		Options: TableOptions{
			FixWidth:         160,
			AllowLinebreaks:  true,
			DisplayHeaders:   true,
			WhitespaceWrap:   true,
			DefaultAlignment: AlignLeft,
		},
		Headers: []string{},
		Columns: []ColumnConfig{},
		rows:    [][]interface{}{},
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

func (t *Table) SetHeaders(headers ...string) *Table {
	t.Headers = headers
	return t
}

func (t *Table) AddColumn(name string, opts ...ColOption) *Table {
	col := ColumnConfig{
		Name:      name,
		Alignment: AlignLeft,
	}

	for _, opt := range opts {
		opt(&col)
	}

	t.Columns = append(t.Columns, col)
	return t
}

func (t *Table) AddRow(cells ...interface{}) *Table {
	t.rows = append(t.rows, cells)
	return t
}

func (t *Table) Display() error {
	return t.Render(os.Stdout)
}

func (t *Table) Render(w io.Writer) error {
	return render(t, w)
}

func (t *Table) String() (string, error) {
	var buf bytes.Buffer
	err := render(t, &buf)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
