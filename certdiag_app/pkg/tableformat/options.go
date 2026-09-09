package tableformat

type TextAlign int

const (
	AlignLeft TextAlign = iota
	AlignCenter
	AlignRight
)

const Ellipsis = "\u2026"

type TableOptions struct {
	AutoDetect       bool
	FixWidth         int
	MinWidth         int
	MaxWidth         int
	AllowLinebreaks  bool
	WhitespaceWrap   bool
	Compact          bool
	DisplayHeaders   bool
	RowSeparators    bool
	DefaultAlignment TextAlign
}

type ColumnConfig struct {
	Name            string
	FixWidth        int
	FixWidthPercent float64
	MinWidth        int
	MaxWidth        int
	TruncateAfter   int
	NoWrap          bool
	Alignment       TextAlign
	HasAlignment    bool
	// Priority marks a column the renderer may hide when the width cannot
	// hold every column at its minimum: the highest number goes first, 0
	// (the default) is never hidden.
	Priority int
}

type TableOption func(*Table)

func WithAutoDetect() TableOption {
	return func(t *Table) {
		t.Options.AutoDetect = true
		t.Options.FixWidth = 0
	}
}

func WithWidth(width int) TableOption {
	return func(t *Table) {
		t.Options.FixWidth = width
		t.Options.AutoDetect = false
	}
}

func WithMinWidth(min int) TableOption {
	return func(t *Table) {
		t.Options.MinWidth = min
	}
}

func WithMaxWidth(max int) TableOption {
	return func(t *Table) {
		t.Options.MaxWidth = max
	}
}

func WithAllowLinebreaks(allow bool) TableOption {
	return func(t *Table) {
		t.Options.AllowLinebreaks = allow
	}
}

func WithWhitespaceWrap(wrap bool) TableOption {
	return func(t *Table) {
		t.Options.WhitespaceWrap = wrap
	}
}

func WithCompact(compact bool) TableOption {
	return func(t *Table) {
		t.Options.Compact = compact
	}
}

func WithDisplayHeaders(display bool) TableOption {
	return func(t *Table) {
		t.Options.DisplayHeaders = display
	}
}

func WithRowSeparators(separators bool) TableOption {
	return func(t *Table) {
		t.Options.RowSeparators = separators
	}
}

func WithDefaultAlignment(align TextAlign) TableOption {
	return func(t *Table) {
		t.Options.DefaultAlignment = align
	}
}

type ColOption func(*ColumnConfig)

func ColFixWidth(width int) ColOption {
	return func(c *ColumnConfig) {
		c.FixWidth = width
	}
}

func ColFixWidthPercent(percent float64) ColOption {
	return func(c *ColumnConfig) {
		c.FixWidthPercent = percent
	}
}

func ColMinWidth(min int) ColOption {
	return func(c *ColumnConfig) {
		c.MinWidth = min
	}
}

func ColMaxWidth(max int) ColOption {
	return func(c *ColumnConfig) {
		c.MaxWidth = max
	}
}

func ColTruncateAfter(length int) ColOption {
	return func(c *ColumnConfig) {
		c.TruncateAfter = length
	}
}

// ColPriority makes the column droppable at narrow widths; higher numbers are
// dropped before lower ones. Identity columns keep the default 0.
func ColPriority(priority int) ColOption {
	return func(c *ColumnConfig) {
		c.Priority = priority
	}
}

func ColNoWrap() ColOption {
	return func(c *ColumnConfig) {
		c.NoWrap = true
	}
}

func ColAlign(align TextAlign) ColOption {
	return func(c *ColumnConfig) {
		c.Alignment = align
		c.HasAlignment = true
	}
}
