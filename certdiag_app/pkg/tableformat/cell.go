package tableformat

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/text"
)

type CellStyle struct {
	FgColor   text.Color
	BgColor   text.Color
	Bold      bool
	Italic    bool
	Alignment TextAlign
	HasAlign  bool
}

type TableCell struct {
	Content string
	Style   CellStyle
}

type CellOption func(*TableCell)

func Cell(content ...interface{}) TableCell {
	return TableCell{
		Content: fmt.Sprint(content...),
		Style:   CellStyle{},
	}
}

func CellBold(cell TableCell) TableCell {
	cell.Style.Bold = true
	return cell
}

func CellItalic(cell TableCell) TableCell {
	cell.Style.Italic = true
	return cell
}

func CellFg(color text.Color) func(TableCell) TableCell {
	return func(cell TableCell) TableCell {
		cell.Style.FgColor = color
		return cell
	}
}

func CellBg(color text.Color) func(TableCell) TableCell {
	return func(cell TableCell) TableCell {
		cell.Style.BgColor = color
		return cell
	}
}

func CellAlign(align TextAlign) func(TableCell) TableCell {
	return func(cell TableCell) TableCell {
		cell.Style.Alignment = align
		cell.Style.HasAlign = true
		return cell
	}
}
