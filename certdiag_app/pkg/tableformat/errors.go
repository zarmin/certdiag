package tableformat

import "fmt"

type TableErrorCode int

const (
	ErrMaxLessThanMin TableErrorCode = iota
	ErrAutoDetectWithFixWidth
	ErrBothFixWidthAndPercent
	ErrBothFixWidthAndMinMax
	ErrEffectiveMaxLessThanMin
	ErrFixedWidthExceedsTable
	ErrNoWrapContentDoesNotFit
	ErrColumnWidthTooSmall
	ErrInvalidConfig
)

type TableError struct {
	Code    TableErrorCode
	Message string
	Column  int
}

func (e *TableError) Error() string {
	if e.Column >= 0 {
		return fmt.Sprintf("table error (code=%d, column=%d): %s", e.Code, e.Column, e.Message)
	}
	return fmt.Sprintf("table error (code=%d): %s", e.Code, e.Message)
}

func newTableError(code TableErrorCode, message string) *TableError {
	return &TableError{
		Code:    code,
		Message: message,
		Column:  -1,
	}
}

func newTableErrorWithColumn(code TableErrorCode, message string, column int) *TableError {
	return &TableError{
		Code:    code,
		Message: message,
		Column:  column,
	}
}
