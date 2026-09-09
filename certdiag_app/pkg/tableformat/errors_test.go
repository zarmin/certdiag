package tableformat

import (
	"strings"
	"testing"
)

func TestTableErrorError(t *testing.T) {
	tests := []struct {
		name       string
		err        TableError
		wantCol    bool
		wantColNum int
	}{
		{
			name:    "Column=-1 no column in output",
			err:     TableError{Code: ErrInvalidConfig, Message: "test", Column: -1},
			wantCol: false,
		},
		{
			name:       "Column=0 column in output",
			err:        TableError{Code: ErrMaxLessThanMin, Message: "test", Column: 0},
			wantCol:    true,
			wantColNum: 0,
		},
		{
			name:       "Column=3 column in output",
			err:        TableError{Code: ErrBothFixWidthAndPercent, Message: "bad col", Column: 3},
			wantCol:    true,
			wantColNum: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if tt.wantCol {
				want := "column="
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want to contain %q", got, want)
				}
			} else {
				if strings.Contains(got, "column=") {
					t.Errorf("Error() = %q, should not contain column=", got)
				}
			}
			if !strings.Contains(got, tt.err.Message) {
				t.Errorf("Error() = %q, should contain message %q", got, tt.err.Message)
			}
		})
	}
}

func TestNewTableError(t *testing.T) {
	err := newTableError(ErrInvalidConfig, "something wrong")
	if err.Column != -1 {
		t.Errorf("Column = %d, want -1", err.Column)
	}
	if err.Code != ErrInvalidConfig {
		t.Errorf("Code = %d, want %d", err.Code, ErrInvalidConfig)
	}
	if err.Message != "something wrong" {
		t.Errorf("Message = %q, want %q", err.Message, "something wrong")
	}
}

func TestNewTableErrorWithColumn(t *testing.T) {
	err := newTableErrorWithColumn(ErrBothFixWidthAndMinMax, "col problem", 5)
	if err.Column != 5 {
		t.Errorf("Column = %d, want 5", err.Column)
	}
	if err.Code != ErrBothFixWidthAndMinMax {
		t.Errorf("Code = %d, want %d", err.Code, ErrBothFixWidthAndMinMax)
	}
}

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		code TableErrorCode
		want int
	}{
		{"ErrMaxLessThanMin", ErrMaxLessThanMin, 0},
		{"ErrAutoDetectWithFixWidth", ErrAutoDetectWithFixWidth, 1},
		{"ErrBothFixWidthAndPercent", ErrBothFixWidthAndPercent, 2},
		{"ErrBothFixWidthAndMinMax", ErrBothFixWidthAndMinMax, 3},
		{"ErrEffectiveMaxLessThanMin", ErrEffectiveMaxLessThanMin, 4},
		{"ErrFixedWidthExceedsTable", ErrFixedWidthExceedsTable, 5},
		{"ErrNoWrapContentDoesNotFit", ErrNoWrapContentDoesNotFit, 6},
		{"ErrColumnWidthTooSmall", ErrColumnWidthTooSmall, 7},
		{"ErrInvalidConfig", ErrInvalidConfig, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.code) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.want)
			}
		})
	}
}
