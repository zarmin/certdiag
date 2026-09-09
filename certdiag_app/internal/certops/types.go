package certops

import "fmt"

type OperationError struct {
	Op      string
	Message string
	Err     error
}

func (e *OperationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Message)
}

func (e *OperationError) Unwrap() error {
	return e.Err
}
