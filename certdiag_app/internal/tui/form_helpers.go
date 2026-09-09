package tui

import (
	"errors"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// formResult wraps an operation error into a FormResultMsg.
// Detects certlib.ErrFileExists and sets the FileExists flag.
func formResult(err error, successMsg string) FormResultMsg {
	if err != nil {
		if errors.Is(err, certlib.ErrFileExists) {
			return FormResultMsg{FileExists: true, Err: err}
		}
		return FormResultMsg{Err: err}
	}
	return FormResultMsg{Success: true, Message: successMsg}
}

func nilIfEmpty(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func formResultWithPasswords(err error, successMsg string, passwords ...[]byte) FormResultMsg {
	msg := formResult(err, successMsg)
	if msg.Success {
		for _, pw := range passwords {
			if pw != nil {
				msg.Passwords = append(msg.Passwords, pw)
			}
		}
	}
	return msg
}
