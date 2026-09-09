package cmdutil

import "testing"

func TestNewSimplePasswordManager_NilConfig(t *testing.T) {
	pm, err := NewSimplePasswordManager(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pm == nil {
		t.Fatal("expected non-nil PasswordManager")
	}
}

func TestNewSimplePasswordManager_WithPasswords(t *testing.T) {
	pm, err := NewSimplePasswordManager([]string{"pass1", "pass2"}, nil, nil, []byte("master"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pm == nil {
		t.Fatal("expected non-nil PasswordManager")
	}
}
