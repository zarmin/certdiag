package tui

import "testing"

func TestPasswordCache_AddEmpty(t *testing.T) {
	pc := newPasswordCache()
	pc.add([]byte(""))
	if pc.len() != 1 {
		t.Fatalf("len = %d, want 1 after adding empty password", pc.len())
	}
}

func TestPasswordCache_AddNil(t *testing.T) {
	pc := newPasswordCache()
	pc.add(nil)
	if pc.len() != 0 {
		t.Fatalf("len = %d, want 0 after adding nil", pc.len())
	}
}

func TestPasswordCache_DeduplicateEmpty(t *testing.T) {
	pc := newPasswordCache()
	pc.add([]byte(""))
	pc.add([]byte(""))
	if pc.len() != 1 {
		t.Fatalf("len = %d, want 1 after adding empty twice", pc.len())
	}
}

func TestPasswordCache_EmptyAndNonEmpty(t *testing.T) {
	pc := newPasswordCache()
	pc.add([]byte(""))
	pc.add([]byte("x"))
	if pc.len() != 2 {
		t.Fatalf("len = %d, want 2", pc.len())
	}
}
