package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestRestoreNavEntry_IdentityWinsOverStaleIndex(t *testing.T) {
	m := makeTestRootModel()
	m.tree.cursor = 0

	// entry references server.key (visible index 1), but the stored
	// treeCursor is stale and points at a different visible row.
	entry := navEntry{
		ref:        certlib.ItemRef{ContainerIdx: 1, ItemIdx: 0},
		treeCursor: 2,
		treeOffset: 0,
	}

	m.restoreNavEntry(entry)

	if m.tree.cursor != 1 {
		t.Fatalf("expected cursor at identity-synced node (1), got %d", m.tree.cursor)
	}
	if m.detail == nil {
		t.Fatal("expected detail to be set for restored node")
	}
	if m.detail.node.ContainerIdx != 1 || m.detail.node.ItemIdx != 0 {
		t.Fatalf("expected detail on server.key, got container=%d item=%d",
			m.detail.node.ContainerIdx, m.detail.node.ItemIdx)
	}
}

func TestRestoreNavEntry_StaleIndexNeverClobbersIdentity(t *testing.T) {
	m := makeTestRootModel()
	m.tree.cursor = 1

	// Reference the bundle (visible index 2) while the stored index is 0.
	entry := navEntry{
		ref:        certlib.ItemRef{ContainerIdx: 2, ItemIdx: -1},
		treeCursor: 0,
		treeOffset: 0,
	}

	m.restoreNavEntry(entry)

	if m.tree.cursor != 2 {
		t.Fatalf("expected cursor at identity-synced node (2), got %d", m.tree.cursor)
	}
}

func TestRestoreNavEntry_MissingRefIsNoOp(t *testing.T) {
	m := makeTestRootModel()
	m.tree.cursor = 1

	// Ref no longer present in the tree: restore must not corrupt the cursor.
	entry := navEntry{
		ref:        certlib.ItemRef{ContainerIdx: 99, ItemIdx: 99},
		treeCursor: 0,
		treeOffset: 0,
	}

	m.restoreNavEntry(entry)

	if m.tree.cursor != 1 {
		t.Fatalf("expected cursor unchanged (1) for missing ref, got %d", m.tree.cursor)
	}
	if m.detail != nil {
		t.Fatal("expected no detail for missing ref")
	}
}
