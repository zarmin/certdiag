package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// newModelFromStore builds a RootModel in the tree state from an in-memory
// store, the way ScanCompleteMsg would, without touching the filesystem.
func newModelFromStore(t *testing.T, store *certlib.CertStore) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()
	m := makeTestRootModel()
	m.state = stateTree
	m.store = store
	m.opts = m.stampDisplayOpts(output.OutputOptions{})
	m.allNodes = ConvertStore(store, m.opts, m.pathDisplay)
	m.recomputeVisible()
	return m
}
