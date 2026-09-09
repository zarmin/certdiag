package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

func TestConvertStore_LabelShownInsteadOfBasename(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21/lib/security/cacerts", tsCert(t, "Root A")),
	)

	// The store name is what is useful, not the basename "cacerts".
	if nodeByFilename(m, "Java 21 (Temurin)") == nil {
		var got []string
		for _, n := range m.visible {
			got = append(got, n.Filename)
		}
		t.Fatalf("expected the store label as the first column, got %v", got)
	}
	if nodeByFilename(m, "cacerts") != nil {
		t.Error("the basename must not be shown when a label is set")
	}
}

func TestConvertStore_EmptyLabelUnchanged(t *testing.T) {
	// Regression guard for the CertContainer.Label addition: a container with
	// no label must render exactly as it did before.
	cert := tsCert(t, "File Root")
	// Already absolute on every platform: on Windows filepath.Abs would
	// prepend the current drive to a rooted slash path.
	path, err := filepath.Abs(filepath.FromSlash("/tmp/some/server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: path,
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items: []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: cert},
		},
	})

	nodes := ConvertStore(store, output.OutputOptions{}, "filename")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Filename != "server.pem" {
		t.Errorf("expected the formatted path, got %q", nodes[0].Filename)
	}

	// And the other path display modes still work.
	abs := ConvertStore(store, output.OutputOptions{}, "absolute")
	if abs[0].Filename != path {
		t.Errorf("expected the absolute path, got %q", abs[0].Filename)
	}
}

func TestConvertStore_TrustStoreAlwaysRendersAsGroup(t *testing.T) {
	// Even a single-cert store must show a group header plus a child row, so
	// the grouping is consistent regardless of store size.
	m := newStoreTestModel(t,
		tsStore("Tiny Store", truststore.StoreTypeCustom, "/tmp/tiny.pem", tsCert(t, "Only Root")),
	)

	header := nodeByFilename(m, "Tiny Store")
	if header == nil {
		t.Fatal("expected a group header row")
	}
	if !header.IsBundle {
		t.Error("a trust store container must render as a bundle")
	}
	if header.ChildCount != 1 {
		t.Errorf("expected ChildCount 1, got %d", header.ChildCount)
	}

	var children int
	for _, n := range m.visible {
		if n.IsChild {
			children++
		}
	}
	if children != 1 {
		t.Errorf("expected 1 child row, got %d", children)
	}
}

func TestConvertStore_EmptyStoreRendersAsGroup(t *testing.T) {
	locked := truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:     truststore.StoreTypeJava,
			Name:     "Java 21 (locked)",
			Path:     "/jdk/cacerts",
			Warnings: []string{"read error: bad password"},
		},
	}
	m := newStoreTestModel(t, locked)

	header := nodeByFilename(m, "Java 21 (locked)")
	if header == nil {
		t.Fatal("a store that failed to read must still appear")
	}
	if header.ChildCount != 0 {
		t.Errorf("expected no children, got %d", header.ChildCount)
	}
}

func TestSearchable_IncludesStoreLabel(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21", tsCert(t, "Root A")),
		tsStore("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", tsCert(t, "Root B")),
	)

	m.search.filterText = "temurin"
	m.recomputeVisible()

	if len(m.visible) == 0 {
		t.Fatal("expected the Temurin group to match")
	}
	for _, n := range m.visible {
		if strings.Contains(n.Filename, "OpenSSL") {
			t.Error("the OpenSSL group must be filtered out")
		}
	}
}

func TestSearchable_IncludesStoreTags(t *testing.T) {
	shared := tsCert(t, "Shared Root")
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
	)

	// Store tags are searchable, so "j21" finds certs present in that JDK.
	m.search.filterText = "j21"
	m.recomputeVisible()

	if len(m.visible) == 0 {
		t.Fatal("expected the store tag to be searchable")
	}
}

func TestFirstColHeader_StoreVsFilename(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Some Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)
	if m.tree.firstColHeader != headerStore {
		t.Errorf("expected the STORE header in the store view, got %q", m.tree.firstColHeader)
	}

	// The Cert Lister keeps FILENAME.
	plain := makeTestRootModel()
	if plain.tree.firstColHeader != "" && plain.tree.firstColHeader != headerFilename {
		t.Errorf("expected FILENAME for the cert lister, got %q", plain.tree.firstColHeader)
	}

	cols := colWidths{filename: 20, ctype: 10, opt: map[string]int{}}
	if got := buildHeader(cols, displayTruncate, 0, ""); !strings.Contains(got, headerFilename) {
		t.Errorf("an empty first-column header must default to FILENAME, got %q", got)
	}
	if got := buildHeader(cols, displayTruncate, 0, headerStore); !strings.Contains(got, headerStore) {
		t.Errorf("expected STORE in the header, got %q", got)
	}
}

func TestStoreNodes_CarryAliasAndSubject(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "DigiCert Global Root G2")),
	)

	var child *TreeNode
	for i := range m.visible {
		if m.visible[i].IsChild {
			child = &m.visible[i]
			break
		}
	}
	if child == nil {
		t.Fatal("expected a certificate row")
	}
	if !strings.Contains(child.Subject, "DigiCert") {
		t.Errorf("expected the subject populated, got %q", child.Subject)
	}
	if child.Item == nil || child.Item.Alias != "DigiCert Global Root G2" {
		t.Errorf("expected the alias set from the CN, got %+v", child.Item)
	}
}
