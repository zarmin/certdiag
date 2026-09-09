package output

import (
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestFormatTableView_BasicCert(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, rsaKey, caCert, caKey)
	container := makeContainer("/tmp/cert.pem", certlib.FormatPEM, makeCertItem(leaf))

	got := FormatTableView([]*certlib.CertContainer{container}, OutputOptions{})
	for _, sub := range []string{"FILENAME", "TYPE", "SUBJECT", "pem/cert"} {
		if !strings.Contains(got, sub) {
			t.Errorf("output missing %q", sub)
		}
	}
}

func TestFormatTableView_PrivateKey(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	container := makeContainer("/tmp/key.pem", certlib.FormatPEM, makeKeyItem(rsaKey))

	got := FormatTableView([]*certlib.CertContainer{container}, OutputOptions{})
	if !strings.Contains(got, "pem/key") {
		t.Error("should contain 'pem/key'")
	}
}

func TestFormatTableView_EncryptedKey(t *testing.T) {
	disableColors(t)
	t.Setenv("COLUMNS", "120") // content test; narrow widths wrap ALGO
	item := certlib.CertItem{Type: certlib.ContentPrivateKey, Encrypted: true}
	container := makeContainer("/tmp/enc.pem", certlib.FormatPEM, item)

	got := FormatTableView([]*certlib.CertContainer{container}, OutputOptions{})
	if !strings.Contains(got, "(encrypted)") {
		t.Error("should contain '(encrypted)'")
	}
}

func TestFormatTableView_SelfSigned(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/ca.pem", certlib.FormatPEM, makeCertItem(cert))

	got := FormatTableView([]*certlib.CertContainer{container}, OutputOptions{})
	if !strings.Contains(got, "Self-signed") {
		t.Error("should contain 'Self-signed'")
	}
}

func TestFormatTableView_SkipsRelationsOnly(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/rel.pem", certlib.FormatPEM, makeCertItem(cert))
	container.RelationsOnly = true

	got := FormatTableView([]*certlib.CertContainer{container}, OutputOptions{})
	if strings.Contains(got, "rel.pem") {
		t.Error("RelationsOnly container should not appear in table")
	}
}

func TestFormatTableView_MultipleContainers(t *testing.T) {
	disableColors(t)
	rsaKey1 := mustGenRSAKey(t)
	cert1 := mustSelfSignedCert(t, rsaKey1)
	rsaKey2 := mustGenRSAKey(t)
	cert2 := mustSelfSignedCert(t, rsaKey2)

	containers := []*certlib.CertContainer{
		makeContainer("/tmp/first.pem", certlib.FormatPEM, makeCertItem(cert1)),
		makeContainer("/tmp/second.pem", certlib.FormatPEM, makeCertItem(cert2)),
	}

	got := FormatTableView(containers, OutputOptions{})
	if !strings.Contains(got, "first.pem") {
		t.Error("should contain first filename")
	}
	if !strings.Contains(got, "second.pem") {
		t.Error("should contain second filename")
	}
}

func TestNewTable_HeaderColumnLockstep(t *testing.T) {
	cases := []struct {
		name         string
		hasRelations bool
		hasChecks    bool
		wantExtra    []string
	}{
		{"neither", false, false, nil},
		{"relations-only", true, false, []string{"RELATIONS"}},
		{"checks-only", false, true, []string{"WARNINGS"}},
		{"both", true, true, []string{"RELATIONS", "WARNINGS"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl := newTable(tc.hasRelations, tc.hasChecks, false)
			if len(tbl.Headers) != len(tbl.Columns) {
				t.Fatalf("header count %d != column count %d", len(tbl.Headers), len(tbl.Columns))
			}
			for i := range tbl.Headers {
				if tbl.Headers[i] != tbl.Columns[i].Name {
					t.Errorf("header/column mismatch at %d: header %q vs column %q", i, tbl.Headers[i], tbl.Columns[i].Name)
				}
			}
			want := append([]string{"FILENAME", "TYPE", "SUBJECT", "ISSUER", "EXPIRY", "ALGO"}, tc.wantExtra...)
			if len(tbl.Headers) != len(want) {
				t.Fatalf("got %d headers, want %d", len(tbl.Headers), len(want))
			}
			for i, h := range want {
				if tbl.Headers[i] != h {
					t.Errorf("header[%d] = %q, want %q", i, tbl.Headers[i], h)
				}
			}
		})
	}
}

func TestFormatTableView_RelationsAndChecksAligned(t *testing.T) {
	disableColors(t)
	t.Setenv("COLUMNS", "200") // every column must be present to check alignment
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leafKey := mustGenRSAKey(t)
	leaf, _, err := certlib.CreateSignedCert(leafKey, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "leaf.example.com"},
		SANs:       certlib.SANList{DNSNames: []string{"leaf.example.com"}},
		Days:       3,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	store := certlib.NewCertStore()
	store.AddContainer(*makeContainer("/tmp/leaf.pem", certlib.FormatPEM, makeCertItem(leaf)))
	store.AddContainer(*makeContainer("/tmp/ca.pem", certlib.FormatPEM, makeCertItem(caCert)))

	relations := certlib.DetectRelations(store)
	relIndex := certlib.BuildRelationIndex(relations, store)
	checkResult := certlib.RunChecks(store, relIndex, certlib.CheckOptions{})

	if len(checkResult.Issues) == 0 {
		t.Fatal("expected the near-expiry leaf to trigger warnings")
	}

	opts := OutputOptions{
		RelationIndex: relIndex,
		Chains:        certlib.AssembleChains(relIndex, store),
		Store:         store,
		CheckResult:   checkResult,
	}
	containers := []*certlib.CertContainer{&store.Containers[0], &store.Containers[1]}

	got := stripANSI(FormatTableView(containers, opts))

	cellGrid := func() [][]string {
		var grid [][]string
		for _, line := range strings.Split(got, "\n") {
			if !strings.Contains(line, "│") {
				continue
			}
			var cells []string
			for _, c := range strings.Split(line, "│") {
				cells = append(cells, strings.TrimSpace(c))
			}
			grid = append(grid, cells)
		}
		return grid
	}()

	if len(cellGrid) == 0 {
		t.Fatalf("no bordered rows found in:\n%s", got)
	}

	relCol, warnCol := -1, -1
	for i, c := range cellGrid[0] {
		if strings.HasPrefix(c, "REL") {
			relCol = i
		}
		if strings.HasPrefix(c, "WARN") {
			warnCol = i
		}
	}
	if relCol == -1 || warnCol == -1 {
		t.Fatalf("RELATIONS (%d) and/or WARNINGS (%d) header column not found in %v", relCol, warnCol, cellGrid[0])
	}
	if relCol >= warnCol {
		t.Errorf("RELATIONS column %d should be left of WARNINGS column %d", relCol, warnCol)
	}
	for _, cells := range cellGrid {
		if len(cells) != len(cellGrid[0]) {
			t.Errorf("row has %d cells, header has %d: %v", len(cells), len(cellGrid[0]), cells)
		}
	}

	colText := func(col int) string {
		var b strings.Builder
		for r, cells := range cellGrid {
			if r == 0 || col >= len(cells) {
				continue
			}
			b.WriteString(strings.ReplaceAll(cells[col], " ", ""))
		}
		return b.String()
	}

	if !strings.Contains(colText(relCol), "TestCA") {
		t.Errorf("relation data should render under the RELATIONS column, got %q", colText(relCol))
	}
	if !strings.Contains(colText(warnCol), "CRITICAL") {
		t.Errorf("warning data should render under the WARNINGS column, got %q", colText(warnCol))
	}
	if strings.Contains(colText(warnCol), "TestCA") {
		t.Errorf("relation data leaked into the WARNINGS column (misaligned)")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestResolveTableContainerIndices_DuplicatePaths(t *testing.T) {
	store := &certlib.CertStore{
		Containers: []certlib.CertContainer{
			{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM},
			{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM},
			{FilePath: "/tmp/other.pem", Format: certlib.FormatPEM},
		},
	}
	containers := []*certlib.CertContainer{
		&store.Containers[1],
		&store.Containers[2],
		&store.Containers[0],
	}

	got := resolveTableContainerIndices(containers, OutputOptions{Store: store})
	want := map[int]int{0: 1, 1: 2, 2: 0}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d resolved to store %d, want %d", i, got[i], w)
		}
	}
}

func TestResolveTableContainerIndices_NoMatch(t *testing.T) {
	store := &certlib.CertStore{
		Containers: []certlib.CertContainer{{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM}},
	}
	orphan := makeContainer("/tmp/dup.pem", certlib.FormatPEM)

	got := resolveTableContainerIndices([]*certlib.CertContainer{orphan}, OutputOptions{Store: store})
	if got[0] != -1 {
		t.Errorf("orphan container resolved to store %d, want -1", got[0])
	}
}
