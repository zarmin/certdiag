package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// TestJSONView_EmptyScanIsAnEmptyList guards M5: `"files": []`, never null.
func TestJSONView_EmptyScanIsAnEmptyList(t *testing.T) {
	out := FormatJSONView(nil, OutputOptions{})
	var parsed struct {
		Files []any `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if parsed.Files == nil {
		t.Errorf("files must be an empty array, got null:\n%s", out)
	}
	if !strings.Contains(FormatYAMLView(nil, OutputOptions{}), "files: []") {
		t.Errorf("YAML must agree: files: []")
	}
}

// TestListView_ChainLineHasOnePrefix guards M14: the chain label already
// carries "chain: ", the list view must not add a second one.
func TestListView_ChainLineHasOnePrefix(t *testing.T) {
	disableColors(t)
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, mustGenRSAKey(t), caCert, caKey)
	container := makeContainer("/tmp/chain.pem", certlib.FormatPEM, makeCertItem(leaf), makeCertItem(caCert))

	store := certlib.NewCertStore()
	store.AddContainer(*container)
	relations := certlib.DetectRelations(store)
	store.Relations = relations
	opts := OutputOptions{Store: store, RelationIndex: certlib.BuildRelationIndex(relations, store)}
	alts := certlib.AssembleChainAlternatives(opts.RelationIndex, store)
	opts.Chains = certlib.FirstChains(alts)

	out := FormatListView(&store.Containers[0], 0, opts)
	if !strings.Contains(out, "chain: ") {
		t.Fatalf("expected a chain line:\n%s", out)
	}
	if strings.Contains(out, "chain:     chain:") || strings.Count(out, "chain: ") > strings.Count(out, "\n      chain: ") {
		t.Errorf("chain line carries a doubled prefix:\n%s", out)
	}
}

// TestRemoteCheckSummary_InfoOnlyTargetIsOK guards M23.
func TestRemoteCheckSummary_InfoOnlyTargetIsOK(t *testing.T) {
	disableColors(t)
	result := &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{Target: "info.example:443", Issues: []certlib.CheckIssue{{Severity: certlib.SeverityInfo, CheckID: "remote_no_alpn", Message: "x"}},
				Summary: certlib.CheckSummary{Info: 1}},
			{Target: "warn.example:443", Issues: []certlib.CheckIssue{{Severity: certlib.SeverityWarning, CheckID: "sha1_sig", Message: "y"}},
				Summary: certlib.CheckSummary{Warning: 1}},
			{Target: "down.example:443", Error: "connection refused"},
		},
		Summary: certops.CheckRemoteSummary{Total: 3},
	}
	out := FormatRemoteCheckHuman(result)
	if !strings.Contains(out, "Targets: 3 total, 1 ok, 2 with issues") {
		t.Errorf("an INFO-only target is ok:\n%s", out)
	}
}

// TestTableView_NarrowWidthKeepsIdentityColumns guards H6: at 80 columns the
// FILENAME and SUBJECT columns stay readable and the optional columns give
// way, with a footer saying so.
func TestTableView_NarrowWidthKeepsIdentityColumns(t *testing.T) {
	disableColors(t)
	t.Setenv("COLUMNS", "80")
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, mustGenRSAKey(t), caCert, caKey)
	container := makeContainer("/tmp/a-certificate-with-a-long-file-name.pem", certlib.FormatPEM, makeCertItem(leaf), makeCertItem(caCert))

	store := certlib.NewCertStore()
	store.AddContainer(*container)
	relations := certlib.DetectRelations(store)
	store.Relations = relations
	opts := OutputOptions{Store: store, RelationIndex: certlib.BuildRelationIndex(relations, store)}

	out := stripANSI(FormatTableView([]*certlib.CertContainer{&store.Containers[0]}, opts))
	if !strings.Contains(out, "FILENAME") || !strings.Contains(out, "SUBJECT") {
		t.Fatalf("identity columns missing:\n%s", out)
	}
	if !strings.Contains(out, "a-certificat") { // the first 12 cells of the name, intact
		t.Errorf("FILENAME must keep at least 12 cells at 80 columns:\n%s", out)
	}
	header := strings.SplitN(out, "\n", 3)[1]
	if strings.Contains(header, "RELATIONS") {
		t.Errorf("RELATIONS is the first column to give way at 80 columns:\n%s", out)
	}
	if !strings.Contains(out, "columns hidden") {
		t.Errorf("the footer must say which columns were hidden:\n%s", out)
	}
}
