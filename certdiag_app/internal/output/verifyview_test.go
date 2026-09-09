package output

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"gopkg.in/yaml.v3"
)

func verifyChainFixture(t *testing.T) (leaf, root *x509.Certificate) {
	t.Helper()
	caKey := mustGenECKey(t)
	root = mustSelfSignedCert(t, caKey)
	leaf = mustLeafCert(t, mustGenECKey(t), root, caKey)
	return leaf, root
}

func TestFormatVerifyHuman_Trusted(t *testing.T) {
	leaf, root := verifyChainFixture(t)

	out := FormatVerifyHuman(truststore.VerifyResult{
		Trusted:     true,
		Chain:       []*x509.Certificate{leaf, root},
		TrustAnchor: root,
		Store:       truststore.StoreInfo{Type: truststore.StoreTypeOS, Name: "OS Trust Store"},
	})

	if !strings.Contains(out, "TRUSTED") {
		t.Errorf("expected a TRUSTED verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "Trust anchor") {
		t.Errorf("expected the trust anchor line, got:\n%s", out)
	}
}

func TestFormatVerifyHuman_ChainInIssuanceOrder(t *testing.T) {
	leaf, root := verifyChainFixture(t)

	out := FormatVerifyHuman(truststore.VerifyResult{
		Trusted:     true,
		Chain:       []*x509.Certificate{leaf, root},
		TrustAnchor: root,
	})

	// Project-wide rule: chains render root first (who signed whom).
	rootIdx := strings.Index(out, "[Root]")
	leafIdx := strings.Index(out, "[Leaf]")
	if rootIdx == -1 || leafIdx == -1 {
		t.Fatalf("expected both Root and Leaf labels, got:\n%s", out)
	}
	if rootIdx > leafIdx {
		t.Errorf("chain must be in issuance order (root first), got:\n%s", out)
	}
}

func TestFormatVerifyHuman_NotTrustedShowsReason(t *testing.T) {
	leaf, _ := verifyChainFixture(t)

	out := FormatVerifyHuman(truststore.VerifyResult{
		Trusted: false,
		Chain:   []*x509.Certificate{leaf},
		Error:   errors.New("x509: certificate signed by unknown authority"),
		Reason:  "unknown authority -- no CA in the trust store issued this certificate",
	})

	if !strings.Contains(out, "NOT TRUSTED") {
		t.Errorf("expected a NOT TRUSTED verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "unknown authority") {
		t.Errorf("expected the reason, got:\n%s", out)
	}
}

func TestFormatVerifyHuman_Suggestions(t *testing.T) {
	out := FormatVerifyHuman(truststore.VerifyResult{
		Trusted:     false,
		Reason:      "unknown authority",
		Suggestions: []string{"Check for a missing intermediate", "Use --file for a private CA"},
	})

	if !strings.Contains(out, "missing intermediate") {
		t.Errorf("expected suggestions rendered, got:\n%s", out)
	}
}

func TestFormatVerifyHuman_NoSuggestionsSectionWhenEmpty(t *testing.T) {
	out := FormatVerifyHuman(truststore.VerifyResult{
		Trusted: true,
		Store:   truststore.StoreInfo{Name: "OS Trust Store"},
	})

	if strings.Contains(strings.ToLower(out), "suggestion") {
		t.Errorf("did not expect a suggestions section, got:\n%s", out)
	}
}

func TestFormatVerifyHuman_EmptyResultDoesNotPanic(t *testing.T) {
	out := FormatVerifyHuman(truststore.VerifyResult{})
	if out == "" {
		t.Error("expected some output even for an empty result")
	}
}

func TestFormatVerifyJSON(t *testing.T) {
	leaf, root := verifyChainFixture(t)

	out, err := FormatVerifyJSON(truststore.VerifyResult{
		Trusted:     true,
		Chain:       []*x509.Certificate{leaf, root},
		TrustAnchor: root,
		Store:       truststore.StoreInfo{Type: truststore.StoreTypeJava, Name: "Java 21"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("must be valid JSON: %v\n%s", err, out)
	}
	if _, ok := parsed["trusted"]; !ok {
		t.Errorf("expected a 'trusted' field in:\n%s", out)
	}
}

func TestFormatVerifyJSON_NotTrustedCarriesReason(t *testing.T) {
	out, err := FormatVerifyJSON(truststore.VerifyResult{
		Trusted: false,
		Reason:  "hostname mismatch",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "hostname mismatch") {
		t.Errorf("expected the reason in JSON, got:\n%s", out)
	}
}

func TestFormatVerifyYAML(t *testing.T) {
	leaf, root := verifyChainFixture(t)

	out := FormatVerifyYAML(truststore.VerifyResult{
		Trusted:     true,
		Chain:       []*x509.Certificate{leaf, root},
		TrustAnchor: root,
	})

	var parsed any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("must be valid YAML: %v\n%s", err, out)
	}
}
