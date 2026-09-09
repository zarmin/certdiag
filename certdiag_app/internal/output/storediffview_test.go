package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

const (
	diffFPA = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	diffFPB = "1122334455667788990011223344556677889900112233445566778899001122"
)

func storeDiffFixture() *certops.StoreDiffResult {
	return &certops.StoreDiffResult{
		SideA:  certops.StoreDiffSide{Spec: "os", Name: "System Roots", CertCount: 3},
		SideB:  certops.StoreDiffSide{Spec: "mozilla", Name: "Mozilla", CertCount: 2},
		Common: 1,
		OnlyInA: []certops.StoreDiffEntry{{
			Subject:     "CN=Corporate Root CA",
			Fingerprint: diffFPA,
			NotAfter:    time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC),
		}},
		Rotated: []certops.StoreDiffRotation{{
			Subject:       "CN=Rotated Root",
			FingerprintsA: []string{diffFPA},
			FingerprintsB: []string{diffFPB},
		}},
		Warnings: []string{"one profile was unreadable"},
	}
}

// The human view must render the digest in the format the user configured,
// while the structured output stays canonical hex.
func TestStoreDiffHumanHonoursFingerprintFormat(t *testing.T) {
	tests := []struct {
		format certlib.FingerprintFormat
		want   string
	}{
		{certlib.FingerprintHex, "aabbccddeeff0011..."},
		{certlib.FingerprintHexColon, "aa:bb:cc:dd:ee:ff:00:11..."},
		{certlib.FingerprintBase64, "qrvM3e7/ABE=..."},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			got := FormatStoreDiffHuman(storeDiffFixture(), tt.format)
			if !strings.Contains(got, tt.want) {
				t.Errorf("output missing %q\n%s", tt.want, got)
			}
		})
	}
}

// Truncation happens on byte boundaries, so a colon-separated digest never ends
// mid-byte.
func TestStoreDiffShortFPTruncatesOnByteBoundary(t *testing.T) {
	got := shortFP(diffFPA, certlib.FingerprintHexColon)
	trimmed := strings.TrimSuffix(got, "...")
	if strings.HasSuffix(trimmed, ":") {
		t.Errorf("digest %q ends mid-byte", got)
	}
	if n := len(strings.Split(trimmed, ":")); n != shortFPBytes {
		t.Errorf("got %d bytes, want %d (%q)", n, shortFPBytes, got)
	}
}

func TestStoreDiffShortFPKeepsShortDigestWhole(t *testing.T) {
	short := "aabbccdd"
	if got := shortFP(short, certlib.FingerprintHex); got != short {
		t.Errorf("got %q, want %q untruncated", got, short)
	}
}

// A/B alone forces the reader back to the header, so each bucket names the spec
// the user typed.
func TestStoreDiffHumanNamesTheStoreInBucketHeaders(t *testing.T) {
	got := FormatStoreDiffHuman(storeDiffFixture(), certlib.FingerprintHex)
	if !strings.Contains(got, "Only in A (os):") {
		t.Errorf("bucket header does not name side A\n%s", got)
	}
}

func TestStoreDiffHumanColorsExpiryAndHeaders(t *testing.T) {
	oldEnabled, oldNoColor := ColorsEnabled, color.NoColor
	ColorsEnabled, color.NoColor = true, false
	InitColors()
	defer func() {
		ColorsEnabled, color.NoColor = oldEnabled, oldNoColor
		InitColors()
	}()

	got := FormatStoreDiffHuman(storeDiffFixture(), certlib.FingerprintHex)
	if !strings.Contains(got, "\x1b[") {
		t.Errorf("expected ANSI styling in the human view\n%q", got)
	}
}

// Display format is display-only: JSON always carries canonical lowercase hex.
func TestStoreDiffJSONStaysCanonicalHex(t *testing.T) {
	var decoded storeDiffJSON
	if err := json.Unmarshal([]byte(FormatStoreDiffJSON(storeDiffFixture())), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.OnlyInA) != 1 || decoded.OnlyInA[0].Fingerprint != diffFPA {
		t.Fatalf("want canonical %q, got %+v", diffFPA, decoded.OnlyInA)
	}
	if len(decoded.Rotated) != 1 || decoded.Rotated[0].FingerprintsB[0] != diffFPB {
		t.Fatalf("rotated digest not canonical: %+v", decoded.Rotated)
	}
}

// Warnings reach stderr for humans; machine consumers read stdout only, so the
// structured output has to carry them too.
func TestStoreDiffJSONCarriesWarnings(t *testing.T) {
	var decoded storeDiffJSON
	if err := json.Unmarshal([]byte(FormatStoreDiffJSON(storeDiffFixture())), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Warnings) != 1 || decoded.Warnings[0] != "one profile was unreadable" {
		t.Errorf("warnings missing from JSON: %+v", decoded.Warnings)
	}
}

func TestStoreDiffHumanIdenticalStores(t *testing.T) {
	result := &certops.StoreDiffResult{
		SideA:     certops.StoreDiffSide{Spec: "os", Name: "System Roots", CertCount: 2},
		SideB:     certops.StoreDiffSide{Spec: "openssl", Name: "OpenSSL", CertCount: 2},
		Common:    2,
		Identical: true,
	}
	got := FormatStoreDiffHuman(result, certlib.FingerprintHex)
	if !strings.Contains(got, "Stores are identical: 2 common certificates") {
		t.Errorf("unexpected identical rendering\n%s", got)
	}
	if strings.Contains(got, "Only in A") {
		t.Errorf("identical stores must not print bucket sections\n%s", got)
	}
}
