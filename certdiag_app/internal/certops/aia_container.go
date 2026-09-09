package certops

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// AIAContainerLabel names the container when everything in it was just fetched.
const AIAContainerLabel = "AIA fetched"

// AIAContainer turns fetched certificates into a container so they are ordinary
// rows: they get relations, chains, a trust verdict and can be saved. Saving
// the cross-signed root next to a served chain is precisely how a user builds
// the chain a client that does not chase AIA will accept.
//
// It is appended last so scanned files keep their container indices, which
// navigation, the saved column state and the check view all depend on.
func AIAContainer(res certlib.AIAResult) *certlib.CertContainer {
	if len(res.Fetched) == 0 {
		return nil
	}

	c := &certlib.CertContainer{
		FilePath: "(aia)",
		Label:    aiaContainerLabel(res),
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceAIA,
	}
	for _, f := range res.Fetched {
		if f.Cert == nil {
			continue
		}
		c.Items = append(c.Items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Alias:       f.Source.String(),
			Certificate: f.Cert,
			RawBytes:    f.Cert.Raw,
		})
	}
	for _, f := range res.Failures {
		c.ParseErrors = append(c.ParseErrors, fmt.Sprintf("%s: %s", f.URL, f.Reason))
	}
	return c
}

// aiaContainerLabel states the provenance. A certificate remembered from three
// weeks ago is a different claim from one fetched just now, so the label says
// which, with the date.
func aiaContainerLabel(res certlib.AIAResult) string {
	var fetched, cached int
	oldest := ""
	for _, f := range res.Fetched {
		if f.Source == certlib.AIASourceCached {
			cached++
			d := f.FetchedAt.Format("2006-01-02")
			if oldest == "" || d < oldest {
				oldest = d
			}
			continue
		}
		fetched++
	}

	switch {
	case cached == 0:
		return AIAContainerLabel
	case fetched == 0:
		return fmt.Sprintf("AIA cache (fetched %s)", oldest)
	default:
		return fmt.Sprintf("%s + cache (fetched %s)", AIAContainerLabel, oldest)
	}
}
