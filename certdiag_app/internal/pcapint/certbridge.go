package pcapint

import (
	"crypto/x509"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

func ToCertStore(sessions []*session.Session) *certlib.CertStore {
	store := certlib.NewCertStore()

	for i, s := range sessions {
		if s.Certificates == nil || len(s.Certificates.Certificates) == 0 {
			continue
		}

		sni := s.SNI()
		label := sni
		if label == "" {
			label = s.ServerAddr
		}

		container := certlib.CertContainer{
			FilePath: fmt.Sprintf("pcap:session#%d:%s->%s", i+1, s.ClientAddr, s.ServerAddr),
			Source:   certlib.SourcePcap,
		}

		for _, der := range s.Certificates.Certificates {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			container.Items = append(container.Items, certlib.CertItem{
				Type:        certlib.ContentCertificate,
				Certificate: cert,
				RawBytes:    der,
			})
		}

		if len(container.Items) > 0 {
			store.AddContainer(container)
		}
	}

	return store
}
