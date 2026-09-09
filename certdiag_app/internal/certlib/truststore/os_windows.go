//go:build windows

package truststore

import (
	"crypto/x509"
	"fmt"
	"syscall"
	"unsafe"
)

var windowsStores = []struct {
	name    string
	display string
}{
	{"ROOT", "Windows Trusted Root CAs"},
	{"CA", "Windows Intermediate CAs"},
	{"MY", "Windows Personal Certificates"},
}

func ReadOSStore() ([]StoreContents, error) {
	var stores []StoreContents

	for _, ws := range windowsStores {
		certs, err := readWindowsStore(ws.name)
		if err != nil {
			continue
		}
		if len(certs) == 0 {
			continue
		}
		stores = append(stores, StoreContents{
			Info: StoreInfo{
				Type:      StoreTypeOS,
				Name:      ws.display,
				Path:      ws.name,
				CertCount: len(certs),
			},
			Certificates: certs,
		})
	}

	if len(stores) == 0 {
		return nil, fmt.Errorf("failed to read any Windows certificate stores")
	}

	var allCerts []*x509.Certificate
	for _, s := range stores {
		allCerts = append(allCerts, s.Certificates...)
	}
	trustMap := LoadTrustSettings(allCerts)

	if trustMap != nil {
		for i := range stores {
			stores[i].TrustMap = make(map[string]CertTrust)
			for _, cert := range stores[i].Certificates {
				fp := CertFingerprint(cert)
				if t, ok := trustMap[fp]; ok {
					stores[i].TrustMap[fp] = t
				}
			}
		}
	}

	return stores, nil
}

func DiscoverOSStores() []StoreInfo {
	var stores []StoreInfo

	for _, ws := range windowsStores {
		certs, err := readWindowsStore(ws.name)
		if err != nil || len(certs) == 0 {
			continue
		}
		stores = append(stores, StoreInfo{
			Type:      StoreTypeOS,
			Name:      ws.display,
			Path:      ws.name,
			CertCount: len(certs),
		})
	}

	return stores
}

func readWindowsStore(storeName string) ([]*x509.Certificate, error) {
	storeNamePtr, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, err
	}

	handle, err := syscall.CertOpenSystemStore(0, storeNamePtr)
	if err != nil {
		return nil, fmt.Errorf("CertOpenSystemStore(%s): %w", storeName, err)
	}
	defer syscall.CertCloseStore(handle, 0)

	var certs []*x509.Certificate
	var ctx *syscall.CertContext

	for {
		ctx, err = syscall.CertEnumCertificatesInStore(handle, ctx)
		if err != nil {
			break
		}

		buf := (*[1 << 20]byte)(unsafe.Pointer(ctx.EncodedCert))[:ctx.Length:ctx.Length]
		// Clone before parsing: the CERT_CONTEXT buffer is freed/reused by the
		// next CertEnumCertificatesInStore / CertCloseStore, and ParseCertificate
		// keeps subslices of its input, so the parsed cert must not alias buf.
		cert, err := parseCertCopy(buf)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}
