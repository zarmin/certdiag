package certops

import (
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// RemoteCertStore turns fetched remote results into a CertStore, so the shared
// pipeline - relations, chains, trust, the renderers, the TUI tree - treats a
// served chain exactly like a file. Everything a certificate needs lives in the
// store; the connection metadata stays on TargetFetchResult and is looked up by
// container index, because certlib must stay ignorant of TLS sessions.
//
// One container per target. Per-IP containers would need FetchRemoteCert to
// retain a chain per resolved address, which it does not: MultiIPInfo carries
// only the address list and an "all identical" flag.
func RemoteCertStore(result *FetchRemoteCertResult) *certlib.CertStore {
	store := certlib.NewCertStore()
	if result == nil {
		return store
	}
	for i := range result.TargetResults {
		store.AddContainer(RemoteContainer(&result.TargetResults[i]))
	}
	return store
}

// RemoteContainer builds the container for one target.
func RemoteContainer(tr *TargetFetchResult) certlib.CertContainer {
	c := certlib.CertContainer{
		FilePath: tr.Target,
		Label:    remoteContainerLabel(tr),
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceRemote,
	}

	if tr.Error != "" {
		// A target that failed reads like an unreadable file: the row is there,
		// carrying the reason, rather than silently missing.
		c.ParseErrors = []string{tr.Error}
		return c
	}

	for _, ci := range tr.Certs {
		if ci.Cert == nil || ci.Cert.Certificate == nil {
			continue
		}
		item := *ci.Cert
		item.Alias = ci.Role
		c.Items = append(c.Items, item)
	}
	return c
}

// remoteContainerLabel names the row: the target plus the negotiated connection,
// which is the context a served chain is read in.
func remoteContainerLabel(tr *TargetFetchResult) string {
	if tr.Connection == nil {
		return tr.Target
	}
	parts := []string{tr.Target}
	if tr.Connection.TLSVersion != "" {
		parts = append(parts, tr.Connection.TLSVersion)
	}
	if tr.Connection.CipherSuite != "" {
		parts = append(parts, tr.Connection.CipherSuite)
	}
	return strings.Join(parts, "  ")
}

// RemoteStoreOptions builds the render options for a remote store: relations and
// chains, so the served order can be checked against who actually signed whom.
func RemoteStoreOptions(store *certlib.CertStore) (relations certlib.RelationIndex, chains map[certlib.ItemRef][]certlib.ItemRef) {
	index, chains, _ := RemoteStoreChains(store)
	return index, chains
}

// RemoteStoreChains additionally returns the reverse index, so an intermediate
// in a served chain can show its place in it.
func RemoteStoreChains(store *certlib.CertStore) (certlib.RelationIndex, map[certlib.ItemRef][]certlib.ItemRef, map[certlib.ItemRef][][]certlib.ItemRef) {
	if store == nil || store.TotalItems() < 2 {
		return nil, nil, nil
	}
	rels := certlib.DetectRelations(store)
	store.Relations = rels
	index := certlib.BuildRelationIndex(rels, store)
	alts := certlib.AssembleChainAlternatives(index, store)
	return index, certlib.FirstChains(alts), certlib.ChainsContaining(alts)
}
