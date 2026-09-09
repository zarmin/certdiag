package tui

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type nodeKey struct {
	containerIdx int
	itemIdx      int
}

type multiSelectModel struct {
	selected map[nodeKey]bool
}

func newMultiSelectModel() multiSelectModel {
	return multiSelectModel{
		selected: make(map[nodeKey]bool),
	}
}

func (ms *multiSelectModel) toggle(node TreeNode, allNodes []TreeNode) {
	if needsPassword(node) {
		return
	}

	if node.IsBundle {
		// Cascade: toggle all children with same ContainerIdx
		key := nodeKey{containerIdx: node.ContainerIdx, itemIdx: node.ItemIdx}
		selecting := !ms.selected[key]

		// Toggle the header itself
		if selecting {
			ms.selected[key] = true
		} else {
			delete(ms.selected, key)
		}

		// Toggle all children (iterate allNodes, not just visible)
		for _, n := range allNodes {
			if n.ContainerIdx == node.ContainerIdx && n.IsChild {
				childKey := nodeKey{containerIdx: n.ContainerIdx, itemIdx: n.ItemIdx}
				if selecting {
					ms.selected[childKey] = true
				} else {
					delete(ms.selected, childKey)
				}
			}
		}
		return
	}

	// Individual item toggle
	key := nodeKey{containerIdx: node.ContainerIdx, itemIdx: node.ItemIdx}
	if ms.selected[key] {
		delete(ms.selected, key)
	} else {
		ms.selected[key] = true
	}
}

func (ms *multiSelectModel) autoSelectChain(node TreeNode, allNodes []TreeNode, relIndex certlib.RelationIndex) string {
	if relIndex == nil {
		return "no relations available"
	}
	if node.Item == nil || node.Item.Type != certlib.ContentCertificate {
		return "auto-chain requires a certificate"
	}

	// Build nodeKey -> CertItem lookup for cert-identity dedup
	nodeItems := map[nodeKey]*certlib.CertItem{}
	for _, n := range allNodes {
		if n.Item != nil {
			nodeItems[nodeKey{containerIdx: n.ContainerIdx, itemIdx: n.ItemIdx}] = n.Item
		}
	}

	// Collect refs to select
	toSelect := map[nodeKey]bool{}

	// Start with current node
	toSelect[nodeKey{containerIdx: node.ContainerIdx, itemIdx: node.ItemIdx}] = true

	// Track seen cert identities to avoid selecting duplicate certs
	certSeen := map[[32]byte]bool{}
	if node.Item.Certificate != nil {
		certSeen[sha256.Sum256(node.Item.Certificate.Raw)] = true
	}

	// Follow signed_by outgoing chain recursively
	visited := map[certlib.ItemRef]bool{}
	var followChain func(ref certlib.ItemRef)
	followChain = func(ref certlib.ItemRef) {
		if visited[ref] {
			return
		}
		visited[ref] = true

		rels := relIndex[ref]
		for _, r := range rels {
			if r.Type == certlib.RelationSignedBy && r.Direction == certlib.DirectionOutgoing {
				peerKey := nodeKey{containerIdx: r.Peer.ContainerIdx, itemIdx: r.Peer.ItemIdx}
				if item, ok := nodeItems[peerKey]; ok && item.Certificate != nil {
					hash := sha256.Sum256(item.Certificate.Raw)
					if certSeen[hash] {
						continue
					}
					certSeen[hash] = true
				}
				toSelect[peerKey] = true
				followChain(r.Peer)
			}
		}
	}
	followChain(node.Ref)

	// Find matching key via key_cert_pair incoming relation
	rels := relIndex[node.Ref]
	for _, r := range rels {
		if r.Type == certlib.RelationKeyCert && r.Direction == certlib.DirectionIncoming {
			toSelect[nodeKey{containerIdx: r.Peer.ContainerIdx, itemIdx: r.Peer.ItemIdx}] = true
		}
	}

	// Select all found nodes
	count := 0
	for key := range toSelect {
		if !ms.selected[key] {
			// Verify node exists in allNodes and is not locked
			for _, n := range allNodes {
				if n.ContainerIdx == key.containerIdx && n.ItemIdx == key.itemIdx && !n.Locked {
					ms.selected[key] = true
					count++
					break
				}
			}
		}
	}

	return fmt.Sprintf("auto-selected %d items in chain", count)
}

func (ms *multiSelectModel) isSelected(node TreeNode) bool {
	key := nodeKey{containerIdx: node.ContainerIdx, itemIdx: node.ItemIdx}
	return ms.selected[key]
}

func (ms *multiSelectModel) count() int {
	n := 0
	for key := range ms.selected {
		// Skip bundle headers (itemIdx < 0)
		if key.itemIdx < 0 {
			continue
		}
		n++
	}
	return n
}

func (ms *multiSelectModel) clear() {
	ms.selected = make(map[nodeKey]bool)
}

func (ms *multiSelectModel) collectSelected(allNodes []TreeNode) []TreeNode {
	var result []TreeNode
	for _, n := range allNodes {
		// Skip bundle headers (ItemIdx < 0)
		if n.ItemIdx < 0 {
			continue
		}
		key := nodeKey{containerIdx: n.ContainerIdx, itemIdx: n.ItemIdx}
		if ms.selected[key] {
			result = append(result, n)
		}
	}
	return result
}

func (ms *multiSelectModel) collectFilePaths(allNodes []TreeNode) []string {
	seen := map[string]bool{}
	var paths []string
	for _, n := range allNodes {
		if n.ItemIdx < 0 {
			continue
		}
		key := nodeKey{containerIdx: n.ContainerIdx, itemIdx: n.ItemIdx}
		if !ms.selected[key] {
			continue
		}
		if n.Container == nil {
			continue
		}
		fp := n.Container.FilePath
		if !seen[fp] {
			seen[fp] = true
			paths = append(paths, fp)
		}
	}
	return paths
}

func (ms *multiSelectModel) itemsSummary(allNodes []TreeNode) string {
	selected := ms.collectSelected(allNodes)
	if len(selected) == 0 {
		return "(none)"
	}
	var lines []string
	for i, n := range selected {
		filename := filepath.Base(n.Container.FilePath)
		if n.Item != nil && n.Item.Alias != "" {
			filename = n.Item.Alias
		}
		line := fmt.Sprintf("%d. %s (%s)", i+1, filename, n.ContentType)
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
