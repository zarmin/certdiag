package tui

import "github.com/zarmin/certdiag/certdiag_app/internal/certlib"

type navEntry struct {
	ref          certlib.ItemRef
	treeCursor   int
	treeOffset   int
	detailScroll int
}

type navHistory struct {
	back    []navEntry
	forward []navEntry
}

func (h *navHistory) push(entry navEntry) {
	h.back = append(h.back, entry)
	h.forward = nil
}

func (h *navHistory) goBack(current navEntry) (navEntry, bool) {
	if len(h.back) == 0 {
		return navEntry{}, false
	}
	h.forward = append(h.forward, current)
	last := h.back[len(h.back)-1]
	h.back = h.back[:len(h.back)-1]
	return last, true
}

func (h *navHistory) goForward(current navEntry) (navEntry, bool) {
	if len(h.forward) == 0 {
		return navEntry{}, false
	}
	h.back = append(h.back, current)
	last := h.forward[len(h.forward)-1]
	h.forward = h.forward[:len(h.forward)-1]
	return last, true
}

func (h *navHistory) canGoBack() bool {
	return len(h.back) > 0
}

func (h *navHistory) canGoForward() bool {
	return len(h.forward) > 0
}

func (h *navHistory) clear() {
	h.back = nil
	h.forward = nil
}
