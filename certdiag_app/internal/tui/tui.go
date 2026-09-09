package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

type TUIOptions struct {
	StatusMessage  string
	SubjectOrg     string
	SubjectCountry string
	ActiveCols     []string
	ConfigPath     string
	PathDisplay    string
	SaveColumns    func(cols []string) error
	SaveOptions    func(opts SavedOptions) error
	LockedFlags    map[string]bool
	DisabledChecks []string
	KeyDefaults    certlib.KeyGenOptions
	DefaultDays    int
	DefaultCADays  int

	InitialPcapFile    string
	InitialPcapFilter  string
	InitialPcapAggr    bool
	InitialProxyListen string
	InitialProxyTarget string
	InitialProxyFilter string
	InitialProxyAggr   bool

	StoreCols         []string
	StoreGrouping     string
	FingerprintFormat string
	SaveStoreOptions  func(cols []string, grouping string) error
	InitialTrustStore bool
	InitialStoreFiles []string
	TrustStoreLoader  func(certops.StoreLoadAllOptions) (*certops.StoreLoadAllResult, error)
	// AIACache is set when the user enabled caching. Nil means fetched
	// certificates are used for this run and then forgotten.
	AIACache certlib.AIACache
	// BundleDir is where refreshed root snapshots are installed. Empty means
	// only the compiled-in snapshots are used.
	BundleDir string
}

type SavedOptions struct {
	Recursive         bool
	MaxDepth          int
	FileSignatureScan bool
	AutoDiscover      bool
	PathDisplay       string
	FingerprintFormat string
}

func Run(path string, scanOpts certlib.ScanOptions, discover bool, opts output.OutputOptions, tuiOpts TUIOptions) error {
	model := NewRootModel(path, scanOpts, discover, opts, tuiOpts)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
