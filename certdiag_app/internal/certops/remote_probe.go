package certops

import (
	"context"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type ProbeRemoteOptions struct {
	Target     string
	Hostname   string
	DisableSNI bool
	Starttls   string
	Timeout    time.Duration
	IPv4Only   bool
	IPv6Only   bool
}

type ProbeRemoteResult struct {
	Target string
	Probe  *certlib.ProbeResult
	Error  string
}

func ProbeRemoteTLS(opts ProbeRemoteOptions) (*ProbeRemoteResult, error) {
	if opts.Target == "" {
		return nil, &OperationError{Op: "remote-probe", Message: "no target specified"}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	starttls, err := certlib.ParseStarttlsProtocol(opts.Starttls)
	if err != nil {
		return nil, &OperationError{Op: "remote-probe", Message: err.Error()}
	}

	target, err := certlib.ParseTarget(opts.Target)
	if err != nil {
		return nil, &OperationError{Op: "remote-probe", Message: err.Error()}
	}

	if opts.Hostname != "" {
		target.SNI = opts.Hostname
	}
	if opts.DisableSNI {
		target.SNI = ""
	}

	ctx := context.Background()
	probeResult, err := certlib.ProbeServer(ctx, target, starttls, opts.Timeout, opts.IPv4Only, opts.IPv6Only)
	if err != nil {
		return &ProbeRemoteResult{
			Target: target.Address(),
			Error:  err.Error(),
		}, nil
	}

	return &ProbeRemoteResult{
		Target: target.Address(),
		Probe:  &probeResult,
	}, nil
}
