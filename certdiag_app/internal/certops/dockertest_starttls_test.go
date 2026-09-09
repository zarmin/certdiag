//go:build dockertest

package certops

import (
	"testing"
)

func TestDockerStarttls_SMTP(t *testing.T) {
	requireDockerAvailable(t)
	requireSMTPReady(t, portSMTP)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portSMTP)},
		Starttls: "smtp",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("SMTP STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from SMTP STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}

func TestDockerStarttls_IMAP(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceResponds(t, portIMAP)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portIMAP)},
		Starttls: "imap",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("IMAP STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from IMAP STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}

func TestDockerStarttls_POP3(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceResponds(t, portPOP3)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portPOP3)},
		Starttls: "pop3",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("POP3 STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from POP3 STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}

func TestDockerStarttls_LDAP(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portLDAP)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portLDAP)},
		Starttls: "ldap",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("LDAP STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from LDAP STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}

func TestDockerStarttls_PostgreSQL(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portPostgreSQL)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portPostgreSQL)},
		Starttls: "postgres",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("PostgreSQL STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from PostgreSQL STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}

func TestDockerStarttls_MySQL(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portMySQL)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  []string{dockerTarget(portMySQL)},
		Starttls: "mysql",
		Timeout:  dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("MySQL STARTTLS error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least 1 cert from MySQL STARTTLS")
	}
	if tr.Connection == nil || tr.Connection.TLSVersion == "" {
		t.Error("expected TLS version in connection info")
	}
}
