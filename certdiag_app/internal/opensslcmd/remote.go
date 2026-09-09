package opensslcmd

import (
	"strconv"
	"strings"
)

// RemoteSpec describes a remote TLS endpoint for the s_client equivalent.
type RemoteSpec struct {
	Host       string
	Port       int
	SNI        string
	DisableSNI bool
	Starttls   string
	ShowCerts  bool
}

// RemoteFetch returns the openssl s_client command that connects to a remote
// endpoint the way certdiag remote fetch does.
func RemoteFetch(spec RemoteSpec) Command {
	port := spec.Port
	if port == 0 {
		port = 443
	}
	// An IPv6 literal must be bracketed in -connect host:port.
	host := spec.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	c := Command{Tool: ToolOpenSSL, Args: []string{"s_client", "-connect", host + ":" + strconv.Itoa(port)}}

	if spec.DisableSNI {
		c.Args = append(c.Args, "-noservername")
	} else {
		sni := spec.SNI
		if sni == "" {
			sni = spec.Host
		}
		c.Args = append(c.Args, "-servername", sni)
	}
	if spec.Starttls != "" {
		c.Args = append(c.Args, "-starttls", spec.Starttls)
	}
	if spec.ShowCerts {
		c.Args = append(c.Args, "-showcerts")
	}
	c.Notes = append(c.Notes, "s_client stays connected; append </dev/null to close the connection after the handshake")
	return c
}
