# Captures

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) ·
[trust](trust.md) · [create and convert](create-and-convert.md) · pcap · [TUI](tui.md) ·
[config](config.md) · [scripting](scripting.md)

```sh
certdiag pcap capture.pcap                      # same as: pcap sessions
certdiag pcap sessions capture.pcap -d
certdiag pcap check capture.pcap                # extract the certificates and run the checks
certdiag pcap extract capture.pcap --target-dir ./out
certdiag pcap capture.pcap -f example.com       # filter sessions by substring
certdiag pcap capture.pcap -a                   # look for TLS anywhere in a stream (STARTTLS)
tcpdump -i eth0 -w - | certdiag pcap -          # a capture stream on stdin
```

pcap and pcapng are read without libpcap. `-a` / `--aggressive` hunts for TLS anywhere in a stream
rather than only at connection start, which is what a STARTTLS capture needs.

## TLS 1.3 and key logs

TLS 1.3 encrypts the Certificate message, so a passive capture cannot show the certificate.
certdiag reports the session as encrypted and says the certificate is not visible; it never guesses.
Hand it the session keys and it decrypts the handshake:

```sh
certdiag pcap check capture.pcap --keylog keys.txt
SSLKEYLOGFILE=keys.txt certdiag pcap check capture.pcap
```

Produce the key log on the client at capture time:

| Stack | How |
|---|---|
| curl, wget | `SSLKEYLOGFILE=keys.txt curl https://host` |
| Firefox, Chrome | set `SSLKEYLOGFILE` before launching |
| Go | `tls.Config.KeyLogWriter` |
| Node.js | `node --tls-keylog=keys.txt app.js` |
| Python | `SSLContext.keylog_filename = "keys.txt"` |
| OpenSSL `s_client` | `-keylogfile keys.txt` |
| Java (JSSE) | no native support; a key-logging agent such as `extract-tls-secrets`: `java -javaagent:extract-tls-secrets.jar=keys.txt -jar app.jar` |

## Live capture

```sh
sudo certdiag pcap live --iface eth0
sudo certdiag pcap live --iface eth0 --duration 30s
sudo certdiag pcap live --iface eth0 --count 1000
```

Linux only, AF_PACKET raw sockets, pure Go, needs `CAP_NET_RAW` or root. Stops on Ctrl-C or after
`--count` or `--duration`. On macOS and Windows, pipe a capture tool through stdin as above.

## The TLS proxy

```sh
certdiag proxy -l :8443 -t backend:443
certdiag proxy -l :8443 -t backend:443 --dump-dir ./captured
certdiag proxy -l :8443 -t backend:443 --ndjson       # or --multiyaml
```

A transparent TCP proxy for when you can control routing but cannot capture packets. It forwards
raw TCP bytes and parses the handshake as it passes; it never terminates or re-signs TLS, so the
client sees the real certificate and nothing warns. `--dump-dir` saves every intercepted
certificate.

Both views also exist in the TUI: `certdiag tui pcap capture.pcap` and
`certdiag tui proxy -l :8443 -t backend:443`.
