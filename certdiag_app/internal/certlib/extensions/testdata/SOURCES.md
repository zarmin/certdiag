# Extension corpus sources

Public X.509 certificates committed for the `extensions` package tests. Every file was
fetched on 2026-09-06 by the method given below and is stored unmodified (DER to PEM
conversion only, where noted). Certificates are public data published by their subjects
and CAs through TLS handshakes, Certificate Transparency logs and the Federal PKI
repository; no licence applies and none is claimed. They are here to exercise parsers,
not to assert trust: several are expired and that is intentional.

Extensions certdiag can create itself are not collected; the tests synthesise them with
`x509.CreateCertificate` / `ExtraExtensions`: TLS Feature (must-staple), Netscape cert type
and comment, Microsoft template name / info / application policies, OCSP No Check. No public
AD CS certificate is available to fetch, so the MS fixtures are synthetic by necessity.

Refresh rule: replace a file only when a test needs something the current one lacks; keep
the expired pair (the parser must cope with retired CT logs). Record the new fetch date here.

| File | Subject | Issuer | Not after | SHA-256 |
|---|---|---|---|---|
| `sct-dv-letsencrypt-2026.pem` | letsencrypt.org | YE2 | Dec  3 14:34:31 2026 GMT | `1f:c4:f6:97:ee:fa:30:22...` |
| `sct-final-radiantlock-2019.pem` | radiantlock.letsencrypt.org | Let's Encrypt Authority X3 | Aug 10 21:42:32 2019 GMT | `d3:a0:07:5b:37:9c:dd:f5...` |
| `precert-radiantlock-2019.pem` | radiantlock.letsencrypt.org | Let's Encrypt Authority X3 | Aug 10 21:42:32 2019 GMT | `78:71:16:9c:f0:a4:be:00...` |
| `qc-qwac-agenciatributaria-sectigo.pem` | agenciatributaria.gob.es | Sectigo Qualified Website Authentication CA R35 | Nov 17 23:59:59 2026 GMT | `d8:0e:7e:88:42:ef:81:01...` |
| `ev-globalsign.pem` | www.globalsign.com | GlobalSign GCC R3 EV TLS CA 2025 | Nov 18 07:56:05 2026 GMT | `54:2f:75:5c:b4:3d:c5:cc...` |
| `ev-dtrust-etsi.pem` | www.d-trust.net | D-TRUST SSL Class 3 CA 1 EV 2009 | Oct 17 16:41:11 2026 GMT | `5a:da:84:87:ba:d9:a6:52...` |
| `ov-bundesbank-telekom.pem` | bundesbank.de | Telekom Security ServerID OV Class 2 CA | Oct  6 23:59:59 2026 GMT | `21:d7:40:b1:a0:75:f9:09...` |
| `fpki-fbca-g4-from-certipath.pem` | Federal Bridge CA G4 | CertiPath Bridge CA - G3 | Apr 30 23:59:59 2027 GMT | `e7:6b:b2:28:dc:b0:cc:b3...` |
| `fpki-fbca-g4-from-fcpca-g2.pem` | Federal Bridge CA G4 | Federal Common Policy CA G2 | Dec  6 16:52:46 2029 GMT | `74:38:3c:a1:bb:64:8f:96...` |
| `fpki-fcpca-g2-root.pem` | Federal Common Policy CA G2 | Federal Common Policy CA G2 | Oct 14 13:35:12 2040 GMT | `5f:9a:ec:c2:46:16:b2:19...` |

## Per file

### `sct-dv-letsencrypt-2026.pem`

- Source: TLS handshake with letsencrypt.org:443 (openssl s_client)
- Subject: `CN=letsencrypt.org`
- Issuer: `C=US, O=Let's Encrypt, CN=YE2`
- Not after: Dec  3 14:34:31 2026 GMT
- SHA-256: `1f:c4:f6:97:ee:fa:30:22:d8:72:df:23:22:93:bd:da:76:24:c9:39:64:d7:78:a5:30:26:91:2d:9d:52:9a:53`
- Why: Embedded SCT list on current CT logs (log-ID naming), CA/B DV policy 2.23.140.1.2.1, AIA, current issuance. Refresh when the log IDs rotate out of the known-logs table.

### `sct-final-radiantlock-2019.pem`

- Source: crt.sh id 1485147627 (https://crt.sh/?d=1485147627)
- Subject: `CN=radiantlock.letsencrypt.org`
- Issuer: `C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3`
- Not after: Aug 10 21:42:32 2019 GMT
- SHA-256: `d3:a0:07:5b:37:9c:dd:f5:e3:58:cc:54:34:13:63:81:a5:a5:03:70:ef:c1:86:2d:e9:be:32:08:19:1d:ff:8a`
- Why: Final certificate of a real precert/final pair; SCTs reference retired 2019 logs, so the parser must handle unknown log IDs. Expired.

### `precert-radiantlock-2019.pem`

- Source: crt.sh id 1465354307 (https://crt.sh/?d=1465354307)
- Subject: `CN=radiantlock.letsencrypt.org`
- Issuer: `C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3`
- Not after: Aug 10 21:42:32 2019 GMT
- SHA-256: `78:71:16:9c:f0:a4:be:00:9c:d0:03:64:7f:95:b8:ca:0c:c0:4a:a5:7e:86:8e:76:1e:03:2e:2c:4c:11:c3:88`
- Why: The matching precertificate: critical CT poison extension (1.3.6.1.4.1.11129.2.4.3), no SCTs, same serial as the final. Expired.

### `qc-qwac-agenciatributaria-sectigo.pem`

- Source: TLS handshake with www.agenciatributaria.gob.es:443
- Subject: `serialNumber=Q2826000H, jurisdictionC=ES, businessCategory=Government Entity, C=ES, ST=Madrid, O=Agencia Estatal de Administración Tributaria, organizationIdentifier=NTRES-Q2826000H, CN=agenciatributaria.gob.es`
- Issuer: `C=ES, O=Sectigo (Europe) SL, CN=Sectigo Qualified Website Authentication CA R35`
- Not after: Nov 17 23:59:59 2026 GMT
- SHA-256: `d8:0e:7e:88:42:ef:81:01:f1:5d:bf:11:36:aa:df:52:5a:05:71:05:b2:45:f6:0d:b7:e9:d0:ce:fe:78:0a:35`
- Why: eIDAS qualified website certificate (QWAC) from Sectigo (Europe): qcStatements (1.3.6.1.5.5.7.1.3), ETSI QCP-w policy 0.4.0.194112.1.4, EV 2.23.140.1.1 and two Sectigo policy OIDs in one extension.

### `ev-globalsign.pem`

- Source: TLS handshake with www.globalsign.com:443
- Subject: `businessCategory=Private Organization, serialNumber=578611, jurisdictionC=US, jurisdictionST=New Hampshire, C=US, ST=New Hampshire, L=Portsmouth, street=2 International Drive, Suite 150, O=GMO GlobalSign, Inc., CN=www.globalsign.com`
- Issuer: `C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R3 EV TLS CA 2025`
- Not after: Nov 18 07:56:05 2026 GMT
- SHA-256: `54:2f:75:5c:b4:3d:c5:cc:8e:7a:7e:71:8c:98:e1:59:19:46:f7:b4:56:8c:ad:b5:a2:9e:e8:21:7b:9c:97:5e`
- Why: EV policy 2.23.140.1.1 next to two GlobalSign policy OIDs; three policies in one extension.

### `ev-dtrust-etsi.pem`

- Source: TLS handshake with www.d-trust.net:443
- Subject: `jurisdictionC=DE, jurisdictionST=Berlin, jurisdictionL=Berlin, businessCategory=Private Organization, serialNumber=HRB 74346 B, C=DE, ST=Berlin, L=Berlin, postalCode=10969, street=Kommandantenstr. 15, O=D-Trust GmbH, CN=www.d-trust.net`
- Issuer: `C=DE, O=D-Trust GmbH, CN=D-TRUST SSL Class 3 CA 1 EV 2009`
- Not after: Oct 17 16:41:11 2026 GMT
- SHA-256: `5a:da:84:87:ba:d9:a6:52:a4:a8:17:57:ef:f7:55:65:dc:8d:47:a8:dd:a1:15:27:db:db:42:6f:e6:c0:4d:08`
- Why: EV with the ETSI EVCP policy 0.4.0.2042.1.4 and a CA policy OID; jurisdiction* subject attributes.

### `ov-bundesbank-telekom.pem`

- Source: TLS handshake with bundesbank.de:443
- Subject: `C=DE, ST=Hessen, L=Frankfurt am Main, O=Deutsche Bundesbank, CN=bundesbank.de`
- Issuer: `C=DE, O=Deutsche Telekom Security GmbH, CN=Telekom Security ServerID OV Class 2 CA`
- Not after: Oct  6 23:59:59 2026 GMT
- SHA-256: `21:d7:40:b1:a0:75:f9:09:4c:30:0f:5c:82:37:6d:b6:72:0f:6c:c3:ab:b4:67:8e:10:29:34:98:35:eb:74:50`
- Why: OV policy 2.23.140.1.2.2; the plain case for policy naming.

### `fpki-fbca-g4-from-certipath.pem`

- Source: http://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c (first certificate)
- Subject: `C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA G4`
- Issuer: `C=US, O=CertiPath, OU=Certification Authorities, CN=CertiPath Bridge CA - G3`
- Not after: Apr 30 23:59:59 2027 GMT
- SHA-256: `e7:6b:b2:28:dc:b0:cc:b3:12:b2:00:5b:45:fb:d5:e0:33:1b:ef:68:d2:9b:85:67:e8:ac:cd:19:cd:9b:6e:7b`
- Why: Real cross-certificate carrying critical Name Constraints (excluded DirName subtrees), critical Policy Constraints (requireExplicitPolicy 0, inhibitPolicyMapping 2), Policy Mappings, Inhibit anyPolicy and Subject Information Access in one certificate.

### `fpki-fbca-g4-from-fcpca-g2.pem`

- Source: http://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c (third certificate)
- Subject: `C=US, O=U.S. Government, OU=FPKI, CN=Federal Bridge CA G4`
- Issuer: `C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA G2`
- Not after: Dec  6 16:52:46 2029 GMT
- SHA-256: `74:38:3c:a1:bb:64:8f:96:ef:e9:e6:ec:ad:b5:a8:a3:59:e7:df:9b:a2:62:ef:7c:02:bd:00:4e:ab:38:95:f4`
- Why: Cross-certificate issued by the Federal Common Policy CA G2: Policy Mappings, Policy Constraints, Inhibit anyPolicy, SIA. With the root below it forms a real policy-mapped chain.

### `fpki-fcpca-g2-root.pem`

- Source: http://repo.fpki.gov/fcpca/fcpcag2.crt (DER, converted to PEM)
- Subject: `C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA G2`
- Issuer: `C=US, O=U.S. Government, OU=FPKI, CN=Federal Common Policy CA G2`
- Not after: Oct 14 13:35:12 2040 GMT
- SHA-256: `5f:9a:ec:c2:46:16:b2:19:13:72:60:0d:d8:0f:6d:d3:20:c8:ca:5a:0c:eb:7f:09:c9:85:eb:f0:69:69:34:fc`
- Why: Self-signed root that issued the certificate above; lets the chain tests run against a genuine bridge-PKI path.
