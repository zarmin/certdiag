package tls

import (
	"encoding/binary"
)

// Extension type codes
const (
	ExtServerName        uint16 = 0
	ExtSupportedGroups   uint16 = 10
	ExtSignatureAlgs     uint16 = 13
	ExtALPN              uint16 = 16
	ExtSupportedVersions uint16 = 43
	ExtKeyShare          uint16 = 51
)

type Extension struct {
	Type uint16
	Data []byte
}

// ParseExtensions parses a TLS extensions block.
// The input should start at the extensions length field (2 bytes).
func ParseExtensions(data []byte) ([]Extension, error) {
	if len(data) < 2 {
		return nil, nil
	}
	extLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < extLen {
		return nil, ErrTruncated
	}
	data = data[:extLen]

	var exts []Extension
	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[:2])
		extDataLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < extDataLen {
			return exts, ErrTruncated
		}
		extData := make([]byte, extDataLen)
		copy(extData, data[:extDataLen])
		exts = append(exts, Extension{Type: extType, Data: extData})
		data = data[extDataLen:]
	}
	return exts, nil
}

// ExtractSNI extracts the server name from an SNI extension's data.
func ExtractSNI(extData []byte) string {
	// SNI extension format:
	// ServerNameList length (2 bytes)
	//   ServerNameType (1 byte, 0 = hostname)
	//   HostName length (2 bytes)
	//   HostName (variable)
	if len(extData) < 5 {
		return ""
	}
	// listLen := binary.BigEndian.Uint16(extData[:2])
	extData = extData[2:]

	for len(extData) >= 3 {
		nameType := extData[0]
		nameLen := int(binary.BigEndian.Uint16(extData[1:3]))
		extData = extData[3:]
		if len(extData) < nameLen {
			return ""
		}
		if nameType == 0 { // host_name
			return string(extData[:nameLen])
		}
		extData = extData[nameLen:]
	}
	return ""
}

// ExtractSupportedVersions extracts version codes from a supported_versions extension.
// In ClientHello, it's a list; in ServerHello, it's a single value.
func ExtractSupportedVersions(extData []byte, isServerHello bool) []Version {
	if isServerHello {
		// ServerHello: just 2 bytes (selected version)
		if len(extData) < 2 {
			return nil
		}
		code := binary.BigEndian.Uint16(extData[:2])
		return []Version{VersionFromCode(code)}
	}

	// ClientHello: 1-byte length prefix + list of 2-byte version codes
	if len(extData) < 1 {
		return nil
	}
	listLen := int(extData[0])
	extData = extData[1:]
	if len(extData) < listLen {
		return nil
	}

	var versions []Version
	for i := 0; i+1 < listLen; i += 2 {
		code := binary.BigEndian.Uint16(extData[i : i+2])
		versions = append(versions, VersionFromCode(code))
	}
	return versions
}

// ExtractALPN extracts protocol names from an ALPN extension.
func ExtractALPN(extData []byte) []string {
	if len(extData) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	extData = extData[2:]
	if len(extData) < listLen {
		return nil
	}
	extData = extData[:listLen]

	var protocols []string
	for len(extData) > 0 {
		pLen := int(extData[0])
		extData = extData[1:]
		if len(extData) < pLen {
			break
		}
		protocols = append(protocols, string(extData[:pLen]))
		extData = extData[pLen:]
	}
	return protocols
}

// ExtractSupportedGroups extracts named group IDs from a supported_groups extension.
func ExtractSupportedGroups(extData []byte) []uint16 {
	if len(extData) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	extData = extData[2:]
	if len(extData) < listLen {
		return nil
	}

	var groups []uint16
	for i := 0; i+1 < listLen; i += 2 {
		groups = append(groups, binary.BigEndian.Uint16(extData[i:i+2]))
	}
	return groups
}

// ExtractSignatureAlgorithms extracts signature algorithm IDs from the extension.
func ExtractSignatureAlgorithms(extData []byte) []uint16 {
	if len(extData) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	extData = extData[2:]
	if len(extData) < listLen {
		return nil
	}

	var algs []uint16
	for i := 0; i+1 < listLen; i += 2 {
		algs = append(algs, binary.BigEndian.Uint16(extData[i:i+2]))
	}
	return algs
}
