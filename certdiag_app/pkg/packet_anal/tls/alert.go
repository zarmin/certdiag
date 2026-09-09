package tls

import "fmt"

type AlertLevel uint8

const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
)

func (l AlertLevel) String() string {
	switch l {
	case AlertLevelWarning:
		return "warning"
	case AlertLevelFatal:
		return "fatal"
	default:
		return fmt.Sprintf("unknown(%d)", l)
	}
}

type AlertDescription uint8

const (
	AlertCloseNotify            AlertDescription = 0
	AlertUnexpectedMessage      AlertDescription = 10
	AlertBadRecordMAC           AlertDescription = 20
	AlertHandshakeFailure       AlertDescription = 40
	AlertBadCertificate         AlertDescription = 42
	AlertUnsupportedCertificate AlertDescription = 43
	AlertCertificateRevoked     AlertDescription = 44
	AlertCertificateExpired     AlertDescription = 45
	AlertCertificateUnknown     AlertDescription = 46
	AlertIllegalParameter       AlertDescription = 47
	AlertUnknownCA              AlertDescription = 48
	AlertAccessDenied           AlertDescription = 49
	AlertDecodeError            AlertDescription = 50
	AlertProtocolVersion        AlertDescription = 70
	AlertInsufficientSecurity   AlertDescription = 71
	AlertInternalError          AlertDescription = 80
	AlertInappropriateFallback  AlertDescription = 86
	AlertUserCanceled           AlertDescription = 90
	AlertMissingExtension       AlertDescription = 109
	AlertUnrecognizedName       AlertDescription = 112
	AlertCertificateRequired    AlertDescription = 116
)

var alertNames = map[AlertDescription]string{
	AlertCloseNotify:            "close_notify",
	AlertUnexpectedMessage:      "unexpected_message",
	AlertBadRecordMAC:           "bad_record_mac",
	AlertHandshakeFailure:       "handshake_failure",
	AlertBadCertificate:         "bad_certificate",
	AlertUnsupportedCertificate: "unsupported_certificate",
	AlertCertificateRevoked:     "certificate_revoked",
	AlertCertificateExpired:     "certificate_expired",
	AlertCertificateUnknown:     "certificate_unknown",
	AlertIllegalParameter:       "illegal_parameter",
	AlertUnknownCA:              "unknown_ca",
	AlertAccessDenied:           "access_denied",
	AlertDecodeError:            "decode_error",
	AlertProtocolVersion:        "protocol_version",
	AlertInsufficientSecurity:   "insufficient_security",
	AlertInternalError:          "internal_error",
	AlertInappropriateFallback:  "inappropriate_fallback",
	AlertUserCanceled:           "user_canceled",
	AlertMissingExtension:       "missing_extension",
	AlertUnrecognizedName:       "unrecognized_name",
	AlertCertificateRequired:    "certificate_required",
}

func (d AlertDescription) String() string {
	if name, ok := alertNames[d]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", d)
}

type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

func ParseAlert(data []byte) (Alert, error) {
	if len(data) < 2 {
		return Alert{}, ErrTruncated
	}
	return Alert{
		Level:       AlertLevel(data[0]),
		Description: AlertDescription(data[1]),
	}, nil
}
