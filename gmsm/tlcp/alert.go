package tlcp

import "strconv"

type alert uint8

const (
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify                  alert = 0
	alertUnexpectedMessage            alert = 10
	alertBadRecordMAC                 alert = 20
	alertDecryptionFailed             alert = 21
	alertRecordOverflow               alert = 22
	alertDecompressionFailure         alert = 30
	alertHandshakeFailure             alert = 40
	alertBadCertificate               alert = 42
	alertUnsupportedCertificate       alert = 43
	alertCertificateRevoked           alert = 44
	alertCertificateExpired           alert = 45
	alertCertificateUnknown           alert = 46
	alertIllegalParameter             alert = 47
	alertUnknownCA                    alert = 48
	alertAccessDenied                 alert = 49
	alertDecodeError                  alert = 50
	alertDecryptError                 alert = 51
	alertExportRestriction            alert = 60
	alertProtocolVersion              alert = 70
	alertInsufficientSecurity         alert = 71
	alertInternalError                alert = 80
	alertInappropriateFallback        alert = 86
	alertUserCanceled                 alert = 90
	alertNoRenegotiation              alert = 100
	alertMissingExtension             alert = 109
	alertUnsupportedExtension         alert = 110
	alertCertificateUnobtainable      alert = 111
	alertUnrecognizedName             alert = 112
	alertBadCertificateStatusResponse alert = 113
	alertBadCertificateHashValue      alert = 114
	alertUnknownPSKIdentity           alert = 115
	alertCertificateRequired          alert = 116
	alertNoApplicationProtocol        alert = 120
	alertUnsupportedSite2site         alert = 200
	alertNoArea                       alert = 201
	alertUnsupportedAreaType          alert = 202
	alertBadIbcParam                  alert = 203
	alertUnsupportedIbcParam          alert = 204
	alertIdentityNeed                 alert = 205
)

var alertText = map[alert]string{
	alertCloseNotify:                  "close notify",
	alertUnexpectedMessage:            "unexpected message",
	alertBadRecordMAC:                 "bad record MAC",
	alertDecryptionFailed:             "decryption failed",
	alertRecordOverflow:               "record overflow",
	alertDecompressionFailure:         "decompression failure",
	alertHandshakeFailure:             "handshake failure",
	alertBadCertificate:               "bad certificate",
	alertUnsupportedCertificate:       "unsupported certificate",
	alertCertificateRevoked:           "revoked certificate",
	alertCertificateExpired:           "expired certificate",
	alertCertificateUnknown:           "unknown certificate",
	alertIllegalParameter:             "illegal parameter",
	alertUnknownCA:                    "unknown certificate authority",
	alertAccessDenied:                 "access denied",
	alertDecodeError:                  "error decoding message",
	alertDecryptError:                 "error decrypting message",
	alertExportRestriction:            "export restriction",
	alertProtocolVersion:              "protocol version not supported",
	alertInsufficientSecurity:         "insufficient security level",
	alertInternalError:                "internal error",
	alertInappropriateFallback:        "inappropriate fallback",
	alertUserCanceled:                 "user canceled",
	alertNoRenegotiation:              "no renegotiation",
	alertMissingExtension:             "missing extension",
	alertUnsupportedExtension:         "unsupported extension",
	alertCertificateUnobtainable:      "certificate unobtainable",
	alertUnrecognizedName:             "unrecognized name",
	alertBadCertificateStatusResponse: "bad certificate status response",
	alertBadCertificateHashValue:      "bad certificate hash value",
	alertUnknownPSKIdentity:           "unknown PSK identity",
	alertCertificateRequired:          "certificate required",
	alertNoApplicationProtocol:        "no application protocol",
}

var alertTextCN = map[alert]string{
	alertCloseNotify:            "关闭通知",
	alertUnexpectedMessage:      "接收到一个不符合上下文关系的消息",
	alertBadRecordMAC:           "MAC校验错误或解密错误",
	alertDecryptionFailed:       "解密失败",
	alertRecordOverflow:         "报文过长",
	alertDecompressionFailure:   "解压缩失败",
	alertHandshakeFailure:       "协商失败",
	alertBadCertificate:         "证书破坏",
	alertUnsupportedCertificate: "不支持证书类型",
	alertCertificateRevoked:     "证书被撤销",
	alertCertificateExpired:     "证书过期或未生效",
	alertCertificateUnknown:     "未知证书错误",
	alertIllegalParameter:       "非法参数",
	alertUnknownCA:              "根证书不可信",
	alertAccessDenied:           "拒绝访问",
	alertDecodeError:            "消息解码失败",
	alertDecryptError:           "消息解密失败",
	alertProtocolVersion:        "版本不匹配",
	alertInsufficientSecurity:   "安全性不足",
	alertInternalError:          "内部错误",
	alertUserCanceled:           "用户取消操作",
	alertNoRenegotiation:        "拒绝重新协商",
	alertUnsupportedSite2site:   "不支持 site2site",
	alertNoArea:                 "没有保护域",
	alertUnsupportedAreaType:    "不支持的保护域类型",
	alertBadIbcParam:            "接收到一个无效的ibc公共参数",
	alertUnsupportedIbcParam:    "不支持ibc公共参数中定义的信息",
	alertIdentityNeed:           "缺少对方的ibc标识",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return "tlcp: " + s
	}
	return "tlcp: alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}

func (e alert) CN() string {
	s, ok := alertTextCN[e]
	if ok {
		return s
	}
	return "TLCP: 报警(" + strconv.Itoa(int(e)) + ")"
}

func AlertCN(code uint8) string {
	s, ok := alertTextCN[alert(code)]
	if ok {
		return s
	}
	return s
}
