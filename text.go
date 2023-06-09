package gopkcs8der

import (
	"crypto/x509"
	"encoding/base64"
)

var b64Enc = base64.RawURLEncoding

func (k PrivateKey) MarshalText() (text []byte, err error) {
	if k.Key == nil {
		return
	}
	binBuf, err := x509.MarshalPKCS8PrivateKey(k.Key)
	if nil != err {
		return
	}
	text = make([]byte, b64Enc.EncodedLen(len(binBuf)))
	base64.RawURLEncoding.Encode(text, binBuf)
	return
}

func (k *PrivateKey) UnmarshalText(text []byte) (err error) {
	txtLen := len(text)
	if txtLen == 0 {
		k.Key = nil
		return
	}
	decBuf := make([]byte, b64Enc.DecodedLen(txtLen))
	n, err := b64Enc.Decode(decBuf, text)
	if nil != err {
		return
	}
	priKey, err := x509.ParsePKCS8PrivateKey(decBuf[:n])
	if nil != err {
		return
	}
	k.Key = priKey
	return
}
