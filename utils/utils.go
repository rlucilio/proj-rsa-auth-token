package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"log"
	"math/big"
	"rlucilio/rsa-token/config"
)

func ToBase64String(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func ToStringBase64(value string) []byte {
	value64, err := base64.StdEncoding.DecodeString(value)
	VerifyError(err)
	return value64
}

func AuthToXML(authMetaXML config.AuthenticationXML) []byte {
	xml, err := xml.Marshal(authMetaXML)

	VerifyError(err)

	return xml
}

func VerifyError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func EncryptRSA(key *rsa.PublicKey, value []byte) []byte {
	tokenRsa, err := rsa.EncryptPKCS1v15(rand.Reader, key, value)
	VerifyError(err)

	return tokenRsa
}

func Base64bigint(str string) *big.Int {
	bInt := &big.Int{}
	bInt = bInt.SetBytes([]byte(str))

	return bInt
}

func BytesToString(value []byte) string {
	return string(value[:])
}

func StringToBytes(value string) []byte {
	return []byte(value)
}
