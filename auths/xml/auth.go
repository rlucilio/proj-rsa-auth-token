package authxml

import (
	"crypto/rsa"
	"encoding/xml"
	"os"
	"rlucilio/rsa-token/config"
	"rlucilio/rsa-token/utils"
)

func Authenticate(id, username, pass, branchId string) string {
	publicKey := genPublicKey()

	userNameEncrypt := utils.EncryptRSA(publicKey, utils.StringToBytes(username))
	passEncrypt := utils.EncryptRSA(publicKey, utils.StringToBytes(pass))
	branchIdEncrypt := utils.EncryptRSA(publicKey, utils.StringToBytes(branchId))

	auth := &config.AuthenticationXML{
		Id:       id,
		UserName: utils.ToBase64String(userNameEncrypt),
		Password: utils.ToBase64String(passEncrypt),
		BranchId: utils.ToBase64String(branchIdEncrypt),
	}

	token := utils.AuthToXML(*auth)

	return utils.ToBase64String(token[:])
}

func genPublicKey() *rsa.PublicKey {
	xmlPkString, err := getPublicKeyXML()

	rsaKeyValue := config.RSAKeyValueXML{}
	utils.VerifyError(xml.Unmarshal(xmlPkString, &rsaKeyValue))

	decodedModulus := utils.ToStringBase64(rsaKeyValue.Modulus)
	utils.VerifyError(err)
	decodedExponent := utils.ToStringBase64(rsaKeyValue.Exponent)
	utils.VerifyError(err)

	return &rsa.PublicKey{
		N: utils.Base64bigint(utils.BytesToString(decodedModulus)),
		E: int(utils.Base64bigint(utils.BytesToString(decodedExponent)).Int64()),
	}
}

func getPublicKeyXML() ([]byte, error) {
	data, err := os.ReadFile("./keys/public_key.xml")

	utils.VerifyError(err)

	return data, err
}
