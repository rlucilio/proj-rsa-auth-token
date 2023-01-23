package authpem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"rlucilio/rsa-token/config"
	"rlucilio/rsa-token/utils"
)

func getPublicKeyPemFile() []byte {
	data, err := os.ReadFile("./keys/public_key.pem")

	utils.VerifyError(err)

	return data
}

func genPrimaryKey() *rsa.PublicKey {
	pemString := getPublicKeyPemFile()
	block, _ := pem.Decode([]byte(pemString))
	pubBlock, err := x509.ParsePKIXPublicKey(block.Bytes)
	utils.VerifyError(err)
	return pubBlock.(*rsa.PublicKey)
}

func Authenticate(id, username, pass, branchId string) string {
	pk := genPrimaryKey()

	userNameEncrypt := utils.EncryptRSA(pk, utils.StringToBytes(username))
	passEncrypt := utils.EncryptRSA(pk, utils.StringToBytes(pass))
	branchIdEncrypt := utils.EncryptRSA(pk, utils.StringToBytes(branchId))

	auth := &config.AuthenticationXML{
		Id:       id,
		UserName: utils.ToBase64String(userNameEncrypt),
		Password: utils.ToBase64String(passEncrypt),
		BranchId: utils.ToBase64String(branchIdEncrypt),
	}

	return utils.ToBase64String(utils.AuthToXML(*auth))[:]
}
