package main

import (
	"fmt"
	"os"
	authPEM "rlucilio/rsa-token/auths/pem"
	authXML "rlucilio/rsa-token/auths/xml"
	"rlucilio/rsa-token/config"
)

func main() {

	token := authPEM.Authenticate(config.SYSTEM_ID_CONFIG, config.USER_CONFIG, config.PASS_CONFIG, config.BRANCH_CONFIG)
	token2 := authXML.Authenticate(config.SYSTEM_ID_CONFIG, config.USER_CONFIG, config.PASS_CONFIG, config.BRANCH_CONFIG)

	fileXml, _ := os.Create("./tokens-rsa/token-xml.txt")
	filePem, _ := os.Create("./tokens-rsa/token-pem.txt")

	defer fileXml.Close()
	defer filePem.Close()

	fileXml.WriteString(token)
	filePem.WriteString(token2)

	fmt.Printf("Token with XML: %v\n", token)
	fmt.Println()
	fmt.Printf("Token with PEM: %v\n", token2)

}
