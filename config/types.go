package config

import "encoding/xml"

type AuthenticationXML struct {
	XMLName  xml.Name `xml:"Authentication"`
	Id       string   `xml:"Id"`
	UserName string   `xml:"UserName"`
	Password string   `xml:"Password"`
	BranchId string   `xml:"BranchId"`
}

type RSAKeyValueXML struct {
	Modulus  string
	Exponent string
	P        string
	Q        string
	DP       string
	DQ       string
	InverseQ string
	D        string
}
