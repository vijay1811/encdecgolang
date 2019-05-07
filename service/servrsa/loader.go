package servrsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// LoadPrivateKey ...
func LoadPrivateKey(file string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(data)

	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

// LoadPublicKey ...
func LoadPublicKey(file string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(data)

	return x509.ParsePKCS1PublicKey(p.Bytes)
}
