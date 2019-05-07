package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
)

func main() {
	savePrivateFileTo := "./id_rsa_private.pem"
	savePublicFileTo := "./id_rsa_public.pem"
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	// publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	// if err != nil {
	// 	log.Fatal(err.Error())
	// }

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	publicKeyBytes := encodePublicKeyToPEM(&privateKey.PublicKey)

	err = writeKeyToFile(privateKeyBytes, savePrivateFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(publicKeyBytes), savePublicFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func encodePublicKeyToPEM(publicKey *rsa.PublicKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PublicKey(publicKey)

	// pem.Block
	pubBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// publicKey key in PEM format
	publicPEM := pem.EncodeToMemory(&pubBlock)

	return publicPEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}
