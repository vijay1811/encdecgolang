package servrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

const (
	signMe = "i am a secret"
)

// Encrypt ...
func Encrypt(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, data, label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt ...
func Decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Sign ...
func Sign(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := []byte(signMe)
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, newhash, hashed, &opts)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify ...
func Verify(publicKey *rsa.PublicKey, signature []byte) error {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple exae

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write([]byte(signMe))
	hashed := pssh.Sum(nil)
	return rsa.VerifyPSS(publicKey, newhash, hashed, signature, &opts)
}
