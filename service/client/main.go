package main

import (
	"bytes"
	"encoding/json"
	"end_2_end_POC/service/models"
	"end_2_end_POC/service/servaes"
	"end_2_end_POC/service/servrsa"
	"io/ioutil"
	"strings"

	//"bytes"
	"log"
	"net/http"
)

const (
	clientPrivateKey = "../keys/id_rsa_private_client.pem"
	serverPublicKey  = "../keys/id_rsa_public_server.pem"
)

func main() {
	clientPrivKey, err := servrsa.LoadPrivateKey(clientPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	servPubKey, err := servrsa.LoadPublicKey(serverPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	aesKey := []byte("FTeK3CoZqtjtWkUeKQMRohGAW2xSItLr")

	data := &models.Data{
		Name:  strings.Repeat("Vijay ", 1000000),
		Addr:  strings.Repeat("India ", 1000000),
		Phone: strings.Repeat("8447836575 ", 1000000),
	}

	text, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	aesCipherText, err := servaes.Encrypt(aesKey, text)
	if err != nil {
		log.Fatal(err)
	}

	rsaCipherText, err := servrsa.Encrypt(servPubKey, aesKey)
	if err != nil {
		log.Fatal(err)
	}

	rsaSignature, err := servrsa.Sign(clientPrivKey, aesKey)
	if err != nil {
		log.Fatal(err)
	}

	info := &models.Info{
		EncSymKey: rsaCipherText,
		Signature: rsaSignature,
		Data:      aesCipherText,
	}

	reqBody, err := json.Marshal(info)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9998", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(body))
}
