package main

import (
	"crypto/rsa"
	"encoding/json"
	"end_2_end_POC/service/models"
	"end_2_end_POC/service/servaes"
	"end_2_end_POC/service/servrsa"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	serverPrivateKey = "../keys/id_rsa_private_server.pem"
	clientPublicKey  = "../keys/id_rsa_public_client.pem"
)

type handler struct {
	serverPrivKey *rsa.PrivateKey
	clientPubKey  *rsa.PublicKey
}

func (h *handler) decryptData(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return
	}
	info := &models.Info{}
	if err := json.Unmarshal(body, info); err != nil {
		log.Println(err)
		return
	}

	// verify signature
	if err := servrsa.Verify(h.clientPubKey, info.Signature); err != nil {
		log.Println(err)
		return
	}

	aesSymKey, err := servrsa.Decrypt(h.serverPrivKey, info.EncSymKey)
	if err != nil {
		log.Println(err)
		return
	}

	data, err := servaes.Decrypt(aesSymKey, info.Data)
	if err != nil {
		log.Println(err)
		return
	}

	if err := ioutil.WriteFile("data.json", data, os.ModePerm); err != nil {
		log.Println(err)
		return
	}

}

func main() {
	mux := http.NewServeMux()
	servPrivKey, err := servrsa.LoadPrivateKey(serverPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	clientPubKey, err := servrsa.LoadPublicKey(clientPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	h := &handler{
		serverPrivKey: servPrivKey,
		clientPubKey:  clientPubKey,
	}

	mux.HandleFunc("/", h.decryptData)

	server := &http.Server{
		Addr:    ":9998",
		Handler: mux,
	}

	server.ListenAndServe()
}
