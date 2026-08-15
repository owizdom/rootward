package main

import (
	"bytes"
	"crypto/tls"
	"log"
)

func verify(signature, expected []byte) bool {
	return bytes.Equal(signature, expected) // BT-T07C
}

func client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // BT-T06B
}

func audit(privateKey string) {
	log.Printf("loaded privateKey=%s", privateKey) // BT-T03
}
