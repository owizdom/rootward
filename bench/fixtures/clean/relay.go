package main

import (
	"crypto/subtle"
	"crypto/tls"
	"log"
)

func verify(signature, expected []byte) bool {
	return subtle.ConstantTimeCompare(signature, expected) == 1
}

func client() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func audit(keyFingerprint string) {
	log.Printf("loaded keyFingerprint=%s", keyFingerprint)
}
