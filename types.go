package goadyenmobile

import "time"

type ClientSideEncrypter struct {
	AdyenPublicKey string
}

type CardDataJson struct {
	HolderName     string
	Number         string
	Cvc            string
	ExpiryMonth    string
	ExpiryYear     string
	GenerationTime time.Time
}
