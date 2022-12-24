package goadyenmobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func (c ClientSideEncrypter) GenerateAdyenNonce(name string, pan string, cvc string, expiryMonth string, expiryYear string) (string, error) {

	plainCardData, err := c.GenerateCardDataJson(name, pan, cvc, expiryMonth, expiryYear)

	if err != nil {
		return "", err
	}

	aesKey, err := c.GenerateAESKey()

	if err != nil {
		return "", err
	}

	nonce, err := c.GenerateNonce()

	if err != nil {
		return "", err
	}

	encryptedCardData, err := c.EncryptWithAESKey(aesKey, nonce, plainCardData)

	if err != nil {
		return "", err
	}

	encryptedCardComponent := append(nonce, encryptedCardData...)

	publicKey, err := c.DecodeAdyenPublicKey(c.AdyenPublicKey)

	if err != nil {
		return "", err
	}

	encryptedAesKey, err := c.EncryptWithPublicKey(publicKey, aesKey)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("adyenan0_1_1$%s$%s", base64.StdEncoding.EncodeToString(encryptedAesKey), base64.StdEncoding.EncodeToString(encryptedCardComponent)), nil
}

func (c ClientSideEncrypter) GenerateCardDataJson(name string, pan string, cvc string, expiryMonth string, expiryYear string) ([]byte, error) {
	return json.Marshal(CardDataJson{
		HolderName:     name,
		Number:         pan,
		Cvc:            cvc,
		ExpiryMonth:    expiryMonth,
		ExpiryYear:     expiryYear,
		GenerationTime: time.Now(),
	})
}

func (c ClientSideEncrypter) GenerateAESKey() ([]byte, error) {
	key := make([]byte, 256)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c ClientSideEncrypter) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func (c ClientSideEncrypter) EncryptWithAESKey(aesKey, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c ClientSideEncrypter) DecodeAdyenPublicKey(encodedPublicKey string) (*rsa.PublicKey, error) {
	keyComponents := strings.Split(encodedPublicKey, "|")
	if len(keyComponents) != 2 {
		return nil, fmt.Errorf("invalid encoded public key: %s", encodedPublicKey)
	}
	n, ok := new(big.Int).SetString(keyComponents[0], 16)
	if !ok {
		return nil, fmt.Errorf("invalid encoded public key: %s", encodedPublicKey)
	}
	e, ok := new(big.Int).SetString(keyComponents[1], 16)
	if !ok {
		return nil, fmt.Errorf("invalid encoded public key: %s", encodedPublicKey)
	}
	publicNumber := &rsa.PublicKey{N: n, E: int(e.Int64())}
	return publicNumber, nil
}

func (c ClientSideEncrypter) EncryptWithPublicKey(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, err
}
