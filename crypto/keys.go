package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
)

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func LoadKeyPair(privateKeyBytes []byte) (*KeyPair, error) {
	if len(privateKeyBytes) != PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func PublicKeyFromBytes(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

func PublicKeyToHex(publicKey ed25519.PublicKey) string {
	return hex.EncodeToString(publicKey)
}

func PublicKeyFromHex(hexString string) (ed25519.PublicKey, error) {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}
	return PublicKeyFromBytes(bytes)
}
