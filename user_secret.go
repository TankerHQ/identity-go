package identity

import (
	"crypto/rand"

	"golang.org/x/crypto/blake2b"
)

const (
	userSecretSize = 32
)

func hashUserID(trustchainID []byte, userIDString string) []byte {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	hashedUserID := blake2b.Sum256(userIDBuffer)
	return hashedUserID[:]
}

func newUserSecret(userID []byte) []byte {
	// make payload for all subsequent operations
	payload := make([]byte, userSecretSize - 1 + len(userID))

	// make userSecret-1 length secret
	_, _ = rand.Read(payload[:userSecretSize-1])
	// append userId
	copy(payload[userSecretSize-1:], userID)
	// get check byte
	check := oneByteGenericHash(payload)

	// set check byte
	payload[userSecretSize-1] = check
	// return only up to userSecretSize length
	return payload[:userSecretSize]
}

func oneByteGenericHash(input []byte) byte {
	hash, err := blake2b.New(16, nil)
	if err != nil {
		panic("hash failed: " + err.Error())
	}
	_, _ = hash.Write(input)
	return hash.Sum(nil)[0]
}
