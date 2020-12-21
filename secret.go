package identity

import (
	"crypto/rand"

	"golang.org/x/crypto/blake2b"
)

const (
	AppSecretSize     = 64
	AppPublicKeySize  = 32
	userSecretSize    = 32
	appCreationNature = 1
)

func generateAppID(appSecret []byte) []byte {
	publicKey := appSecret[AppSecretSize-AppPublicKeySize : AppSecretSize]
	author := make([]byte, 32)
	payload := append([]byte{appCreationNature}, author...)
	payload = append(payload, publicKey...)
	hashed := blake2b.Sum256(payload)
	return hashed[:]
}

func hashUserID(trustchainID []byte, userIDString string) []byte {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	hashedUserID := blake2b.Sum256(userIDBuffer)
	return hashedUserID[:]
}

func createUserSecret(userID []byte) []byte {
	randdata := make([]byte, userSecretSize-1)
	_, _ = rand.Read(randdata)
	check := oneByteGenericHash(append(randdata, userID...))
	return append(randdata, check)
}

func oneByteGenericHash(input []byte) byte {
	hash, err := blake2b.New(16, []byte{})
	if err != nil {
		panic("hash failed: " + err.Error())
	}
	_, _ = hash.Write(input)
	return hash.Sum([]byte{})[0]
}
