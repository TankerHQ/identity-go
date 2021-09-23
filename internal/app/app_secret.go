package app

import (
	"golang.org/x/crypto/blake2b"
)

const AppSecretSize = 64
const AppPublicKeySize = 32
const authorSize = 32
const appCreationNature = 1

func GetAppId(appSecret []byte) []byte {
	publicKey := appSecret[AppSecretSize-AppPublicKeySize : AppSecretSize]

	payload := make([]byte, 1 +authorSize+AppPublicKeySize)
	payload[0] = appCreationNature
	copy(payload[1 +authorSize:], publicKey)

	hashed := blake2b.Sum256(payload)
	return hashed[:]
}
