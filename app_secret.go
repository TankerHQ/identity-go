package identity

import (
	"golang.org/x/crypto/blake2b"
)

const AppSecretSize = 64
const AppPublicKeySize = 32
const authorSize = 32
const appCreationNature = 1

func generateAppID(appSecret []byte) []byte {
	publicKey := appSecret[AppSecretSize-AppPublicKeySize : AppSecretSize]
	author := make([]byte, 32)
	payload := append([]byte{appCreationNature}, author...)
	payload = append(payload, publicKey...)
	hashed := blake2b.Sum256(payload)
	return hashed[:]
}
