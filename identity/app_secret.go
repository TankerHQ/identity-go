package identity

import (
	"golang.org/x/crypto/blake2b"
)

const appSecretSize = 64
const appPublicKeySize = 32
const authorSize = 32
const appCreationNature = 1

func generateAppID(appSecret []byte) []byte {
	publicKey := appSecret[appSecretSize-appPublicKeySize : appSecretSize]
	author := make([]byte, 32)
	payload := append([]byte{appCreationNature}, author...)
	payload = append(payload, publicKey...)
	hashed := blake2b.Sum256(payload)
	return hashed[:]
}
