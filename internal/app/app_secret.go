package app

import (
	"golang.org/x/crypto/blake2b"
)

const (
	// AppSecretSize is the length of an app secret, in bytes
	AppSecretSize = 64
	// AppPublicKeySize is the length of an app public key, in bytes
	AppPublicKeySize = 32
)

const (
	authorSize = 32
	appCreationNature = 1
)

// GetAppId returns the app ID from the appSecret it is provided with.
// appSecret should be precisely AppSecretSize bytes long.
func GetAppId(appSecret []byte) []byte {
	publicKey := appSecret[AppSecretSize-AppPublicKeySize : AppSecretSize]

	payload := make([]byte, 1 +authorSize+AppPublicKeySize)
	payload[0] = appCreationNature
	copy(payload[1 +authorSize:], publicKey)

	hashed := blake2b.Sum256(payload)
	return hashed[:]
}
