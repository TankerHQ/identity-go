package identity

import (
	"golang.org/x/crypto/blake2b"
)

const (
	AppPublicKeySize = 32
	AppSecretSize    = 64
)

const (
	appCreationNature = 1
	authorSize        = 32
)

func newAppId(appSecret []byte) []byte {
	pKeyStart, pKeyEnd := AppSecretSize-AppPublicKeySize, AppSecretSize

	payload := make([]byte, 1 + authorSize + AppPublicKeySize)
	payload[0] = appCreationNature
	copy(payload[authorSize+1:], appSecret[pKeyStart:pKeyEnd])

	hashed := blake2b.Sum256(payload)
	return hashed[:]
}