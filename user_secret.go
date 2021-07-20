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
