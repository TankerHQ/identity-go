package identity

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func GenerateKey() (PublicKey []byte, PrivateKey []byte, Error error) {
	sk := [32]byte{}
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}

	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	pk := [32]byte{}
	curve25519.ScalarBaseMult(&pk, &sk)

	return pk[:], sk[:], nil
}
