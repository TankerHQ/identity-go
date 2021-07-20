package identity

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// NewKeyPair returns a pair of signature keys, or an error if it occurs
func NewKeyPair() ([]byte, []byte, error) {
	var (
		sk [32]byte
		pk [32]byte
	)

	if _, err := rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}

	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:], sk[:], nil
}
