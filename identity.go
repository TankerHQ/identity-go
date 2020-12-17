package identity

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

func Create(config Config, userID string) (*string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return nil, err
	}
	identity, err := generateIdentity(*conf, userID)
	if err != nil {
		return nil, err
	}
	return Base64Encode(identity)
}

func CreateProvisional(config Config, email string) (*string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return nil, err
	}
	identity, err := generateProvisionalIdentity(*conf, email)
	if err != nil {
		return nil, err
	}
	return Base64Encode(identity)
}

func GetPublicIdentity(b64Identity string) (*string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}
	publicIdentity := &anyPublicIdentity{}
	err := Base64Decode(b64Identity, publicIdentity)
	if err != nil {
		return nil, err
	}

	if publicIdentity.Target != "user" && publicIdentity.Target != "email" {
		return nil, errors.New("unsupported identity target")
	}

	return Base64Encode(publicIdentity)
}

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
