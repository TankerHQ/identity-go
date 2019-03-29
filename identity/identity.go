package identity

import (
	"encoding/base64"

	"github.com/TankerHQ/identity-go/curve25519"
	"golang.org/x/crypto/ed25519"
)

type publicIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       string `json:"target"`
	Value        string `json:"value"`
}

type identity struct {
	publicIdentity
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserSecret                   []byte `json:"user_secret"`
}

type publicProvisionalIdentity struct {
	publicIdentity
	PublicSignatureKey  []byte `json:"public_signature_key"`
	PublicEncryptionKey []byte `json:"public_encryption_key"`
}

type provisionalIdentity struct {
	publicProvisionalIdentity
	PrivateSignatureKey  []byte `json:"private_signature_key"`
	PrivateEncryptionKey []byte `json:"private_encryption_key"`
}

func generateIdentity(config config, userIDString string) (*identity, error) {
	userID := hashUserID(config.TrustchainID, userIDString)
	userSecret := createUserSecret(userID)

	eprivSignKey, epubSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	payload := append(epubSignKey, userID...)

	delegationSignature := ed25519.Sign(config.TrustchainPrivateKey, payload)

	identity := identity{
		publicIdentity: publicIdentity{
			TrustchainID: config.TrustchainID,
			Target:       "user",
			Value:        base64.StdEncoding.EncodeToString(userID),
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   userSecret,
	}

	return &identity, nil
}

func generateProvisionalIdentity(config config, email string) (*provisionalIdentity, error) {
	privateSignatureKey, publicSignatureKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	privateEncryptionKey, publicEncryptionKey, err := curve25519.GenerateKey()
	if err != nil {
		return nil, err
	}

	provisionalIdentity := provisionalIdentity{
		publicProvisionalIdentity: publicProvisionalIdentity{
			publicIdentity: publicIdentity{
				TrustchainID: config.TrustchainID,
				Target:       "email",
				Value:        email,
			},
			PublicEncryptionKey: publicEncryptionKey,
			PublicSignatureKey:  publicSignatureKey,
		},
		PrivateSignatureKey:  privateSignatureKey,
		PrivateEncryptionKey: privateEncryptionKey,
	}

	return &provisionalIdentity, nil
}
