package identity

import (
	"golang.org/x/crypto/ed25519"
)

type publicIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       string `json:"target"`
	Value        []byte `json:"value"`
}

type identity struct {
	publicIdentity
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserSecret                   []byte `json:"user_secret"`
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
			Value:        userID,
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   userSecret,
	}

	return &identity, nil
}
