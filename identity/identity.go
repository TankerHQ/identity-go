package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/blake2b"

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
	generatedAppID := generateAppID(config.AppSecret)

	if !bytes.Equal(generatedAppID, config.AppID) {
		return nil, errors.New("App secret and app ID mismatch")
	}

	userID := hashUserID(config.AppID, userIDString)
	userSecret := createUserSecret(userID)

	epubSignKey, eprivSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	payload := append(epubSignKey, userID...)

	delegationSignature := ed25519.Sign(config.AppSecret, payload)

	identity := identity{
		publicIdentity: publicIdentity{
			TrustchainID: config.AppID,
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

func generateProvisionalIdentity(config config, target string, value string) (*provisionalIdentity, error) {
	publicSignatureKey, privateSignatureKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	publicEncryptionKey, privateEncryptionKey, err := curve25519.GenerateKey()
	if err != nil {
		return nil, err
	}

	provisionalIdentity := provisionalIdentity{
		publicProvisionalIdentity: publicProvisionalIdentity{
			publicIdentity: publicIdentity{
				TrustchainID: config.AppID,
				Target:       target,
				Value:        value,
			},
			PublicEncryptionKey: publicEncryptionKey,
			PublicSignatureKey:  publicSignatureKey,
		},
		PrivateSignatureKey:  privateSignatureKey,
		PrivateEncryptionKey: privateEncryptionKey,
	}

	return &provisionalIdentity, nil
}

func hashProvisionalIdentityEmail(email string) (hash string) {
	hashedValue := blake2b.Sum256([]byte(email))
	return base64.StdEncoding.EncodeToString(hashedValue[:])
}

func hashProvisionalIdentityValue(value string, privateSignatureKeyB64 string) (hash string) {
	privateSignatureKey, _ := base64.StdEncoding.DecodeString(privateSignatureKeyB64)
	hashSalt := blake2b.Sum256(privateSignatureKey)
	hashedValue := blake2b.Sum256(append(hashSalt[:], []byte(value)...))
	return base64.StdEncoding.EncodeToString(hashedValue[:])
}
