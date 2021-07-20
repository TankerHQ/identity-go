package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
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

func newIdentity(config config, userIDString string) (identity, error) {
	generatedAppID := newAppId(config.AppSecret)

	if !bytes.Equal(generatedAppID, config.AppID) {
		return identity{}, errors.New("app secret and app ID mismatch")
	}

	userID := hashUserID(config.AppID, userIDString)
	userSecret := newUserSecret(userID)

	epubSignKey, eprivSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return identity{}, err
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

	return identity, nil
}

func newProvisionalIdentity(config config, email string) (provisionalIdentity, error) {
	publicSignatureKey, privateSignatureKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return provisionalIdentity{}, err
	}
	publicEncryptionKey, privateEncryptionKey, err := NewKeyPair()
	if err != nil {
		return provisionalIdentity{}, err
	}

	provisionalIdentity := provisionalIdentity{
		publicProvisionalIdentity: publicProvisionalIdentity{
			publicIdentity: publicIdentity{
				TrustchainID: config.AppID,
				Target:       "email",
				Value:        email,
			},
			PublicEncryptionKey: publicEncryptionKey,
			PublicSignatureKey:  publicSignatureKey,
		},
		PrivateSignatureKey:  privateSignatureKey,
		PrivateEncryptionKey: privateEncryptionKey,
	}

	return provisionalIdentity, nil
}

func Create(config Config, userID string) (string, error) {
	return New(config, userID)
}

func CreateProvisional(config Config, email string) (string, error) {
	return NewProvisional(config, email)
}

func GetPublicIdentity(b64Identity string) (string, error) {
	return GetPublic(b64Identity)
}

func New(cfg Config, userID string) (string, error) {
	conf, err := cfg.fromBase64()
	if err != nil {
		return "", err
	}
	id, err := newIdentity(conf, userID)
	if err != nil {
		return "", err
	}
	return Base64JsonEncode(id)
}

func NewProvisional(config Config, email string) (string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return "", err
	}
	id, err := newProvisionalIdentity(conf, email)
	if err != nil {
		return "", err
	}
	return Base64JsonEncode(id)
}

func GetPublic(b64Identity string) (string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}

	var (
		pid anyPublicIdentity
	)

	err := Base64JsonDecode(b64Identity, &pid)
	if err != nil {
		return "", err
	}

	if pid.Target != "user" && pid.Target != "email" {
		return "", errors.New("unsupported identity target")
	}

	return Base64JsonEncode(pid)
}
