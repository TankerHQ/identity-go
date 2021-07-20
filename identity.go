package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

type publicIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       Target `json:"target"`
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

func newIdentity(cfg config, userIDString string) (identity, error) {
	generatedAppID := newAppId(cfg.AppSecret)

	if !bytes.Equal(generatedAppID, cfg.AppID) {
		return identity{}, errors.New("app secret and app ID mismatch")
	}

	userID := hashUserID(cfg.AppID, userIDString)
	userSecret := newUserSecret(userID)

	epubSignKey, eprivSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return identity{}, err
	}

	payload := append(epubSignKey, userID...)

	delegationSignature := ed25519.Sign(cfg.AppSecret, payload)

	id := identity{
		publicIdentity: publicIdentity{
			TrustchainID: cfg.AppID,
			Target:       TargetUser,
			Value:        base64.StdEncoding.EncodeToString(userID),
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   userSecret,
	}

	return id, nil
}

func newProvisionalIdentity(cfg config, target Target, value string) (provisionalIdentity, error) {
	publicSignatureKey, privateSignatureKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return provisionalIdentity{}, err
	}
	publicEncryptionKey, privateEncryptionKey, err := NewKeyPair()
	if err != nil {
		return provisionalIdentity{}, err
	}

	provId := provisionalIdentity{
		publicProvisionalIdentity: publicProvisionalIdentity{
			publicIdentity: publicIdentity{
				TrustchainID: cfg.AppID,
				Target:       target,
				Value:        value,
			},
			PublicEncryptionKey: publicEncryptionKey,
			PublicSignatureKey:  publicSignatureKey,
		},
		PrivateSignatureKey:  privateSignatureKey,
		PrivateEncryptionKey: privateEncryptionKey,
	}

	return provId, nil
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

func Create(config Config, userID string) (string, error) {
	return New(config, userID)
}

func CreateProvisional(config Config, target Target, value string) (string, error) {
	return NewProvisional(config, target, value)
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

func NewProvisional(cfg Config, target Target, value string) (string, error) {
	conf, err := cfg.fromBase64()
	if err != nil {
		return "", err
	}

	if target != TargetEmail && target != TargetPhoneNumber {
		return "", errors.New("unsupported provisional identity target")
	}
	provId, err := newProvisionalIdentity(conf, target, value)
	if err != nil {
		return "", err
	}
	return Base64JsonEncode(provId)
}

func GetPublic(b64Identity string) (string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}

	var (
		pubId anyPublicIdentity
	)

	err := Base64JsonDecode(b64Identity, &pubId)
	if err != nil {
		return "", err
	}

	if pubId.Target != TargetUser &&
		pubId.Target != TargetEmail &&
		pubId.Target != TargetPhoneNumber {
		return "", errors.New("unsupported identity target")
	}

	if pubId.Target != TargetUser {
		if pubId.Target == TargetEmail {
			pubId.Value = hashProvisionalIdentityEmail(pubId.Value)
		} else {
			privId := orderedmap.New()
			err := Base64JsonDecode(b64Identity, &privId)
			if err != nil {
				return "", err
			}
			privateSignatureKey, found := privId.Get("private_signature_key")
			if !found {
				return "", errors.New("invalid tanker identity")
			}
			pubId.Value = hashProvisionalIdentityValue(pubId.Value, privateSignatureKey.(string))
		}
		pubId.Target = ToHashed(pubId.Target)
	}

	return Base64JsonEncode(pubId)
}

func UpgradeIdentity(b64Identity string) (string, error) {
	id := orderedmap.New()
	err := Base64JsonDecode(b64Identity, &id)
	if err != nil {
		return "", err
	}

	_, isPrivate := id.Get("private_encryption_key")
	targetI, found := id.Get("target")
	target, ok := targetI.(Target)
	if !found || !ok {
		return "", errors.New("invalid provisional identity (missing or invalid target field)")
	}
	if target == TargetEmail && !isPrivate {
		id.Set("target", TargetHashedEmail)
		value, valueFound := id.Get("value")
		if !valueFound {
			return "", errors.New("unsupported identity without value")
		}

		hashedEmail := blake2b.Sum256([]byte(value.(string)))
		id.Set("value", base64.StdEncoding.EncodeToString(hashedEmail[:]))
	}

	return Base64JsonEncode(id)
}
