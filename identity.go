package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"github.com/TankerHQ/identity-go/v3/internal/crypto"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/blake2b"

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


func Create(config Config, userID string) (*string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return nil, err
	}
	identity, err := generateIdentity(*conf, userID)
	if err != nil {
		return nil, err
	}
	return base64_json.Encode(identity)
}

func CreateProvisional(config Config, target string, value string) (*string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return nil, err
	}

	if target != "email" && target != "phone_number" {
		return nil, errors.New("unsupported provisional identity target")
	}

	identity, err := generateProvisionalIdentity(*conf, target, value)
	if err != nil {
		return nil, err
	}
	return base64_json.Encode(identity)
}

func GetPublicIdentity(b64Identity string) (*string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}
	publicIdentity := &anyPublicIdentity{}
	err := base64_json.Decode(b64Identity, publicIdentity)
	if err != nil {
		return nil, err
	}

	if publicIdentity.Target != "user" &&
		publicIdentity.Target != "email" &&
		publicIdentity.Target != "phone_number" {
		return nil, errors.New("unsupported identity target")
	}

	if publicIdentity.Target != "user" {
		if publicIdentity.Target == "email" {
			publicIdentity.Value = hashProvisionalIdentityEmail(publicIdentity.Value)
		} else {
			privateIdentity := orderedmap.New()
			err := base64_json.Decode(b64Identity, &privateIdentity)
			if err != nil {
				return nil, err
			}
			privateSignatureKey, found := privateIdentity.Get("private_signature_key")
			if !found {
				return nil, errors.New("invalid tanker identity")
			}
			publicIdentity.Value = hashProvisionalIdentityValue(publicIdentity.Value, privateSignatureKey.(string))
		}
		publicIdentity.Target = "hashed_" + publicIdentity.Target
	}

	return base64_json.Encode(publicIdentity)
}

func UpgradeIdentity(b64Identity string) (*string, error) {
	identity := orderedmap.New()
	err := base64_json.Decode(b64Identity, &identity)
	if err != nil {
		return nil, err
	}

	_, isPrivate := identity.Get("private_encryption_key")
	target, found := identity.Get("target")
	if !found {
		return nil, errors.New("invalid provisional identity (missing target field)")
	}
	if target == "email" && !isPrivate {
		identity.Set("target", "hashed_email")
		value, valueFound := identity.Get("value")
		if !valueFound {
			return nil, errors.New("unsupported identity without value")
		}

		hashedEmail := blake2b.Sum256([]byte(value.(string)))
		identity.Set("value", base64.StdEncoding.EncodeToString(hashedEmail[:]))
	}

	return base64_json.Encode(identity)
}


func generateIdentity(config config, userIDString string) (*identity, error) {
	generatedAppID := newAppId(config.AppSecret)

	if !bytes.Equal(generatedAppID, config.AppID) {
		return nil, errors.New("app secret and app ID mismatch")
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
	publicEncryptionKey, privateEncryptionKey, err := crypto.NewKeyPair()
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
