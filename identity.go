package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/TankerHQ/identity-go/v3/internal/app"
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"github.com/TankerHQ/identity-go/v3/internal/crypto"
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

// Create returns a new identity crafted from config and userID
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

// CreateProvisional returns a new provisional identity crafted from
// config, target and value
func CreateProvisional(config Config, target Target, value string) (*string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return nil, err
	}

	if target != "email" && target != "phone_number" {
		return nil, errors.New("unsupported provisional identity target")
	}

	provisional, err := generateProvisionalIdentity(*conf, target, value)
	if err != nil {
		return nil, err
	}
	return base64_json.Encode(provisional)
}

// GetPublicIdentity returns the public identity associated with the
// identity it is sent
func GetPublicIdentity(b64Identity string) (*string, error) {
	type anyPublicIdentity struct {
		publicIdentity

		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}

	publicIdentity := new(anyPublicIdentity)
	if err := base64_json.Decode(b64Identity, publicIdentity); err != nil {
		return nil, err
	}

	hashTarget := true
	switch publicIdentity.Target {
	case User:
		hashTarget = false
	case Email:
		publicIdentity.Value = hashProvisionalIdentityEmail(publicIdentity.Value)
	case PhoneNumber:
		privateIdentity := make(map[string]interface{})
		// in practice this case should never happen since we are decoding into a
		// more permissive type, and we already decoded above so there should be
		// no problem with b64Identity itself
		if err := base64_json.Decode(b64Identity, &privateIdentity); err != nil {
			return nil, err
		}
		privateSignatureKey, found := privateIdentity["private_signature_key"]
		if !found {
			return nil, errors.New("invalid tanker identity")
		}
		publicIdentity.Value = hashProvisionalIdentityValue(publicIdentity.Value, privateSignatureKey.(string))
	default:
		return nil, errors.New("unsupported identity target")
	}

	if hashTarget {
		publicIdentity.Target = publicIdentity.Target.Hashed()
	}

	return base64_json.Encode(publicIdentity)
}

// UpgradeIdentity upgrades the identity provided to it if needed and returns
// the result of the upgrade
func UpgradeIdentity(b64Identity string) (*string, error) {
	identity := orderedmap.New()
	if err := base64_json.Decode(b64Identity, &identity); err != nil {
		return nil, err
	}

	_, isPrivate := identity.Get("private_encryption_key")
	target, found := identity.Get("target")
	if !found {
		return nil, errors.New("invalid provisional identity (missing target field)")
	}

	if Target(target.(string)) == Email && !isPrivate {
		identity.Set("target", Email.Hashed())
		value, valueFound := identity.Get("value")
		if !valueFound {
			return nil, errors.New("unsupported identity without value")
		}

		hashedEmail := blake2b.Sum256([]byte(value.(string)))
		identity.Set("value", base64.StdEncoding.EncodeToString(hashedEmail[:]))
	}

	return base64_json.Encode(identity)
}

func checkKeysIntegrity(config config) error {
	if !bytes.Equal(app.GetAppId(config.AppSecret), config.AppID) {
		return errors.New("app secret and app ID mismatch")
	}
	return nil
}

func generateIdentity(config config, userIDString string) (*identity, error) {
	if err := checkKeysIntegrity(config); err != nil {
		return nil, err
	}

	userID := hashUserID(config.AppID, userIDString)
	epubSignKey, eprivSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	payload := append(epubSignKey, userID...)
	delegationSignature := ed25519.Sign(config.AppSecret, payload)

	identity := identity{
		publicIdentity: publicIdentity{
			TrustchainID: config.AppID,
			Target:       User,
			Value:        base64.StdEncoding.EncodeToString(userID),
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   newUserSecret(userID),
	}

	return &identity, nil
}

func generateProvisionalIdentity(config config, target Target, value string) (*provisionalIdentity, error) {
	if err := checkKeysIntegrity(config); err != nil {
		return nil, err
	}

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
	hashedValue := blake2b.Sum256(append(hashSalt[:], value...))
	return base64.StdEncoding.EncodeToString(hashedValue[:])
}
