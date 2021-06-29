package identity

import (
	"encoding/base64"
	"errors"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/blake2b"

	"github.com/TankerHQ/identity-go/b64json"
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
	return b64json.Encode(identity)
}

func CreateProvisional(config Config, target string, value string) (*string, error) {
	conf, err := config.fromB64()
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
	return b64json.Encode(identity)
}

func GetPublicIdentity(b64Identity string) (*string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}
	publicIdentity := &anyPublicIdentity{}
	err := b64json.Decode(b64Identity, publicIdentity)
	if err != nil {
		return nil, err
	}

	if publicIdentity.Target != "user" &&
		publicIdentity.Target != "email" &&
		publicIdentity.Target != "phone_number" {
		return nil, errors.New("Unsupported identity target")
	}

	if publicIdentity.Target != "user" {
		if publicIdentity.Target == "email" {
			publicIdentity.Value = hashProvisionalIdentityEmail(publicIdentity.Value)
		} else {
			privateIdentity := orderedmap.New()
			err := b64json.Decode(b64Identity, &privateIdentity)
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

	return b64json.Encode(publicIdentity)
}

func UpgradeIdentity(b64Identity string) (*string, error) {
	identity := orderedmap.New()
	err := b64json.Decode(b64Identity, &identity)
	if err != nil {
		return nil, err
	}

	_, isPrivate := identity.Get("private_encryption_key")
	target, found := identity.Get("target")
	if found && target == "email" && !isPrivate {
		identity.Set("target", "hashed_email")
		value, valueFound := identity.Get("value")
		if !valueFound {
			return nil, errors.New("unsupported identity without value")
		}

		hashedEmail := blake2b.Sum256([]byte(value.(string)))
		identity.Set("value", base64.StdEncoding.EncodeToString(hashedEmail[:]))
	}

	return b64json.Encode(identity)
}
