package identity

import (
	"encoding/base64"
	"errors"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/blake2b"

	"github.com/TankerHQ/identity-go/v2/b64json"
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

func CreateProvisional(config Config, email string) (*string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return nil, err
	}
	identity, err := generateProvisionalIdentity(*conf, email)
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

	if publicIdentity.Target != "user" && publicIdentity.Target != "email" {
		return nil, errors.New("Unsupported identity target")
	}

	if publicIdentity.Target == "email" {
		publicIdentity.Target = "hashed_email"
		hashedEmail := blake2b.Sum256([]byte(publicIdentity.Value))
		publicIdentity.Value = base64.StdEncoding.EncodeToString(hashedEmail[:])
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
