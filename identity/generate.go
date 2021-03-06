package identity

import (
	"errors"

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

	return b64json.Encode(publicIdentity)
}
