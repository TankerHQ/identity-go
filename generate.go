package identity

import (
	"errors"
)

func Create(config Config, userID string) (*string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return nil, err
	}
	identity, err := newIdentity(*conf, userID)
	if err != nil {
		return nil, err
	}
	return Base64JsonEncode(identity)
}

func CreateProvisional(config Config, email string) (*string, error) {
	conf, err := config.fromBase64()
	if err != nil {
		return nil, err
	}
	identity, err := newProvisionalIdentity(*conf, email)
	if err != nil {
		return nil, err
	}
	return Base64JsonEncode(identity)
}

func GetPublicIdentity(b64Identity string) (*string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}
	publicIdentity := &anyPublicIdentity{}
	err := Base64JsonDecode(b64Identity, publicIdentity)
	if err != nil {
		return nil, err
	}

	if publicIdentity.Target != "user" && publicIdentity.Target != "email" {
		return nil, errors.New("Unsupported identity target")
	}

	return Base64JsonEncode(publicIdentity)
}
