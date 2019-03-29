package identity

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

type userToken struct {
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserID                       []byte `json:"user_id"`
	UserSecret                   []byte `json:"user_secret"`
}

func (this userToken) upgrade(trustchainID []byte, userID string) (*identity, error) {
	obfuscatedUserID := hashUserID(trustchainID, userID)

	if subtle.ConstantTimeCompare(obfuscatedUserID, this.UserID) == 0 {
		return nil, errors.New("Invalid userid")
	}

	id := identity{
		publicIdentity: publicIdentity{
			TrustchainID: trustchainID,
			Target:       "user",
			Value:        base64.StdEncoding.EncodeToString(this.UserID),
		},
		DelegationSignature:          this.DelegationSignature,
		EphemeralPublicSignatureKey:  this.EphemeralPublicSignatureKey,
		EphemeralPrivateSignatureKey: this.EphemeralPrivateSignatureKey,
		UserSecret:                   this.UserSecret,
	}
	return &id, nil
}
