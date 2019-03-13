package identity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

const (
	userSecretSize = 32
)

//Config : trustchain cofiguration
type Config struct {
	TrustchainID         string
	TrustchainPrivateKey string
}

func oneByteGenericHash(input []byte) byte {
	hash, err := blake2b.New(16, []byte{})
	if err != nil {
		panic("hash failed: " + err.Error())
	}
	hash.Write(input)
	return hash.Sum([]byte{})[0]
}

func toB64JSON(v interface{}) (string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	b64Token := base64.StdEncoding.EncodeToString(jsonToken)
	return b64Token, nil
}

func fromB64JSON(b64 string, v interface{}) error {
	str, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	err = json.Unmarshal(str, v)
	if err != nil {
		return err
	}
	return nil
}

type PublicPermanentIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       string `json:"target"`
	Value        []byte `json:"value"`
}

//Exported only to facilitate code testing (this shouldn't be needed in any app using this lib)
type SecretPermanentIdentity struct {
	PublicPermanentIdentity
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserSecret                   []byte `json:"user_secret"`
}

//Create a user token for given user.
func Create(config Config, userID string) (string, error) {
	truschainIDBytes, err := base64.StdEncoding.DecodeString(config.TrustchainID)
	if err != nil {
		return "", errors.New("Wrong trustchainID format, should be base64: " + config.TrustchainID)
	}
	trustchainPrivKeyBytes, err2 := base64.StdEncoding.DecodeString(config.TrustchainPrivateKey)
	if err2 != nil {
		return "", errors.New("Wrong trustchainPrivateKey format, should be base64: " + config.TrustchainPrivateKey)
	}
	return generateIdentity(truschainIDBytes, trustchainPrivKeyBytes, userID)
}

func GetPublicIdentity(b64Identity string) (string, error) {
	identity := SecretPermanentIdentity{}
	err := fromB64JSON(b64Identity, &identity)
	if err != nil {
		return "", err
	}

	if identity.Target != "user" {
		return "", errors.New("unsupported identity target")
	}

	publicIdentity := PublicPermanentIdentity{
		TrustchainID: identity.TrustchainID,
		Target:       "user",
		Value:        identity.Value,
	}

	return toB64JSON(publicIdentity)
}

func generateIdentity(trustchainID []byte, trustchainPrivateKey []byte,
	userIDString string) (string, error) {
	userID := hashUserID(trustchainID, userIDString)

	userSecret := createUserSecret(userID)

	eprivSignKey, epubSignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	payload := append(epubSignKey, userID...)

	delegationSignature := ed25519.Sign(trustchainPrivateKey, payload)

	identity := SecretPermanentIdentity{
		PublicPermanentIdentity: PublicPermanentIdentity{
			TrustchainID: trustchainID,
			Target:       "user",
			Value:        userID,
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   userSecret,
	}

	return toB64JSON(identity)
}

func hashUserID(trustchainID []byte, userIDString string) []byte {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	hashedUserID := blake2b.Sum256(userIDBuffer)
	return hashedUserID[:]
}

func createUserSecret(userID []byte) []byte {
	randdata := make([]byte, userSecretSize-1)
	rand.Read(randdata)
	check := oneByteGenericHash(append(randdata, userID...))
	return append(randdata, check)
}
