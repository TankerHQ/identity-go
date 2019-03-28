package identity

import (
	"encoding/base64"
	"errors"
)

type Config struct {
	TrustchainID         string
	TrustchainPrivateKey string
}

type config struct {
	TrustchainID         []byte
	TrustchainPrivateKey []byte
}

func (this Config) fromB64() (*config, error) {
	truschainIDBytes, err := base64.StdEncoding.DecodeString(this.TrustchainID)
	if err != nil {
		return nil, errors.New("Wrong trustchainID format, should be base64: " + this.TrustchainID)
	}
	trustchainPrivKeyBytes, err := base64.StdEncoding.DecodeString(this.TrustchainPrivateKey)
	if err != nil {
		return nil, errors.New("Wrong trustchainPrivateKey format, should be base64: " + this.TrustchainPrivateKey)
	}
	return &config{
		TrustchainID:         truschainIDBytes,
		TrustchainPrivateKey: trustchainPrivKeyBytes,
	}, nil
}
