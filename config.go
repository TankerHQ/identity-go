package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
)

type Config struct {
	AppID     string
	AppSecret string
}

type config struct {
	AppID     []byte
	AppSecret []byte
}

func (this Config) fromBase64() (*config, error) {
	appIDBytes, err := base64.StdEncoding.DecodeString(this.AppID)
	if err != nil {
		return nil, errors.New("Wrong AppID format, should be base64: " + this.AppID)
	}
	if len(appIDBytes) != AppPublicKeySize {
		return nil, fmt.Errorf("Expected App ID of size %d, got %d", AppPublicKeySize, len(appIDBytes))
	}
	appSecretBytes, err := base64.StdEncoding.DecodeString(this.AppSecret)
	if err != nil {
		return nil, errors.New("Wrong AppSecret format, should be base64: " + this.AppSecret)
	}
	if len(appSecretBytes) != AppSecretSize {
		return nil, fmt.Errorf("Expected App secret of size %d, got %d", AppSecretSize, len(appSecretBytes))
	}
	return &config{
		AppID:     appIDBytes,
		AppSecret: appSecretBytes,
	}, nil
}
