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

func (this Config) fromBase64() (config, error) {
	var (
		newCfg config
	)

	appIDBytes, err := base64.StdEncoding.DecodeString(this.AppID)
	if err != nil {
		return config{}, errors.New("Wrong AppID format, should be base64: " + this.AppID)
	}
	if len(appIDBytes) != AppPublicKeySize {
		return config{}, fmt.Errorf("Expected App ID of size %d, got %d", AppPublicKeySize, len(appIDBytes))
	}
	appSecretBytes, err := base64.StdEncoding.DecodeString(this.AppSecret)
	if err != nil {
		return config{}, errors.New("Wrong AppSecret format, should be base64: " + this.AppSecret)
	}
	if len(appSecretBytes) != AppSecretSize {
		return config{}, fmt.Errorf("Expected App secret of size %d, got %d", AppSecretSize, len(appSecretBytes))
	}

	newCfg = config{
		AppID:     appIDBytes,
		AppSecret: appSecretBytes,
	}
	return newCfg, nil
}
