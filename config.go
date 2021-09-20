package identity

import (
	"encoding/base64"
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

func (cfg Config) fromBase64() (*config, error) {
	appIDBytes, err := base64.StdEncoding.DecodeString(cfg.AppID)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AppID '%s', should be a valid base64 string", cfg.AppID)
	}
	if len(appIDBytes) != AppPublicKeySize {
		return nil, fmt.Errorf("wrong byte size for AppID: %d, should be %d", len(appIDBytes), AppPublicKeySize)
	}
	appSecretBytes, err := base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AppSecret '%s', should be a valid base64 string", cfg.AppSecret)
	}
	if len(appSecretBytes) != AppSecretSize {
		return nil, fmt.Errorf("wrong byte size for AppSecret: %d, should be %d", len(appSecretBytes), AppSecretSize)
	}
	return &config{
		AppID:     appIDBytes,
		AppSecret: appSecretBytes,
	}, nil
}
