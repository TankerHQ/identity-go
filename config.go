package identity

import (
	"encoding/base64"
	"fmt"
	"github.com/TankerHQ/identity-go/v3/internal/app"
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
	if len(appIDBytes) != app.AppPublicKeySize {
		return nil, fmt.Errorf("wrong byte size for AppID: %d, should be %d", len(appIDBytes), app.AppPublicKeySize)
	}
	appSecretBytes, err := base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AppSecret '%s', should be a valid base64 string", cfg.AppSecret)
	}
	if len(appSecretBytes) != app.AppSecretSize {
		return nil, fmt.Errorf("wrong byte size for AppSecret: %d, should be %d", len(appSecretBytes), app.AppSecretSize)
	}
	return &config{
		AppID:     appIDBytes,
		AppSecret: appSecretBytes,
	}, nil
}
