package identity

import (
	"encoding/base64"
	"errors"
)

type Config struct {
	AppID     string
	AppSecret string
}

type config struct {
	AppID     []byte
	AppSecret []byte
}

func (this Config) fromB64() (*config, error) {
	appIDBytes, err := base64.StdEncoding.DecodeString(this.AppID)
	if err != nil {
		return nil, errors.New("Wrong AppID format, should be base64: " + this.AppID)
	}
	appSecretBytes, err := base64.StdEncoding.DecodeString(this.AppSecret)
	if err != nil {
		return nil, errors.New("Wrong AppSecret format, should be base64: " + this.AppSecret)
	}
	return &config{
		AppID:     appIDBytes,
		AppSecret: appSecretBytes,
	}, nil
}
