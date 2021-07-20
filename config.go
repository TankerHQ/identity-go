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

func (cfg Config) fromBase64() (config, error) {
	var (
		newCfg config
		err error
	)

	newCfg.AppID, err = base64.StdEncoding.DecodeString(cfg.AppID)
	if err != nil {
		return config{}, errors.New("Wrong AppID format, should be base64: " + cfg.AppID)
	}
	if len(newCfg.AppID) != AppPublicKeySize {
		return config{}, fmt.Errorf("Expected App ID of size %d, got %d", AppPublicKeySize, len(newCfg.AppID))
	}

	newCfg.AppSecret, err = base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return config{}, errors.New("Wrong AppSecret format, should be base64: " + cfg.AppSecret)
	}
	if len(newCfg.AppSecret) != AppSecretSize {
		return config{}, fmt.Errorf("Expected App secret of size %d, got %d", AppSecretSize, len(newCfg.AppSecret))
	}

	return newCfg, nil
}
