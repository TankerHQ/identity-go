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

func (cfg Config) fromBase64() (config, error) {
	var (
		newCfg config
		err    error
	)

	newCfg.AppID, err = base64.StdEncoding.DecodeString(cfg.AppID)
	if err != nil {
		return config{}, fmt.Errorf("unable to decode AppID '%s', should be a valid base64 string", cfg.AppID)
	}
	if len(newCfg.AppID) != AppPublicKeySize {
		return config{}, fmt.Errorf("wrong size for AppID: %d, should be %d", len(newCfg.AppID), AppPublicKeySize)
	}

	newCfg.AppSecret, err = base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return config{}, fmt.Errorf("unable to decode AppSecret '%s', should be a valid base64 string", cfg.AppSecret)
	}
	if len(newCfg.AppSecret) != AppSecretSize {
		return config{}, fmt.Errorf("wrong size for AppSecret: %d, should be %d", len(newCfg.AppSecret), AppSecretSize)
	}

	return newCfg, nil
}
