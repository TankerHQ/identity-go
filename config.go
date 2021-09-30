package identity

import (
	"encoding/base64"
	"fmt"
	"github.com/TankerHQ/identity-go/v3/internal/app"
)

// Config wraps information about an app
type Config struct {
	// AppID is the ID of the app corresponding to this config
	AppID     string
	// AppSecret is the app private signature key used to sign identities
	AppSecret string
}

type config struct {
	AppID     []byte
	AppSecret []byte
}

func (cfg Config) fromBase64() (*config, error) {

	var (
		newCfg = new(config)
		err    error
	)

	newCfg.AppID, err = base64.StdEncoding.DecodeString(cfg.AppID)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AppID '%s', should be a valid base64 string", cfg.AppID)
	}
	if len(newCfg.AppID) != app.AppPublicKeySize {
		return nil, fmt.Errorf("wrong byte size for AppID: %d, should be %d", len(newCfg.AppID), app.AppPublicKeySize)
	}

	newCfg.AppSecret, err = base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AppSecret '%s', should be a valid base64 string", cfg.AppSecret)
	}
	if len(newCfg.AppSecret) != app.AppSecretSize {
		return nil, fmt.Errorf("wrong byte size for AppSecret: %d, should be %d", len(newCfg.AppSecret), app.AppSecretSize)
	}

	return newCfg, nil
}
