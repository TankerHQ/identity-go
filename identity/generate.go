package identity

import (
	identity2 "github.com/TankerHQ/identity-go/v3"
)

// DEPRECATED: use github.com/TankerHQ/identity-go/v3's New function
func Create(config Config, userID string) (*string, error) {
	identity, err := identity2.New(identity2.Config{
		AppID:     config.AppID,
		AppSecret: config.AppSecret,
	}, userID)
	return &identity, err
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3's NewProvisional function
func CreateProvisional(config Config, target string, value string) (*string, error) {
	identity, err := identity2.NewProvisional(identity2.Config{
		AppID:     config.AppID,
		AppSecret: config.AppSecret,
	}, identity2.Target(target), value)
	return &identity, err
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func GetPublicIdentity(b64Identity string) (*string, error) {
	identity, err := identity2.GetPublicIdentity(b64Identity)
	return &identity, err
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func UpgradeIdentity(b64Identity string) (*string, error) {
	identity, err := identity2.UpgradeIdentity(b64Identity)
	return &identity, err
}
