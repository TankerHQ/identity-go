package identity

import (
	identity2 "github.com/TankerHQ/identity-go/v3"
)

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func Create(config Config, userID string) (*string, error) {
	return identity2.Create(identity2.Config{
		AppID:     config.AppID,
		AppSecret: config.AppSecret,
	}, userID)
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func CreateProvisional(config Config, target string, value string) (*string, error) {
	return identity2.CreateProvisional(identity2.Config{
		AppID:     config.AppID,
		AppSecret: config.AppSecret,
	}, target, value)
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func GetPublicIdentity(b64Identity string) (*string, error) {
	return identity2.GetPublicIdentity(b64Identity)
}

// DEPRECATED: use github.com/TankerHQ/identity-go/v3
func UpgradeIdentity(b64Identity string) (*string, error) {
	return identity2.UpgradeIdentity(b64Identity)
}
