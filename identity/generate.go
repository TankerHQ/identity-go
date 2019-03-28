package identity

import (
	"errors"

	"github.com/TankerHQ/identity-go/b64json"
)

//Create a user token for given user.
func Create(config Config, userID string) (*string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return nil, err
	}
	identity, err := generateIdentity(*conf, userID)
	if err != nil {
		return nil, err
	}
	return b64json.Encode(identity)
}

func GetPublicIdentity(b64Identity string) (*string, error) {
	identity := identity{}
	err := b64json.Decode(b64Identity, &identity)
	if err != nil {
		return nil, err
	}

	if identity.Target != "user" {
		return nil, errors.New("unsupported identity target")
	}

	return b64json.Encode(identity.publicIdentity)
}
