# Identity [![Travis][build-badge]][build]

Identity generation in Go for the [Tanker SDK](https://tanker.io/docs/latest).

## Installation

```bash
go get github.com/TankerHQ/identity-go/identity
```

## Usage

The server-side code below demonstrates a typical flow to safely deliver identities to your users:

```go
import (
    "github.com/TankerHQ/identity-go/identity"
)

config := identity.Config {
    AppID: "<app-id>",
    AppSecret: "<app-secret>",
}

// Example server-side function in which you would implement checkAuth(),
// retrieveIdentity() and storeIdentity() to use your own authentication
// and data storage mechanisms:
func getIdentity(string userID) (string, error) {
    isAuthenticated := checkAuth(userID)

    // Always ensure userID is authenticated before returning a identity
    if ! isAuthenticated {
      return "", error.New("Unauthorized")
    }

    // Retrieve a previously stored identity for this user
    identity := retrieveIdentity(userID)

    // If not found, create a new identity
    if identity == "" {
        identity, err = identity.Create(config, userID)
        if err != nil {
            return "", err
        }

        // Store the newly generated identity
        storeIdentity(userID, identity)
    }

    // From now, the same identity will always be returned to a given user
    return identity, nil
}

func getPublicIdentity(string userID) (string, error) {
    // Retrieve a previously stored identity for this user
    tkIdentity := retrieveIdentity(userID)
    if tkIdentity == "" {
      return "", error.New("Not found")
    }

    publicIdentity, err := identity.GetPublicIdentity(tkIdentity)
	if err != nil {
		return "", err
	}

    return publicIdentity, nil
}
```

Read more about identities in the [Tanker guide](https://tanker.io/docs/latest/guide/user-token/).

## Development

Run tests:

```bash
go test ./... -test.v
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/TankerHQ/identity-go.

[build-badge]: https://travis-ci.org/TankerHQ/identity-go.svg?branch=master
[build]: https://travis-ci.org/TankerHQ/identity-go
