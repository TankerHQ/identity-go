<a href="#readme"><img src="https://raw.githubusercontent.com/TankerHQ/spec/master/img/tanker-logotype-blue-nomargin-350.png" alt="Tanker logo" width="175" /></a>

[![Actions status](https://github.com/TankerHQ/identity-go/workflows/Tests/badge.svg)](https://github.com/TankerHQ/identity-go/actions)
[![codecov](https://codecov.io/gh/TankerHQ/identity-go/branch/master/graph/badge.svg)](https://codecov.io/gh/TankerHQ/identity-go)
[![GoDoc][doc-badge]][doc]

# Identity SDK

Identity generation in Go for the [Tanker SDK](https://docs.tanker.io/latest/).

## Installation

```bash
go get github.com/TankerHQ/identity-go/v3
```

## Usage

The server-side code below demonstrates a typical flow to safely deliver identities to your users:

```go
import (
	"fmt"
	"errors"

	"github.com/TankerHQ/identity-go/v3"
)

var config = identity.Config{
	AppID:     "<app-id>",
	AppSecret: "<app-secret>",
}

// Example server-side function in which you would implement checkAuth(),
// retrieveIdentity() and storeIdentity() to use your own authentication
// and data storage mechanisms:
func getIdentity(userID string) (*string, error) {
	// Always ensure userID is authenticated before returning a identity
	if !isAuthenticated(userID) {
		return nil, errors.New("Unauthorized")
	}

	// Retrieve a previously stored identity for this user
	identity := retrieveIdentity(userID)

	// If not found, create a new identity
	if identity == "" {
		identity, err := identity.Create(config, userID)
		if err != nil {
			return nil, err
		}

		// Store the newly generated identity
		storeIdentity(userID, identity)
	}

	// From now, the same identity will always be returned to a given user
	return &identity, nil
}

func getPublicIdentity(userID string) (*string, error) {
	// Retrieve a previously stored identity for this user
	tkIdentity := retrieveIdentity(userID)
	if tkIdentity == "" {
		return nil, errors.New("Not found")
	}

	publicIdentity, err := identity.GetPublicIdentity(tkIdentity)
	if err != nil {
		return nil, err
	}

	return publicIdentity, nil
}
```

Read more about identities in the [Tanker guide](https://docs.tanker.io/latest/guides/identity-management/).

## Development

Run tests:

```bash
go test ./... -test.v
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/TankerHQ/identity-go.

[build-badge]: https://travis-ci.org/TankerHQ/identity-go.svg?branch=master
[build]: https://travis-ci.org/TankerHQ/identity-go
[doc-badge]: https://godoc.org/github.com/TankerHQ/identity-go/identity?status.svg
[doc]: https://godoc.org/github.com/TankerHQ/identity-go/identity
