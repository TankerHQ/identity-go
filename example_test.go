package identity_test

import (
	"fmt"
	"log"

	"github.com/TankerHQ/identity-go"
)

var (
	userID   = "john123"
	config   = identity.Config{AppID: "<app-id>", AppSecret: "<app-secret>"}
	anyStore = fakeStore{}
)

// Example server-side function in which you would implement your own
// authentication, and a store to persist and retrieve identities:
func ExampleGetIdentity() {
	// Always ensure userID is authenticated before returning a identity
	if !anyStore.isAuthenticated(userID) {
		log.Fatal("unauthorized")
	}

	// Retrieve a previously stored identity for this user
	userIdentity := anyStore.get(userID)

	// If not found, create a new identity
	if userIdentity == "" {
		identity, err := identity.Create(config, userID)
		if err != nil {
			log.Fatal(err)
		}
		// Store the newly generated identity
		anyStore.persist(userID, *identity)
	}
	// From now, the same identity will always be returned to a given user
}

func ExampleGetPublicIdentity() {
	// Retrieve a previously stored identity for this user
	tkIdentity := anyStore.get(userID)
	if tkIdentity == "" {
		log.Fatal("not found")
	}

	publicIdentity, err := identity.GetPublicIdentity(tkIdentity)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(publicIdentity)
}

type fakeStore struct{}

func (fakeStore) isAuthenticated(string) bool  { return false }
func (fakeStore) persist(string, string) error { return nil }
func (fakeStore) get(string) string            { return "" }
