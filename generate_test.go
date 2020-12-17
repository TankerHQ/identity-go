package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	appSecret := decodeBase64string("cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ==")
	appID := decodeBase64string("tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4=")
	conf := config{AppID: appID, AppSecret: appSecret}
	userID := "userID"
	obfuscatedUserID := hashUserID(appID, userID)

	t.Run("returns a valid tanker identity", func(t *testing.T) {
		identity, err := generateIdentity(conf, userID)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := identity.TrustchainID, appID; !bytes.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got, want := identity.Target, "user"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got, want := identity.Value, base64.StdEncoding.EncodeToString(obfuscatedUserID); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}

		expectedTrustChain := decodeBase64string("r6oz1Rpl3dsMGu8te0LT02YZ/G8W9NeQmQv3uGSO/jE=")
		checkDelegationSignature(t, *identity, expectedTrustChain)
	})

	t.Run("returns a valid tanker provisional identity", func(t *testing.T) {
		provisionalIdentity, err := generateProvisionalIdentity(conf, "email@example.com")
		if err != nil {
			t.Fatal(err)
		}

		if got, want := provisionalIdentity.TrustchainID, appID; !bytes.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got, want := provisionalIdentity.Target, "email"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got, want := string(provisionalIdentity.Value), "email@example.com"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("returns an error if app ID and secret mismatch", func(t *testing.T) {
		mismatchingAppID := decodeBase64string("rB0/yEJWCUVYRtDZLtXaJqtneXQOsCSKrtmWw+V+ysc=")
		invalidConf := config{AppID: mismatchingAppID, AppSecret: conf.AppSecret}
		if _, err := generateIdentity(invalidConf, "email@example.com"); err == nil {
			t.Fatal("expected error but got none")
		}
	})
}

func checkDelegationSignature(t *testing.T, identity identity, trustChainPublicKey []byte) {
	t.Helper()

	obfuscatedUserID, err := base64.StdEncoding.DecodeString(identity.Value)
	if err != nil {
		t.Fatal(err)
	}
	signedData := append(identity.EphemeralPublicSignatureKey, obfuscatedUserID...)

	if ed25519.Verify(trustChainPublicKey, signedData, identity.DelegationSignature) == false {
		t.Fatal("verification failed")
	}
}

func decodeBase64string(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
