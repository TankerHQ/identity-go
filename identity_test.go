package identity

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
)

func TestIdentityCreation(t *testing.T) {
	appID := "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="
	appSecret := "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ=="
	appConfig := Config{AppID: appID, AppSecret: appSecret}

	t.Run("generates a valid identity in b64 form", func(t *testing.T) {
		identityB64, err := Create(appConfig, "userID")
		if err != nil {
			t.Fatal(err)
		}

		id := &identity{}
		if err := Base64Decode(*identityB64, id); err != nil {
			t.Fatal(err)
		}
		if got, want := id.Target, "user"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("returns an error if the App secret is a valid base64 string but has an incorrect size", func(t *testing.T) {
		invalidAppSecret := base64.StdEncoding.EncodeToString([]byte{0xaa})
		invalidConf := Config{AppID: appID, AppSecret: invalidAppSecret}
		if _, err := Create(invalidConf, "email@example.com"); err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("returns an error if the App ID is a valid base64 string but has an incorrect size", func(t *testing.T) {
		invalidAppID := base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc})
		invalidConf := Config{AppID: invalidAppID, AppSecret: appSecret}
		if _, err := Create(invalidConf, "email@example.com"); err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("generates a valid provisional identity in b64 form", func(t *testing.T) {
		identityB64, err := CreateProvisional(appConfig, "email@example.com")
		if err != nil {
			t.Fatal(err)
		}

		id := &provisionalIdentity{}
		if err := Base64Decode(*identityB64, id); err != nil {
			t.Fatal(err)
		}

		if got, want := id.Target, "email"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got, want := id.Value, "email@example.com"; got != want {
			t.Fatalf("got %v, want %v", got, want)
		}

		assertNotEmpty(t, id.PrivateEncryptionKey)
		assertNotEmpty(t, id.PublicEncryptionKey)
		assertNotEmpty(t, id.PrivateSignatureKey)
		assertNotEmpty(t, id.PublicSignatureKey)
	})

	t.Run("creates a valid public identity from an identity", func(t *testing.T) {
		goodPublicIdentity := "eyJ0YXJnZXQiOiJ1c2VyIiwidHJ1c3RjaGFpbl9pZCI6InRwb3h5TnpoMGhVOUcyaTlhZ012SHl5ZCtwTzZ6R0NqTzlCZmhyQ0xqZDQ9IiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"
		goodIdentity := "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="

		publicID, err := GetPublicIdentity(goodIdentity)
		if err != nil {
			t.Fatal(err)
		}

		extractedPublicID := &publicIdentity{}
		_ = Base64Decode(*publicID, extractedPublicID)

		extractedGoodPublicID := &publicIdentity{}
		_ = Base64Decode(goodPublicIdentity, extractedGoodPublicID)

		if got, want := *extractedGoodPublicID, *extractedPublicID; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("creates a valid public identity from a provisional identity", func(t *testing.T) {
		identityB64, err := CreateProvisional(appConfig, "email@example.com")
		if err != nil {
			t.Fatal(err)
		}

		provisionalID := &provisionalIdentity{}
		if err := Base64Decode(*identityB64, provisionalID); err != nil {
			t.Fatal(err)
		}

		publicID, err := GetPublicIdentity(*identityB64)
		if err != nil {
			t.Fatal(err)
		}

		extractedPublicID := &publicProvisionalIdentity{}
		if err := Base64Decode(*publicID, extractedPublicID); err != nil {
			t.Fatal(err)
		}

		if got, want := *extractedPublicID, provisionalID.publicProvisionalIdentity; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func TestGenerateKey(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(sk), 32; got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, want := len(pk), 32; got != want {
		t.Fatalf("got %v, want %v", got, want)
	}

	t.Run("generate different keys", func(t *testing.T) {
		sk2, pk2, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := sk, sk2; bytes.Equal(got, want) {
			t.Fatalf("unexpected equal: got %v, want %v", got, want)
		}
		if got, want := pk, pk2; bytes.Equal(got, want) {
			t.Fatalf("unexpected equal: got %v, want %v", got, want)
		}
	})
}

func assertNotEmpty(t *testing.T, b []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("unexpected 0 length")
	}
}
