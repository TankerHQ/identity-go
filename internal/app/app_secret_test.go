package app_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/TankerHQ/identity-go/v3/internal/app"
)

func TestGetAppId(t *testing.T) {
	appSecret := make([]byte, app.AppSecretSize)
	_, err := rand.Read(appSecret)
	if err != nil {
		panic("err should not be nil")
	}

	id1 := app.GetAppId(appSecret)
	id2 := app.GetAppId(appSecret)
	if !bytes.Equal(id1, id2) {
		t.Fatal("app IDs should be equal for same app secret")
	}
}
