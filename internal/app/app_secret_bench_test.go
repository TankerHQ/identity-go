package app

import (
	"crypto/rand"
	"testing"
)

func BenchmarkGetAppId(b *testing.B) {
	appSecret := make([]byte, AppSecretSize)
	rand.Read(appSecret)

	for i := 0; i < b.N; i++ {
		GetAppId(appSecret)
	}
}
