package app

import (
	"crypto/ed25519"
	"testing"
)

func BenchmarkGetAppId(b *testing.B) {
	_, secret, _ := ed25519.GenerateKey(nil)

	for i := 0 ; i < b.N ; i++ {
		GetAppId(secret)
	}
}