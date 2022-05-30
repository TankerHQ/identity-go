package crypto_test

import (
	"github.com/TankerHQ/identity-go/v3/internal/crypto"
	"testing"
)

func BenchmarkNewKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.NewKeyPair()
	}
}
