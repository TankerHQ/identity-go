package crypto_test

import (
	"testing"

	"github.com/TankerHQ/identity-go/v3/internal/crypto"
)

func BenchmarkNewKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.NewKeyPair() //nolint: errcheck
	}
}
