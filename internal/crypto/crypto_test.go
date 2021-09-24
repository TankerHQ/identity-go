package crypto_test

import (
	"bytes"
	"crypto/rand"
	"github.com/TankerHQ/identity-go/v3/internal/crypto"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	sk1, pk1, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal("error generating key pair")
	}
	sk2, pk2, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal("error generating key pair")
	}
	sk3, pk3, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal("error generating key pair")
	}
	sk4, pk4, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal("error generating key pair")
	}

	if bytes.Equal(sk1, sk2) ||
		bytes.Equal(sk1, sk3) ||
		bytes.Equal(sk1, sk4) ||
		bytes.Equal(sk2, sk3) ||
		bytes.Equal(sk2, sk4) ||
		bytes.Equal(sk3, sk4) {
		t.Fatal("same secret key generated twice")
	}

	if bytes.Equal(pk1, pk2) ||
		bytes.Equal(pk1, pk3) ||
		bytes.Equal(pk1, pk4) ||
		bytes.Equal(pk2, pk3) ||
		bytes.Equal(pk2, pk4) ||
		bytes.Equal(pk3, pk4) {
		t.Fatal("same public key generated twice")
	}
}

func TestNewKeyPair_Error(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	rand.Reader = buf
	_, _, err := crypto.NewKeyPair()
	if err == nil {
		t.Fatal("no error generating key pair with invalid rand.Reader")
	}
}
