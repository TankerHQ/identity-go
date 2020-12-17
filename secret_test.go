package identity

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestVerifyBlake2b512Implementation(t *testing.T) {
	known, err := hex.DecodeString("BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := blake2b.Sum512([]byte("abc")), known; !bytes.Equal(got[:], want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
